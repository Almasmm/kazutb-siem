package ingest_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
	"github.com/kcsp/platform/internal/parser"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/store"
)

func TestKafkaClickHousePostgresDetectionFlow(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	clickhouseURL := os.Getenv("KCSP_TEST_CLICKHOUSE_URL")
	kafkaBrokers := os.Getenv("KCSP_TEST_KAFKA_BROKERS")
	if databaseURL == "" || clickhouseURL == "" || kafkaBrokers == "" {
		t.Skip("KCSP_TEST_DATABASE_URL, KCSP_TEST_CLICKHOUSE_URL and KCSP_TEST_KAFKA_BROKERS are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tenantID := "data-plane-" + core.NewID("tenant")
	eventID := "sysmon-" + core.NewID("event")

	repository, err := store.OpenHybrid(ctx, databaseURL, clickhouseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.EnsureTenant(ctx, tenantID, "KCSP Data Plane Test"); err != nil {
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		_ = repository.ResetTenant(cleanupCtx, tenantID)
	})

	engine, err := pipeline.New(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	brokers := strings.Split(kafkaBrokers, ",")
	publisher, err := ingest.OpenKafkaPublisher(ctx, ingest.KafkaConfig{
		Brokers: brokers, ClientID: "kcsp-integration-producer",
		RawTopic: "kcsp.test.raw.events.v1", DeadLetterTopic: "kcsp.test.raw.events.dlq.v1",
		Partitions: 3, ReplicationFactor: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	const envelopeHMACKey = "kcsp-integration-envelope-hmac-key-not-for-runtime"
	envelopeAuthenticator, err := ingest.NewEnvelopeAuthenticator(envelopeHMACKey)
	if err != nil {
		t.Fatal(err)
	}

	processor, err := ingest.OpenProcessor(ingest.ProcessorConfig{
		Brokers: brokers, ClientID: "kcsp-integration-processor",
		GroupID: "kcsp-integration-" + core.NewID("group"), Topic: publisher.RawTopic(),
		EnvelopeHMACKey: envelopeHMACKey,
	}, repository, parser.NewRegistry(), engine, publisher)
	if err != nil {
		t.Fatal(err)
	}
	processorCtx, stopProcessor := context.WithCancel(ctx)
	processorDone := make(chan error, 1)
	go func() { processorDone <- processor.Run(processorCtx) }()
	defer func() {
		stopProcessor()
		select {
		case runErr := <-processorDone:
			if runErr != nil && !errors.Is(runErr, context.Canceled) {
				t.Errorf("processor shutdown: %v", runErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("processor did not stop within five seconds")
		}
		processor.Close()
	}()

	eventTime := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	payload := []byte(fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><EventRecordID>9001</EventRecordID>
  <Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>dc-integration</Computer><TimeCreated SystemTime="%s"/></System>
  <EventData><Data Name="User">KCSP\admin</Data><Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
  <Data Name="ProcessId">4242</Data><Data Name="CommandLine">powershell.exe -EncodedCommand SQBFAFgA</Data><Data Name="ParentImage">C:\Windows\System32\services.exe</Data></EventData>
</Event>`, eventTime.Format(time.RFC3339Nano)))
	receipt, err := ingest.NewGateway(publisher, envelopeAuthenticator).SubmitRaw(ctx, tenantID, "sysmon-collector-01", ingest.RawSubmission{
		Format: ingest.FormatSysmonXML, ContentType: "application/xml", EventID: eventID,
		EventTimestamp: eventTime, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "QUEUED" || receipt.EventID != eventID {
		t.Fatalf("unexpected ingest receipt: %+v", receipt)
	}

	telemetry, err := store.OpenClickHouse(ctx, clickhouseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer telemetry.Close()

	deadline := time.Now().Add(30 * time.Second)
	for {
		storedEvent, eventErr := repository.GetEvent(ctx, tenantID, eventID)
		findings, findingsErr := repository.ListFindings(ctx, tenantID, eventID, 10)
		alerts, alertsErr := repository.ListAlerts(ctx, tenantID, store.AlertFilter{Limit: 10})
		audit, auditErr := repository.ListAudit(ctx, tenantID, 10)
		rawCount, rawErr := telemetry.RawEnvelopeCount(ctx, tenantID, eventID)
		if eventErr == nil && findingsErr == nil && alertsErr == nil && auditErr == nil && rawErr == nil &&
			storedEvent.Raw.Hash != "" && storedEvent.Raw.Reference != "" && len(findings) == 1 &&
			len(alerts) == 1 && len(audit) > 0 && rawCount == 1 {
			if !storedEvent.EventTime.Equal(eventTime) {
				t.Fatalf("source event time changed: got %s want %s", storedEvent.EventTime, eventTime)
			}
			if storedEvent.Parser.ID != "microsoft-sysmon-xml" || storedEvent.Schema.OCSFVersion != "1.4.0" {
				t.Fatalf("Sysmon parser lineage missing: parser=%+v schema=%+v", storedEvent.Parser, storedEvent.Schema)
			}
			if alerts[0].EventIDs[0] != eventID {
				t.Fatalf("alert lineage is broken: %+v", alerts[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("data plane did not converge: event=%v findings=%d/%v alerts=%d/%v audit=%d/%v raw=%d/%v",
				eventErr, len(findings), findingsErr, len(alerts), alertsErr, len(audit), auditErr, rawCount, rawErr)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}
