package soar

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

type RuntimeStore interface {
	ClaimSOARNode(context.Context, string, string, time.Duration) (core.SOARWorkItem, bool, error)
	CompleteSOARNode(context.Context, string, string, string, map[string]interface{}) error
	DeferSOARNode(context.Context, string, string, string, time.Time, map[string]interface{}) error
	RetrySOARNode(context.Context, string, string, string, time.Time, string, string) error
	FailSOARNode(context.Context, string, string, string, string, string) error
	RequestSOARApproval(context.Context, core.SOARWorkItem, int, int, time.Time) (core.SOARApproval, error)
	RequestSOARManualTask(context.Context, core.SOARWorkItem) error
	BeginSOARAction(context.Context, core.SOARActionAttempt) (core.SOARActionAttempt, bool, error)
	FinishSOARAction(context.Context, string, string, string, map[string]interface{}, string, string, string) (core.SOARActionAttempt, error)
}

type WorkerConfig struct {
	ID           string
	TenantID     string
	PollInterval time.Duration
	Lease        time.Duration
}

type ActionRequest struct {
	Attempt   core.SOARActionAttempt
	Execution core.SOARExecution
	Node      core.SOARNodeExecution
}

type ActionResult struct {
	Output             map[string]interface{}
	VerificationStatus string
}

type ActionExecutor interface {
	Execute(context.Context, ActionRequest) (ActionResult, error)
}

type Worker struct {
	store              RuntimeStore
	actions            ActionCatalog
	executor           ActionExecutor
	connectorTestStore ConnectorTestRuntimeStore
	connectorTester    ConnectorTester
	config             WorkerConfig
	logger             *slog.Logger
}

type NodeError struct {
	Code      string
	Detail    string
	Permanent bool
}

func (e *NodeError) Error() string { return e.Code + ": " + e.Detail }

func NewWorker(store RuntimeStore, actions ActionCatalog, executor ActionExecutor, config WorkerConfig, logger *slog.Logger) *Worker {
	if actions == nil {
		actions = DefaultActionCatalog()
	}
	if executor == nil {
		executor = SafeActionExecutor{}
	}
	if strings.TrimSpace(config.ID) == "" {
		config.ID = "soar-worker"
	}
	if config.PollInterval <= 0 {
		config.PollInterval = 500 * time.Millisecond
	}
	if config.Lease <= 0 {
		config.Lease = 30 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	worker := &Worker{store: store, actions: actions, executor: executor, config: config, logger: logger}
	if connectorStore, ok := store.(ConnectorTestRuntimeStore); ok {
		if connectorTester, ok := executor.(ConnectorTester); ok {
			worker.connectorTestStore = connectorStore
			worker.connectorTester = connectorTester
		}
	}
	return worker
}

func (w *Worker) Run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			worked, err := w.ProcessOne(ctx)
			if err != nil {
				w.logger.Error("SOAR work item failed", "error", err)
			}
			delay := w.config.PollInterval
			if worked {
				delay = 10 * time.Millisecond
			}
			timer.Reset(delay)
		}
	}
}

func (w *Worker) ProcessOne(ctx context.Context) (bool, error) {
	if w.connectorTestStore != nil && w.connectorTester != nil {
		worked, err := w.processConnectorTest(ctx)
		if err != nil || worked {
			return worked, err
		}
	}
	item, found, err := w.store.ClaimSOARNode(ctx, w.config.ID, w.config.TenantID, w.config.Lease)
	if err != nil || !found {
		return found, err
	}
	err = w.process(ctx, item)
	if err == nil {
		return true, nil
	}
	var nodeError *NodeError
	if !errors.As(err, &nodeError) {
		return true, err
	}
	maximumAttempts := item.Node.Retry.MaximumAttempts
	if maximumAttempts < 1 {
		maximumAttempts = 1
	}
	if !nodeError.Permanent && item.Node.Attempt < maximumAttempts {
		backoff := item.Node.Retry.BackoffSeconds
		if backoff < 1 {
			backoff = 1
		}
		maximumBackoff := item.Node.Retry.MaximumBackoff
		if maximumBackoff < backoff {
			maximumBackoff = backoff
		}
		delay := time.Duration(math.Min(float64(maximumBackoff), float64(backoff)*math.Pow(2, float64(item.Node.Attempt-1)))) * time.Second
		return true, w.store.RetrySOARNode(ctx, item.Node.TenantID, item.Node.ID, w.config.ID,
			time.Now().UTC().Add(delay), nodeError.Code, nodeError.Detail)
	}
	return true, w.store.FailSOARNode(ctx, item.Node.TenantID, item.Node.ID, w.config.ID, nodeError.Code, nodeError.Detail)
}

func (w *Worker) processConnectorTest(ctx context.Context) (bool, error) {
	item, found, err := w.connectorTestStore.ClaimSOARConnectorTest(
		ctx, w.config.ID, w.config.TenantID, w.config.Lease,
	)
	if err != nil || !found {
		return found, err
	}
	timeout := time.Duration(item.Connector.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > time.Minute {
		timeout = 10 * time.Second
	}
	testContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, testErr := w.connectorTester.TestConnector(testContext, item.Connector)
	if testErr != nil {
		result = ConnectorTestResult{
			Status: core.SOARConnectorTestFailed, ErrorClass: "INTERNAL",
			Detail: "connector tester returned an internal error",
		}
	}
	_, finishErr := w.connectorTestStore.FinishSOARConnectorTest(
		ctx, item.Test.TenantID, item.Test.ID, w.config.ID, result.Status,
		result.ErrorClass, result.Detail, result.HTTPStatus, result.LatencyMS,
	)
	return true, finishErr
}

func (w *Worker) process(ctx context.Context, item core.SOARWorkItem) error {
	node := item.Node
	switch node.NodeType {
	case core.SOARNodeAction:
		return w.executeAction(ctx, item)
	case core.SOARNodeApproval:
		required, ok := workerConfigInt(node.Config, "required_approvals")
		if !ok || required < 1 || required > 2 {
			return &NodeError{Code: "invalid_approval", Detail: "required_approvals must be 1 or 2", Permanent: true}
		}
		riskLevel := 4
		if required == 2 {
			riskLevel = 5
		}
		_, err := w.store.RequestSOARApproval(ctx, item, riskLevel, required, time.Now().UTC().Add(24*time.Hour))
		return err
	case core.SOARNodeManualTask:
		return w.store.RequestSOARManualTask(ctx, item)
	case core.SOARNodeDelay:
		if _, scheduled := node.Output["delay_until"]; !scheduled {
			seconds, ok := workerConfigInt(node.Config, "duration_seconds")
			if !ok || seconds < 1 || seconds > 86400 {
				return &NodeError{Code: "invalid_delay", Detail: "duration_seconds is outside safe bounds", Permanent: true}
			}
			until := time.Now().UTC().Add(time.Duration(seconds) * time.Second)
			return w.store.DeferSOARNode(ctx, node.TenantID, node.ID, w.config.ID, until,
				map[string]interface{}{"delay_until": until})
		}
		return w.store.CompleteSOARNode(ctx, node.TenantID, node.ID, w.config.ID, node.Output)
	case core.SOARNodeCondition:
		result, err := evaluateCondition(item.Execution.Context, node.Config)
		if err != nil {
			return err
		}
		return w.store.CompleteSOARNode(ctx, node.TenantID, node.ID, w.config.ID,
			map[string]interface{}{"condition_result": result})
	case core.SOARNodeTransform:
		output, err := transformContext(item.Execution.Context, node.Config)
		if err != nil {
			return err
		}
		return w.store.CompleteSOARNode(ctx, node.TenantID, node.ID, w.config.ID, output)
	case core.SOARNodeTrigger, core.SOARNodeParallel, core.SOARNodeRetry:
		return w.store.CompleteSOARNode(ctx, node.TenantID, node.ID, w.config.ID,
			map[string]interface{}{"completed": true})
	default:
		return &NodeError{Code: "unsupported_node", Detail: "node type " + node.NodeType + " has no enabled runtime", Permanent: true}
	}
}

func (w *Worker) executeAction(ctx context.Context, item core.SOARWorkItem) error {
	actionType, ok := workerConfigString(item.Node.Config, "action_type")
	if !ok {
		return &NodeError{Code: "invalid_action", Detail: "action_type is required", Permanent: true}
	}
	descriptor, ok := w.actions[actionType]
	if !ok {
		return &NodeError{Code: "unknown_action", Detail: "action is not registered", Permanent: true}
	}
	mode, _ := workerConfigString(item.Node.Config, "mode")
	mode = strings.ToUpper(mode)
	if mode == "" {
		mode = "DRY_RUN"
	}
	connectorID, _ := workerConfigString(item.Node.Config, "connector_id")
	if connectorID == "" {
		connectorID = "kcsp-internal"
	}
	request := map[string]interface{}{}
	if configured, ok := item.Node.Config["parameters"].(map[string]interface{}); ok {
		request = configured
	}
	now := time.Now().UTC()
	attempt := core.SOARActionAttempt{
		ID: core.NewID("sat"), TenantID: item.Node.TenantID, ExecutionID: item.Execution.ID,
		NodeExecutionID: item.Node.ID, IdempotencyKey: item.Execution.ID + "|" + item.Node.NodeID + "|" + actionType,
		ConnectorID: connectorID, ActionType: actionType, RiskLevel: descriptor.Level, Mode: mode,
		Status: "RUNNING", Request: request, Result: map[string]interface{}{}, CreatedAt: now, UpdatedAt: now,
	}
	stored, created, err := w.store.BeginSOARAction(ctx, attempt)
	if err != nil {
		return err
	}
	if !created && stored.Status == "SUCCEEDED" {
		return w.store.CompleteSOARNode(ctx, item.Node.TenantID, item.Node.ID, w.config.ID, stored.Result)
	}
	timeout := time.Duration(item.Node.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	actionContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, executionErr := w.executor.Execute(actionContext, ActionRequest{Attempt: stored, Execution: item.Execution, Node: item.Node})
	if executionErr != nil {
		var nodeError *NodeError
		if !errors.As(executionErr, &nodeError) {
			nodeError = &NodeError{Code: "connector_error", Detail: executionErr.Error()}
		}
		_, finishErr := w.store.FinishSOARAction(ctx, stored.TenantID, stored.ID, "FAILED", map[string]interface{}{},
			nodeError.Code, nodeError.Detail, "")
		if finishErr != nil {
			return finishErr
		}
		return nodeError
	}
	finished, err := w.store.FinishSOARAction(ctx, stored.TenantID, stored.ID, "SUCCEEDED", result.Output,
		"", "", result.VerificationStatus)
	if err != nil {
		return err
	}
	return w.store.CompleteSOARNode(ctx, item.Node.TenantID, item.Node.ID, w.config.ID, finished.Result)
}

type SafeActionExecutor struct{}

func (SafeActionExecutor) Execute(_ context.Context, request ActionRequest) (ActionResult, error) {
	if request.Attempt.Mode == "DRY_RUN" {
		return ActionResult{Output: map[string]interface{}{
			"dry_run": true, "action_type": request.Attempt.ActionType, "connector_id": request.Attempt.ConnectorID,
			"parameters": request.Attempt.Request,
		}, VerificationStatus: "DRY_RUN_VERIFIED"}, nil
	}
	if request.Attempt.ActionType == "kcsp.enrich.threat_intel" {
		return ActionResult{Output: map[string]interface{}{
			"enriched": true, "source": "kcsp-threat-intelligence", "context_preserved": true,
		}, VerificationStatus: "VERIFIED"}, nil
	}
	return ActionResult{}, &NodeError{
		Code: "connector_unavailable", Detail: "live execution requires a configured connector implementation", Permanent: true,
	}
}

func evaluateCondition(contextData, config map[string]interface{}) (bool, error) {
	field, ok := workerConfigString(config, "field")
	if !ok {
		return false, &NodeError{Code: "invalid_condition", Detail: "field is required", Permanent: true}
	}
	comparator, _ := workerConfigString(config, "comparator")
	comparator = strings.ToLower(comparator)
	actual, exists := contextPath(contextData, field)
	switch comparator {
	case "exists":
		return exists, nil
	case "not_exists":
		return !exists, nil
	case "eq", "neq":
		expected := fmt.Sprint(config["value"])
		equal := fmt.Sprint(actual) == expected
		if comparator == "neq" {
			equal = !equal
		}
		return exists && equal, nil
	default:
		return false, &NodeError{Code: "invalid_condition", Detail: "unsupported comparator", Permanent: true}
	}
}

func transformContext(contextData, config map[string]interface{}) (map[string]interface{}, error) {
	mappings, ok := config["mappings"].(map[string]interface{})
	if !ok || len(mappings) == 0 || len(mappings) > 50 {
		return nil, &NodeError{Code: "invalid_transform", Detail: "mappings must contain 1 to 50 entries", Permanent: true}
	}
	output := map[string]interface{}{}
	for target, sourceValue := range mappings {
		source, ok := sourceValue.(string)
		if !ok {
			return nil, &NodeError{Code: "invalid_transform", Detail: "mapping source must be a context path", Permanent: true}
		}
		if value, exists := contextPath(contextData, source); exists {
			output[target] = value
		}
	}
	return output, nil
}

func contextPath(data map[string]interface{}, path string) (interface{}, bool) {
	var current interface{} = data
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func workerConfigString(config map[string]interface{}, key string) (string, bool) {
	value, ok := config[key].(string)
	return strings.TrimSpace(value), ok && strings.TrimSpace(value) != ""
}

func workerConfigInt(config map[string]interface{}, key string) (int, bool) {
	switch value := config[key].(type) {
	case int:
		return value, true
	case float64:
		if value == float64(int(value)) {
			return int(value), true
		}
	}
	return 0, false
}
