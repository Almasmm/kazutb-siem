package aisoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/kcsp/platform/internal/core"
)

const maximumContextBytes = 256 * 1024

var (
	sensitiveKey = regexp.MustCompile(`(?i)(password|passwd|secret|token|api.?key|authorization|cookie|credential|private.?key)`)
	emailValue   = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	inlineSecret = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api.?key|authorization)\s*[:=]\s*[^\s,;]+`)
	injection    = regexp.MustCompile(`(?i)(ignore\s+(all\s+)?previous|system\s+prompt|developer\s+message|jailbreak|do\s+not\s+follow|assistant\s*:)`)
)

type ContextStore interface {
	GetEvent(context.Context, string, string) (core.CanonicalEvent, error)
	GetAlert(context.Context, string, string) (core.Alert, error)
	GetIncident(context.Context, string, string) (core.Incident, error)
}

func BuildContext(ctx context.Context, store ContextStore, policy core.AISOCPolicy, request core.AISOCRequest) ([]core.AISOCContextDocument, string, int, bool, error) {
	documents := make([]core.AISOCContextDocument, 0, len(request.ContextRefs))
	redactions := 0
	injectionDetected := false
	for _, ref := range request.ContextRefs {
		var resource interface{}
		var err error
		switch ref.Type {
		case "event":
			resource, err = store.GetEvent(ctx, request.TenantID, ref.ID)
		case "alert":
			resource, err = store.GetAlert(ctx, request.TenantID, ref.ID)
		case "incident":
			resource, err = store.GetIncident(ctx, request.TenantID, ref.ID)
		default:
			return nil, "", 0, false, ErrInvalidRequest
		}
		if err != nil {
			return nil, "", 0, false, fmt.Errorf("load %s context %s: %w", ref.Type, ref.ID, err)
		}
		body, err := json.Marshal(resource)
		if err != nil {
			return nil, "", 0, false, fmt.Errorf("encode AI context: %w", err)
		}
		var content map[string]interface{}
		if err := json.Unmarshal(body, &content); err != nil {
			return nil, "", 0, false, fmt.Errorf("normalize AI context: %w", err)
		}
		sanitized, count, detected := sanitizeValue(content, "", policy.PIIRedaction)
		redactions += count
		injectionDetected = injectionDetected || detected
		documents = append(documents, core.AISOCContextDocument{Ref: ref, Content: sanitized.(map[string]interface{})})
	}
	body, err := json.Marshal(documents)
	if err != nil {
		return nil, "", 0, false, fmt.Errorf("encode AI context snapshot: %w", err)
	}
	if len(body) > maximumContextBytes {
		return nil, "", 0, false, ErrContextTooLarge
	}
	sum := sha256.Sum256(body)
	return documents, hex.EncodeToString(sum[:]), redactions, injectionDetected, nil
}

func sanitizeValue(value interface{}, key string, redactPII bool) (interface{}, int, bool) {
	if sensitiveKey.MatchString(key) {
		return "[REDACTED]", 1, false
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(typed))
		count := 0
		detected := false
		for childKey, childValue := range typed {
			clean, childCount, childDetected := sanitizeValue(childValue, childKey, redactPII)
			result[childKey] = clean
			count += childCount
			detected = detected || childDetected
		}
		return result, count, detected
	case []interface{}:
		result := make([]interface{}, len(typed))
		count := 0
		detected := false
		for index, child := range typed {
			clean, childCount, childDetected := sanitizeValue(child, key, redactPII)
			result[index] = clean
			count += childCount
			detected = detected || childDetected
		}
		return result, count, detected
	case string:
		detected := injection.MatchString(typed)
		count := 0
		clean := inlineSecret.ReplaceAllStringFunc(typed, func(_ string) string {
			count++
			return "[REDACTED_SECRET]"
		})
		if redactPII {
			clean = emailValue.ReplaceAllStringFunc(clean, func(_ string) string {
				count++
				return "[REDACTED_EMAIL]"
			})
		}
		return clean, count, detected
	default:
		return value, 0, false
	}
}
