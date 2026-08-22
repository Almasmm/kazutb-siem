package hunt

import (
	"strings"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
)

func TestCompileExpressionParameterizesUntrustedValues(t *testing.T) {
	injection := `x') OR 1=1 --`
	expression := &core.HuntExpression{All: []core.HuntExpression{
		{Predicate: &core.HuntPredicate{Field: "category", Comparator: "eq", Value: "authentication"}},
		{Predicate: &core.HuntPredicate{Field: "process.command_line", Comparator: "contains", Value: injection}},
	}}
	request, err := Normalize(core.HuntRequest{Start: time.Now().Add(-time.Hour), End: time.Now(), Expression: expression}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	query, args, err := CompileExpression(request.Expression)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(query, injection) || len(args) != 2 || args[1] != injection {
		t.Fatalf("untrusted value entered SQL: query=%q args=%v", query, args)
	}
}

func TestNormalizeRejectsUnknownFieldAndUnboundedWindow(t *testing.T) {
	now := time.Now().UTC()
	unknown := core.HuntRequest{Start: now.Add(-time.Hour), End: now, Expression: &core.HuntExpression{
		Predicate: &core.HuntPredicate{Field: "payload) OR 1=1", Comparator: "eq", Value: "x"},
	}}
	if _, err := Normalize(unknown, now); err == nil {
		t.Fatal("unknown field was accepted")
	}
	if _, err := Normalize(core.HuntRequest{Start: now.Add(-32 * 24 * time.Hour), End: now}, now); err == nil {
		t.Fatal("unbounded hunt window was accepted")
	}
}

func TestCursorIsBoundToNormalizedQuery(t *testing.T) {
	now := time.Now().UTC()
	request, err := Normalize(core.HuntRequest{Start: now.Add(-time.Hour), End: now, Limit: 25}, now)
	if err != nil {
		t.Fatal(err)
	}
	hash := QueryHash(request)
	encoded := EncodeCursor(Cursor{EventTime: now.Add(-time.Minute), EventID: "evt-1", QueryHash: hash})
	cursor, err := DecodeCursor(encoded)
	if err != nil || cursor.QueryHash != hash || cursor.EventID != "evt-1" {
		t.Fatalf("cursor round trip failed: %+v err=%v", cursor, err)
	}
}
