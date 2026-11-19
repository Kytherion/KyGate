package pipeline_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// Traces (OB-5): one span per request with its stages, linked to the caller's
// trace, and metadata only: no prompt, answer, value, or key.
func TestTracesCarryMetadataOnly(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
		tp.Shutdown(context.Background())
	})

	h := newHarness(t, "")
	parent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	resp, _ := h.post("/v1/chat/completions", h.keyA, chat("Charge card "+cardA+" again", false), "traceparent", parent)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	h.events() // the span ends when the handler has finished

	var req sdktrace.ReadOnlySpan
	stages := map[string]bool{}
	for _, s := range rec.Ended() {
		if s.Name() == "kygate /v1/chat/completions" {
			req = s
		}
		if strings.HasPrefix(s.Name(), "kygate.") {
			stages[strings.TrimPrefix(s.Name(), "kygate.")] = true
		}
	}
	if req == nil {
		t.Fatal("no request span")
	}
	if req.Parent().TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("the caller's trace must be continued: %s", req.Parent().TraceID())
	}
	for _, st := range []string{"ingress", "identity", "inspect", "enforce", "cache", "upstream", "respond"} {
		if !stages[st] {
			t.Errorf("no span for stage %s: %v", st, stages)
		}
	}
	attrs := map[string]string{}
	for _, kv := range req.Attributes() {
		attrs[string(kv.Key)] = kv.Value.Emit()
	}
	for k, want := range map[string]string{"kygate.outcome": "ok", "kygate.cache": "miss", "kygate.model.served": "gpt-4o-mini",
		"kygate.connection": "openai", "kygate.findings": `["CREDIT_CARD:mask:1"]`, "http.response.status_code": "200"} {
		if attrs[k] != want {
			t.Errorf("%s = %q, want %q", k, attrs[k], want)
		}
	}
	all := fmt.Sprint(attrs)
	for _, s := range rec.Ended() {
		for _, kv := range s.Attributes() {
			all += kv.Value.Emit()
		}
	}
	for _, secret := range []string{cardA, "4111111111111111", "Charge card", "You said", "[CREDIT_CARD_1]", "sk-openai-1"} {
		if strings.Contains(all, secret) {
			t.Fatalf("a span carries %q", secret)
		}
	}
}
