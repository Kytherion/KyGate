package router

import (
	"strconv"
	"strings"

	"github.com/Kytherion/KyGate/internal/ingress"
)

// FeaturesOf describes a request for the router: shapes and sizes, never text.
func FeaturesOf(req *ingress.Request, local bool, tiers []string) Features {
	f := Features{Family: string(req.Family), Model: req.Model, Local: local, Tiers: tiers,
		Unreadable: len(req.Unreadable) > 0}
	b := req.Body
	msgs, _ := b["messages"].([]any)
	last := -1
	for i, m := range msgs {
		switch str(obj(m)["role"]) {
		case "user":
			f.UserTurns++
			last = i
		case "assistant":
			f.AssistantTurns++
		}
	}
	lastPrefix := "messages." + strconv.Itoa(last)
	for _, s := range req.Segments {
		n := EstimateTokens(s.Text)
		f.PromptTokens += n
		if last >= 0 && (s.ID == lastPrefix || strings.HasPrefix(s.ID, lastPrefix+".")) && s.Role == ingress.RoleUser {
			f.LastUserTokens += n
		}
		if !f.Code && !s.JSON && s.Role != ingress.RoleAssistant && LooksLikeCode(s.Text) {
			f.Code = true
		}
	}
	if t, ok := b["tools"].([]any); ok && len(t) > 0 {
		f.Tools = true
	}
	if t, ok := b["functions"].([]any); ok && len(t) > 0 {
		f.Tools = true
	}
	if rf := obj(b["response_format"]); rf != nil && str(rf["type"]) != "" && str(rf["type"]) != "text" {
		f.Structured = true
	}
	if b["output_format"] != nil || b["text"] != nil {
		f.Structured = true // newer structured-output fields of either API
	}
	if th := obj(b["thinking"]); th != nil && str(th["type"]) != "disabled" {
		f.Reasoning = true
	}
	switch e := str(b["reasoning_effort"]); e {
	case "", "none", "minimal", "low":
	default:
		f.Reasoning = true
	}
	if r := obj(b["reasoning"]); r != nil {
		switch str(r["effort"]) {
		case "", "none", "minimal", "low":
		default:
			f.Reasoning = true
		}
	}
	for _, k := range []string{"max_tokens", "max_completion_tokens", "max_output_tokens"} {
		if v := int(num(b[k])); v > f.MaxOutputTokens {
			f.MaxOutputTokens = v
		}
	}
	return f
}

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }

func str(v any) string { s, _ := v.(string); return s }

// num reads a JSON number, decoded with UseNumber or not.
func num(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case interface{ Float64() (float64, error) }:
		f, _ := t.Float64()
		return f
	}
	return 0
}
