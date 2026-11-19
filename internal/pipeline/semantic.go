package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Kytherion/KyGate/internal/cache"
	"github.com/Kytherion/KyGate/internal/ingress"
	"github.com/Kytherion/KyGate/internal/provider/openaicompat"
)

// The semantic cache on the request path (OP-3, architecture §3.4). It runs
// after an exact miss, only on requests the exact cache could store, and only
// when the request is narrow enough to compare by meaning without the Guard.

const (
	embedTimeout = 3 * time.Second
	// agreeThreshold: a shadow hit "agrees" when the stored answer and the real
	// one are at least this similar. It is an estimate of correctness, not a
	// proof: two good answers to one question can be worded differently.
	agreeThreshold = 0.90
)

// semReq is one request's semantic-cache state.
type semReq struct {
	fp      string // the exact fingerprint: the entry's key
	text    string // the masked last user message
	context string // keyed fingerprint of everything before it
	vec     []float32
	shadow  *cache.Match // the hit shadow mode found, to compare with the real answer
}

// semanticEligible returns the last user message and the context fingerprint,
// or nil when the request does not qualify. The rules: a chat or messages
// request; nothing detected and nothing unreadable; no tools; the last message
// is a user message of plain text, short enough.
func (g *Gateway) semanticEligible(sc *serveCtx, d decision, fp string) *semReq {
	pol, req := sc.pol, sc.req
	if g.Semantic == nil || !pol.SemanticEnabled() {
		return nil
	}
	if !embeddingsAllowed(pol, g.Registry.ByName(pol.Cache.Semantic.Embeddings.Connection)) {
		// The message would go to an embeddings server outside the policy's
		// regions (GV-4): no semantic cache for this request.
		return nil
	}
	if req.Endpoint != ingress.Chat && req.Endpoint != ingress.Messages {
		return nil
	}
	if len(d.counts) > 0 || len(req.Unreadable) > 0 || d.masked > 0 {
		return nil
	}
	for _, k := range []string{"tools", "tool_choice", "functions", "function_call"} {
		if v, ok := req.Body[k]; ok && v != nil {
			if list, isList := v.([]any); !isList || len(list) > 0 {
				return nil
			}
		}
	}
	msgs, _ := req.Body["messages"].([]any)
	n := len(msgs) - 1
	if n < 0 {
		return nil
	}
	last, _ := msgs[n].(map[string]any)
	if role, _ := last["role"].(string); role != "user" {
		return nil
	}
	prefix := "messages." + strconv.Itoa(n) + "."
	var parts []string
	for _, s := range req.Segments {
		if !strings.HasPrefix(s.ID+".", prefix) {
			continue
		}
		if s.Role != ingress.RoleUser || s.JSON {
			return nil // a tool result or structured content
		}
		parts = append(parts, s.Text)
	}
	text := strings.TrimSpace(strings.Join(parts, "\n"))
	if text == "" || (len(text)+3)/4 > pol.Cache.Semantic.MaxPromptTokens {
		return nil
	}

	// Everything before the last message must match exactly.
	before := make(map[string]any, len(req.Body))
	for k, v := range req.Body {
		before[k] = v
	}
	before["messages"] = msgs[:n]
	scope := "key:" + sc.caller.KeyID
	ctxFP := cache.Fingerprint(g.orgKey("fingerprint", sc.caller.OrgID), []byte("semantic-context"),
		[]byte(scope), []byte(req.Family), []byte(req.Endpoint), []byte(req.Model), cache.Canonical(before), []byte(pol.CacheVersion))
	return &semReq{fp: fp, text: text, context: ctxFP}
}

// embed returns one vector per text from the policy's embeddings connection.
func (g *Gateway) embed(ctx context.Context, sc *serveCtx, texts []string) ([][]float32, error) {
	e := sc.pol.Cache.Semantic.Embeddings
	conn := g.Registry.ByName(e.Connection)
	if conn == nil {
		return nil, fmt.Errorf("no provider connection is named %q (cache.semantic.embeddings.connection)", e.Connection)
	}
	ctx, cancel := context.WithTimeout(ctx, embedTimeout)
	defer cancel()
	return openaicompat.Embed(ctx, g.Client.HTTP, conn, e.Model, texts)
}

// semanticLookup embeds the last message and looks for a stored answer. It
// returns the match to serve, if the policy serves; in shadow mode it keeps
// the match for the comparison after the real answer.
func (g *Gateway) semanticLookup(sc *serveCtx, sr *semReq) (*cache.Match, bool) {
	vecs, err := g.embed(sc.r.Context(), sc, []string{sr.text})
	if err != nil {
		if sc.r.Context().Err() == nil {
			g.Semantic.RecordError(err)
			sc.ev.Semantic = "error"
		}
		return nil, false
	}
	sr.vec = vecs[0]
	sem := sc.pol.Cache.Semantic
	shadow := sem.Mode != "serve"
	m, ok := g.Semantic.Lookup(sc.r.Context(), g.orgKey("cache", sc.caller.OrgID), sc.caller.OrgID, sr.context, sr.text, sr.vec, sem.MinSimilarity, shadow)
	if !ok {
		sc.ev.Semantic = "miss"
		return nil, false
	}
	sc.ev.Similarity = round3(m.Similarity)
	if shadow {
		sc.ev.Semantic = "would_hit"
		sr.shadow = &m
		return nil, false
	}
	sc.ev.Semantic = "hit"
	return &m, true
}

// semanticAfter runs once the real answer is out: it admits the answer to the
// semantic cache, and in shadow mode compares it with the stored one.
func (g *Gateway) semanticAfter(sc *serveCtx, sr *semReq, e *cache.Entry, answer map[string]any) {
	if sr == nil || sr.vec == nil {
		return
	}
	pol := sc.pol
	text := answerText(sc.family, answer)
	// Admission: the answer itself must be clean of anything the detectors find.
	if text != "" && len(pol.Detectors().Scan(0, text)) == 0 {
		g.Semantic.Put(g.orgKey("cache", sc.caller.OrgID), sc.caller.OrgID, sr.context, sr.fp, sr.text, sr.vec, e,
			time.Duration(pol.Cache.Semantic.TTL), pol.Cache.Semantic.MaxEntries, g.cacheLabels(sc)...)
	}
	if sr.shadow == nil || text == "" {
		return
	}
	// The client has its answer; the comparison only fills in the event.
	http.NewResponseController(sc.w).Flush()
	stored, err := decodeObj(sr.shadow.Entry.Body)
	if err != nil {
		return
	}
	old := answerText(sc.family, stored)
	if old == text {
		sc.ev.SemanticCheck = "agree"
		return
	}
	vecs, err := g.embed(context.WithoutCancel(sc.r.Context()), sc, []string{text, old})
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			g.Semantic.RecordError(err)
		}
		return
	}
	if cache.Similarity(vecs[0], vecs[1]) >= agreeThreshold {
		sc.ev.SemanticCheck = "agree"
	} else {
		sc.ev.SemanticCheck = "disagree"
	}
}

// answerText is the text of an answer, for admission scans and comparison.
func answerText(family ingress.Family, answer map[string]any) string {
	var b strings.Builder
	if family == ingress.Anthropic {
		blocks, _ := answer["content"].([]any)
		for _, x := range blocks {
			if bm, ok := x.(map[string]any); ok && bm["type"] == "text" {
				s, _ := bm["text"].(string)
				b.WriteString(s)
			}
		}
		return b.String()
	}
	choices, _ := answer["choices"].([]any)
	if len(choices) == 0 {
		return ""
	}
	msg := obj(obj(choices[0])["message"])
	switch c := msg["content"].(type) {
	case string:
		return c
	case []any:
		for _, p := range c {
			if pm, ok := p.(map[string]any); ok {
				s, _ := pm["text"].(string)
				b.WriteString(s)
			}
		}
	}
	return b.String()
}

func round3(f float64) float64 { return float64(int(f*1000+0.5)) / 1000 }
