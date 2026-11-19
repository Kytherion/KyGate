package pipeline_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Kytherion/KyGate/internal/control"
	"github.com/Kytherion/KyGate/internal/policy"
)

func pinned(regions string) string {
	return strings.Replace(string(policy.Starter()), "  # regions: [eu]\n", "  regions: "+regions+"\n", 1)
}

// GV-4: requests go only to connections in the policy's regions; a
// connection without a region is never used; nothing left means a refusal.
func TestRegionPinning(t *testing.T) {
	h := newHarness(t, pinned("[eu]"), "sk-ant-2")
	conns := h.g.Registry.All()
	for _, c := range conns {
		switch c.Name {
		case "anthropic":
			c.Region = "us"
		case "anthropic-2":
			c.Region = "eu"
		}
	}
	for i := 0; i < 4; i++ {
		resp, body := h.post("/v1/messages", h.keyA, messages(fmt.Sprintf("hello %d", i), false), "X-KyGate-Cache", "no-cache")
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: %d %s", i, resp.StatusCode, body)
		}
	}
	for _, e := range h.events() {
		if e.Connection != "anthropic-2" {
			t.Fatalf("a us connection served a request pinned to eu: %q", e.Connection)
		}
	}

	// The OpenAI connection has no region: refused, before any call.
	before := h.up.calls
	resp, body := h.post("/v1/chat/completions", h.keyA, chat("hello", false))
	if resp.StatusCode != 403 || !strings.Contains(body, "data.regions") || resp.Header.Get("X-KyGate-Blocked") != "REGION" {
		t.Fatalf("no connection in the region: %d %s", resp.StatusCode, body)
	}
	if h.up.calls != before {
		t.Fatal("a refused request never reaches a provider")
	}
	evs := h.events()
	if last := evs[0]; last.Outcome != "refused" || !strings.Contains(last.Reason, "region") {
		t.Fatalf("the event says why: %+v", last)
	}
}

func TestRegionPinningInMonitorMode(t *testing.T) {
	h := newHarness(t, strings.Replace(pinned("[eu]"), "mode: enforce", "mode: monitor", 1))
	resp, body := h.post("/v1/chat/completions", h.keyA, chat("hello", false))
	if resp.StatusCode != 200 {
		t.Fatalf("monitor mode changes nothing: %d %s", resp.StatusCode, body)
	}
	if e := h.events()[0]; !e.Alert || !strings.Contains(e.Reason, "region") {
		t.Fatalf("monitor mode flags what it would refuse: %+v", e)
	}
}

// GV-4: answers carry the application's tags; a purge by tag removes them.
func TestCacheTagsAndPurge(t *testing.T) {
	h := newHarness(t, "")
	ctx := context.Background()
	org, _ := h.db.Meta(ctx, "org_id")
	p := &control.Purger{DB: h.db, Cache: h.g.Cache, Semantic: h.g.Semantic, MasterKey: h.g.MasterKey, OrgID: org}
	send := func(text string, hdr ...string) string {
		resp, body := h.post("/v1/chat/completions", h.keyA, chat(text, false), hdr...)
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		return resp.Header.Get("X-KyGate-Cache")
	}
	send("tagged question", "X-KyGate-Cache-Tags", "docs-v3, faq")
	send("other question")
	if send("tagged question") != "hit" || send("other question") != "hit" {
		t.Fatal("both are cached")
	}
	label, _, err := p.Resolve(ctx, "", "faq", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.PurgeCache(ctx, label); err != nil {
		t.Fatal(err)
	}
	if got := send("tagged question"); got != "miss" {
		t.Fatalf("the tagged answer is purged: %s", got)
	}
	if got := send("other question"); got != "hit" {
		t.Fatalf("the untagged one stays: %s", got)
	}
	if got := send("third", "X-KyGate-Cache-Tags", "not a tag!"); got != "bypass" {
		t.Fatalf("an invalid tag is never stored untagged: %s", got)
	}
	if e := h.events()[0]; !strings.Contains(e.CacheReason, "X-KyGate-Cache-Tags") {
		t.Fatalf("the event says why: %+v", e.CacheReason)
	}
	// Purge all.
	label, _, _ = p.Resolve(ctx, "", "", true)
	p.PurgeCache(ctx, label)
	if got := send("other question"); got != "miss" {
		t.Fatalf("purge all: %s", got)
	}
}
