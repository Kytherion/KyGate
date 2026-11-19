package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStarterPolicyKeepsTheCacheOnDisk(t *testing.T) {
	p, err := Parse(Starter(), "starter.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !p.CachePersist() || p.Cache.Exact.MaxDiskMB != 1024 || p.Cache.Exact.MaxSizeMB != 256 {
		t.Fatalf("persist %v, max_disk_mb %d, max_size_mb %d", p.CachePersist(), p.Cache.Exact.MaxDiskMB, p.Cache.Exact.MaxSizeMB)
	}
}

// The upgrade rule: a policy file written before the setting existed keeps
// the cache in memory only.
func TestPersistIsOffWhenNotNamed(t *testing.T) {
	p, err := Parse([]byte("data:\n  unreadable_content: block\ncache:\n  exact:\n    ttl: 30d\n"), "old.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.CachePersist() {
		t.Fatal("persist must be off when the policy does not name it")
	}
	if p.Cache.Exact.MaxDiskMB != 1024 {
		t.Fatalf("max_disk_mb default %d", p.Cache.Exact.MaxDiskMB)
	}
	if time.Duration(p.Cache.Exact.TTL) != 30*24*time.Hour {
		t.Fatalf("ttl %v", time.Duration(p.Cache.Exact.TTL))
	}
}

func TestPersistNeedsTheCache(t *testing.T) {
	p, err := Parse([]byte("data:\n  unreadable_content: block\ncache:\n  exact:\n    enabled: false\n    persist: true\n"), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.CachePersist() {
		t.Fatal("a disabled cache keeps nothing on disk")
	}
}

// The starter policy saves as much as it can: answers kept 30 days, the
// regenerate rule off, and the semantic cache written out but off until an
// embeddings model is named.
func TestStarterCacheSettings(t *testing.T) {
	p, err := Parse(Starter(), "starter.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(p.Cache.Exact.TTL) != 30*24*time.Hour || p.RepeatWindow() != 0 {
		t.Fatalf("ttl %v, repeat window %v", time.Duration(p.Cache.Exact.TTL), p.RepeatWindow())
	}
	s := p.Cache.Semantic
	if p.SemanticEnabled() || s.Mode != "shadow" || s.Scope != "key" || s.MinSimilarity != 0.95 || s.Embeddings.Connection != "local-ollama" {
		t.Fatalf("semantic %+v", s)
	}
	if len(p.Warnings) != 0 {
		t.Fatalf("the starter policy must load without warnings: %v", p.Warnings)
	}
}

// The upgrade rule: an older policy keeps the 30s regenerate rule and has no
// semantic cache.
func TestOlderPolicyDefaults(t *testing.T) {
	p, err := Parse([]byte("data:\n  unreadable_content: block\n"), "old.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.RepeatWindow() != 30*time.Second || p.SemanticEnabled() {
		t.Fatalf("repeat %v, semantic %v", p.RepeatWindow(), p.SemanticEnabled())
	}
	// The illustrative section of the architecture still loads.
	p, err = Parse([]byte("data:\n  unreadable_content: block\ncache:\n  semantic: { scope: application, ttl: 6h, mode: shadow, max_prompt_tokens: 256 }\n"), "old.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.SemanticEnabled() || p.Cache.Semantic.Scope != "key" || len(p.Warnings) != 1 {
		t.Fatalf("semantic %+v, warnings %v", p.Cache.Semantic, p.Warnings)
	}
}

func TestSemanticNeedsAnEmbeddingsModel(t *testing.T) {
	_, err := Parse([]byte("data:\n  unreadable_content: block\ncache:\n  semantic:\n    enabled: true\n"), "x.yaml")
	if err == nil || !strings.Contains(err.Error(), "embeddings") {
		t.Fatalf("want an error naming the embeddings settings, got %v", err)
	}
	for _, s := range []string{"scope: org", "mode: always", "min_similarity: 0.5"} {
		if _, err := Parse([]byte("data:\n  unreadable_content: block\ncache:\n  semantic:\n    "+s+"\n"), "x.yaml"); err == nil {
			t.Fatalf("%s: want an error", s)
		}
	}
}

// The cache version changes only with what can change a masked request.
func TestCacheVersion(t *testing.T) {
	base := string(Starter())
	v := func(s string) string {
		p, err := Parse([]byte(s), "x.yaml")
		if err != nil {
			t.Fatal(err)
		}
		return p.CacheVersion
	}
	want := v(base)
	for _, edit := range [][2]string{
		{"# KyGate starter policy", "# Edited"},
		{"ttl: 30d", "ttl: 90d"},
		{"repeat_window: 0s", "repeat_window: 30s"},
		{"retention_days: 90", "retention_days: 30"},
		{"max_disk_mb: 1024", "max_disk_mb: 4096"},
	} {
		if got := v(strings.Replace(base, edit[0], edit[1], 1)); got != want {
			t.Errorf("%q -> %q must keep the cache version", edit[0], edit[1])
		}
	}
	for _, edit := range [][2]string{
		{"mode: enforce", "mode: monitor"},
		{"EMAIL:       { action: allow }", "EMAIL:       { action: mask }"},
		{"scope: org            #", "scope: key            #"},
		{"unreadable_content: local_only", "unreadable_content: block"},
	} {
		if got := v(strings.Replace(base, edit[0], edit[1], 1)); got == want {
			t.Errorf("%q -> %q must change the cache version", edit[0], edit[1])
		}
	}
}

func TestNegativeCacheSizesAreRejected(t *testing.T) {
	for _, s := range []string{"max_disk_mb: -1", "max_size_mb: -5", "ttl: -1h"} {
		_, err := Parse([]byte("data:\n  unreadable_content: block\ncache:\n  exact:\n    "+s+"\n"), "x.yaml")
		if err == nil || !strings.Contains(err.Error(), "cache.exact") {
			t.Fatalf("%s: want an error, got %v", s, err)
		}
	}
}

// The console reads a rule's action and detection from /api/v1/info under these
// names; without JSON tags Go sent "Action", and the Protection page failed.
func TestEntityRuleJSONShape(t *testing.T) {
	b, err := json.Marshal(EntityRule{Action: Mask, Detection: "model"})
	if err != nil || string(b) != `{"action":"mask","detection":"model"}` {
		t.Fatalf("%s %v", b, err)
	}
}

// detection: model.
func TestDetectionSetting(t *testing.T) {
	base := "data:\n  unreadable_content: block\n  entities:\n"
	p, err := Parse([]byte(base+"    PERSON: { action: mask }\n    EMAIL: { action: mask, detection: model }\n"), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Data.Entities["PERSON"].Detection != "any" || strings.Join(p.ModelRequired(), ",") != "EMAIL" {
		t.Fatalf("%+v", p.Data.Entities)
	}
	// A type the fast detectors find needs the Guard too once it requires a model.
	if strings.Join(p.GuardEntities(), ",") != "EMAIL,PERSON" {
		t.Fatalf("guard entities %v", p.GuardEntities())
	}
	for _, bad := range []string{"    PERSON: { action: mask, detection: ml }\n", "    dict/x: { action: mask, detection: model }\n"} {
		if _, err := Parse([]byte(base+bad+"  dictionaries:\n    x: { terms: [a] }\n"), "x.yaml"); err == nil {
			t.Fatalf("want an error for %q", bad)
		}
	}
	q, _ := Parse([]byte(base+"    PERSON: { action: mask, detection: model }\n    EMAIL: { action: mask, detection: model }\n"), "x.yaml")
	if q.CacheVersion == p.CacheVersion {
		t.Fatal("changing detection must start a new cache")
	}
}
