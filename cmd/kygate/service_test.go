package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretAndNonSecretEnv(t *testing.T) {
	for k, v := range map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-test", "OPENAI_API_KEY_TEAM": "sk-test", "KYGATE_LOCAL_OLLAMA": "http://localhost:11434/v1",
		"KYGATE_LOCAL_VLLM_KEY": "secret", "OPENAI_BASE_URL": "http://proxy", "KYGATE_CATALOG": "/tmp/c.yaml",
		"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318", "OTEL_EXPORTER_OTLP_HEADERS": "authorization=Bearer secret",
	} {
		t.Setenv(k, v)
	}
	secrets := strings.Join(secretEnv(), ",")
	for _, k := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY_TEAM", "KYGATE_LOCAL_VLLM_KEY"} {
		if !strings.Contains(secrets, k) {
			t.Errorf("%s must count as a secret: %s", k, secrets)
		}
	}
	plain := nonSecretEnv()
	if plain["OTEL_EXPORTER_OTLP_HEADERS"] != "" {
		t.Error("OTLP headers can carry a token and are never kept in service.json")
	}
	for _, k := range []string{"KYGATE_LOCAL_OLLAMA", "OPENAI_BASE_URL", "KYGATE_CATALOG", "OTEL_EXPORTER_OTLP_ENDPOINT"} {
		if plain[k] == "" {
			t.Errorf("%s must be kept for the service", k)
		}
	}
	for k := range plain {
		if strings.Contains(k, "API_KEY") || strings.HasSuffix(k, "_KEY") {
			t.Errorf("a key is never kept in service.json: %s", k)
		}
	}
}

func TestConnectionName(t *testing.T) {
	for v, want := range map[string]string{
		"ANTHROPIC_API_KEY": "anthropic", "OPENAI_API_KEY": "openai", "OPENAI_API_KEY_TEAM": "openai-team",
		"ANTHROPIC_API_KEY_2": "anthropic-2", "KYGATE_LOCAL_VLLM_KEY": "local-vllm",
	} {
		if got := connectionName(v); got != want {
			t.Errorf("%s: got %q, want %q", v, got, want)
		}
	}
}

func TestRotatingLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kygate.log")
	l, err := openLog(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		l.Write([]byte(strings.Repeat("x", 30) + "\n"))
	}
	l.Close()
	cur, _ := os.ReadFile(p)
	old, _ := os.ReadFile(p + ".1")
	if len(cur) > 100 || len(old) == 0 || len(old) > 100 {
		t.Fatalf("current %d bytes, previous %d bytes", len(cur), len(old))
	}
}

func TestServeArgs(t *testing.T) {
	c := &serviceConfig{DataDir: "/d", Listen: "127.0.0.1:4000", ConsoleListen: "127.0.0.1:4001", Policy: "/p.yaml"}
	if got := strings.Join(c.serveArgs(), " "); got != "serve --data-dir /d --listen 127.0.0.1:4000 --console-listen 127.0.0.1:4001 --policy /p.yaml" {
		t.Fatal(got)
	}
	if dialAddr(":4000") != "127.0.0.1:4000" || dialAddr("0.0.0.0:4001") != "127.0.0.1:4001" {
		t.Fatal("wildcard listen addresses must be dialed on the loopback")
	}
}

func TestSplitArgs(t *testing.T) {
	got, err := splitArgs(`--recognizers "C:\My Files\names.json"  --workers 2`)
	if err != nil || strings.Join(got, "|") != `--recognizers|C:\My Files\names.json|--workers|2` {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := splitArgs(`--recognizers "C:\open`); err == nil {
		t.Fatal("an unclosed quote is an error")
	}
}
