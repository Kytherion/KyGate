package provider

import (
	"net/http"
	"testing"

	"github.com/Kytherion/KyGate/internal/provider/openai"
)

// A connection whose region changes is replaced at once: a region decides
// where a pinned request may go. Unchanged connections keep their state.
func TestReplaceAppliesARegionChange(t *testing.T) {
	r := NewRegistry()
	a := NewConnection("openai", OpenAI, "", "sk-1", "stored")
	a.Region = "eu"
	b := NewConnection("anthropic", Anthropic, "", "sk-2", "stored")
	r.Replace([]*Connection{a, b})

	a2 := NewConnection("openai", OpenAI, "", "sk-1", "stored")
	a2.Region = "us"
	b2 := NewConnection("anthropic", Anthropic, "", "sk-2", "stored")
	r.Replace([]*Connection{a2, b2})
	if got := r.ByName("openai"); got != a2 || got.Region != "us" {
		t.Fatalf("region %q", got.Region)
	}
	if r.ByName("anthropic") != b {
		t.Fatal("an unchanged connection keeps its state")
	}
}

// The OpenAI organization and project belong to the connection: a client's
// headers never choose what the operator's key bills.
func TestOrganizationAndProjectComeFromTheConnection(t *testing.T) {
	in := http.Header{}
	in.Set("OpenAI-Organization", "org-of-the-client")
	in.Set("OpenAI-Project", "proj-of-the-client")
	in.Set("OpenAI-Beta", "assistants=v2")
	out := openai.ForwardHeaders(in)
	if out.Get("OpenAI-Organization") != "" || out.Get("OpenAI-Project") != "" || out.Get("OpenAI-Beta") != "assistants=v2" {
		t.Fatalf("%v", out)
	}
	c := NewConnection("openai", OpenAI, "", "sk-1", "env")
	c.Organization, c.Project = "org-1", "proj-1"
	c.authorize(in)
	if in.Get("OpenAI-Organization") != "org-1" || in.Get("OpenAI-Project") != "proj-1" || in.Get("Authorization") != "Bearer sk-1" {
		t.Fatalf("%v", in)
	}
	none := NewConnection("openai-2", OpenAI, "", "sk-2", "env")
	h := http.Header{"Openai-Organization": {"org-x"}}
	none.authorize(h)
	if h.Get("OpenAI-Organization") != "" {
		t.Fatal("a connection with no organization sends none")
	}
}
