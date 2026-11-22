package ingress

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

func parse(t *testing.T, family Family, endpoint Endpoint, body string) *Request {
	t.Helper()
	m, err := Decode(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Parse(family, endpoint, m)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ids(r *Request) []string {
	var out []string
	for _, s := range r.Segments {
		out = append(out, s.ID)
	}
	return out
}

// Two positions never share an ID, even when a key holds a dot.
func TestSegmentIDsAreUnique(t *testing.T) {
	r := parse(t, Anthropic, Messages, `{"model":"m","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"f",
		"input":{"a":{"b":"one"},"a.b":"two","a~b":"three","rows":[["four"]]}}]}]}`)
	got := ids(r)
	want := []string{"messages.0.content.0.input.a.b", "messages.0.content.0.input.a~1b", "messages.0.content.0.input.a~0b", "messages.0.content.0.input.rows.0.0"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("%v", got)
	}
}

// Every field that reaches the model is a segment, except settings and the
// structural values of schemas (a type, a name, a pattern).
func TestFieldsOutsideTheMessagesAreSegments(t *testing.T) {
	r := parse(t, OpenAI, Chat, `{"model":"m","temperature":0.2,"stream":true,"tool_choice":"auto",
		"messages":[{"role":"user","name":"alice","content":"hi"},
		            {"role":"assistant","function_call":{"name":"f","arguments":"{\"x\":1}"},"tool_calls":[{"id":"c","type":"custom","custom":{"name":"sh","input":"ls"}}]}],
		"prediction":{"type":"content","content":"old file"},
		"tools":[{"type":"function","function":{"name":"f","description":"does f","parameters":{"type":"object","required":["x"],
		          "properties":{"x":{"type":"string","pattern":"^a","description":"the x","enum":["e1"]}}}}}],
		"response_format":{"type":"json_schema","json_schema":{"name":"s","schema":{"type":"object","description":"the answer"}}},
		"stop":["END"],"user":"u@example.com","metadata":{"k":"v"},"future_field":{"text":"new"}}`)
	got := ids(r)
	sort.Strings(got)
	want := []string{"future_field.text", "messages.0.content", "messages.0.name", "messages.1.function_call.arguments", "messages.1.tool_calls.0.input",
		"metadata.k", "prediction.content", "response_format.json_schema.schema.description", "stop.0",
		"tools.0.function.description", "tools.0.function.parameters.properties.x.description", "tools.0.function.parameters.properties.x.enum.0", "user"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
	for _, s := range r.Segments {
		if s.Fixed != (s.ID == "messages.0.name") {
			t.Fatalf("%s fixed=%v", s.ID, s.Fixed)
		}
	}
	a := parse(t, Anthropic, Messages, `{"model":"m","max_tokens":5,"thinking":{"type":"enabled","budget_tokens":100},
		"messages":[{"role":"user","content":"hi"}],"metadata":{"user_id":"u1"},"stop_sequences":["END"],
		"tools":[{"name":"f","description":"does f","input_schema":{"type":"object"}}],
		"mcp_servers":[{"type":"url","url":"https://mcp.example.com","name":"m","authorization_token":"tok"}]}`)
	got = ids(a)
	sort.Strings(got)
	want = []string{"mcp_servers.0.url", "messages.0.content", "metadata.user_id", "stop_sequences.0", "tools.0.description"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

// Scanning more fields does not change which conversation a request belongs to.
func TestConversationIgnoresTheNewFields(t *testing.T) {
	plain := parse(t, OpenAI, Chat, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
	named := parse(t, OpenAI, Chat, `{"model":"m","messages":[{"role":"user","name":"alice","content":"hi"}],"user":"u1","metadata":{"k":"v"}}`)
	if string(plain.Conversation) != string(named.Conversation) {
		t.Fatalf("%q != %q", plain.Conversation, named.Conversation)
	}
}

// Setting a segment rewrites the request in place, wherever it sits.
func TestSegmentsWriteBack(t *testing.T) {
	r := parse(t, OpenAI, Chat, `{"model":"m","messages":[{"role":"user","content":"hi"}],"prediction":{"type":"content","content":"old"},"stop":["a"]}`)
	for _, s := range r.Segments {
		s.Set("[" + s.ID + "]")
	}
	b, _ := json.Marshal(r.Body)
	if !strings.Contains(string(b), `"content":"[prediction.content]"`) || !strings.Contains(string(b), `"stop":["[stop.0]"]`) {
		t.Fatalf("%s", b)
	}
}
