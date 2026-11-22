package detection

// The coverage gate: a value is protected only if the detectors see it. A
// canary card number is planted in every field of a request that carries text
// to the model, in the request shapes the OpenAI and Anthropic APIs accept;
// each one must be found. A field the parser does not expose as text would
// carry it past every detector and every policy (goal G4).
//
// Every value here is synthetic.

import (
	"strings"
	"testing"

	"github.com/Kytherion/KyGate/internal/detect"
	"github.com/Kytherion/KyGate/internal/ingress"
)

const canary = "4111 1111 1111 1111"

var shapes = []struct {
	name     string
	family   ingress.Family
	endpoint ingress.Endpoint
	body     string
	// planted is how many canaries the body holds that must be found.
	planted int
}{
	{"openai chat, every field", ingress.OpenAI, ingress.Chat, `{"model":"gpt-4o-mini",
		"messages":[
		  {"role":"developer","content":[{"type":"text","text":"rules C"}]},
		  {"role":"user","content":[{"type":"text","text":"C"},{"type":"some_new_part","note":"C"}]},
		  {"role":"assistant","content":"C","refusal":"C",
		   "tool_calls":[{"id":"1","type":"function","function":{"name":"f","arguments":"{\"c\":\"C\"}"}},
		                 {"id":"2","type":"custom","custom":{"name":"sh","input":"C"}}],
		   "function_call":{"name":"g","arguments":"{\"c\":\"C\"}"}},
		  {"role":"tool","tool_call_id":"1","content":"C"},
		  {"role":"user","content":"C","some_new_field":"C"}],
		"prediction":{"type":"content","content":[{"type":"text","text":"C"}]},
		"tools":[{"type":"function","function":{"name":"f","description":"C","parameters":{"type":"object",
		  "properties":{"name":{"type":"string","description":"C","enum":["C"],"default":"C","examples":[["C"]]}}}}}],
		"response_format":{"type":"json_schema","json_schema":{"name":"s","description":"C","schema":{"type":"object","description":"C"}}},
		"stop":["C"],"user":"C","safety_identifier":"C","metadata":{"k":"C"},"web_search_options":{"user_location":{"approximate":{"city":"C"}}},
		"some_new_option":{"text":"C"}}`, 25},
	{"openai embeddings", ingress.OpenAI, ingress.Embeddings, `{"model":"e","input":["C","C"],"user":"C"}`, 3},
	{"anthropic messages, every field", ingress.Anthropic, ingress.Messages, `{"model":"claude-opus-5-5","max_tokens":10,
		"system":[{"type":"text","text":"C"}],
		"messages":[
		  {"role":"user","content":[{"type":"text","text":"C"},
		     {"type":"document","source":{"type":"text","media_type":"text/plain","data":"C"},"title":"C","context":"C"},
		     {"type":"search_result","source":"https://example.com","title":"C","content":[{"type":"text","text":"C"}]}]},
		  {"role":"assistant","content":[{"type":"text","text":"C"},
		     {"type":"tool_use","id":"t","name":"f","input":{"c":"C","rows":[["C"]],"a.b":"C"}}]},
		  {"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"C"}]}]}],
		"tools":[{"name":"f","description":"C","input_schema":{"type":"object","properties":{"x":{"type":"string","description":"C"}}}}],
		"metadata":{"user_id":"C"},"stop_sequences":["C"],"some_new_option":{"text":"C"}}`, 17},
}

func TestEveryTextFieldIsInspected(t *testing.T) {
	set := detect.NewSet(nil)
	for _, s := range shapes {
		body := strings.ReplaceAll(s.body, `"C"`, `"`+canary+`"`)
		body = strings.ReplaceAll(body, `\"C\"`, `\"`+canary+`\"`)
		body = strings.ReplaceAll(body, "rules C", "rules "+canary)
		if n := strings.Count(body, canary); n != s.planted {
			t.Fatalf("%s: the shape holds %d canaries, the case says %d", s.name, n, s.planted)
		}
		m, err := ingress.Decode(strings.NewReader(body))
		if err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		req, err := ingress.Parse(s.family, s.endpoint, m)
		if err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		found := 0
		for i, seg := range req.Segments {
			for _, f := range set.Scan(i, seg.Text) {
				if f.Type == "CREDIT_CARD" {
					found++
				}
			}
		}
		if found != s.planted {
			t.Errorf("%s: %d of %d canaries found; a field carries text past the detectors", s.name, found, s.planted)
		}
	}
}
