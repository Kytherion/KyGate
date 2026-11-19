// Package ingress parses the OpenAI and Anthropic wire formats into one
// internal request model (capability AC-1, pipeline stage 1).
//
// KyGate runs in native mode: a request goes to the API family it
// arrived in. The request keeps its decoded JSON tree, and only the fields
// that carry text are exposed as segments. Every other field passes through
// unchanged (architecture §4.2).
package ingress

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Family is the API family a request arrived in.
type Family string

const (
	OpenAI    Family = "openai"
	Anthropic Family = "anthropic"
)

// Endpoint is the kind of request.
type Endpoint string

const (
	Chat        Endpoint = "chat"         // OpenAI /v1/chat/completions
	Embeddings  Endpoint = "embeddings"   // OpenAI /v1/embeddings
	Messages    Endpoint = "messages"     // Anthropic /v1/messages
	CountTokens Endpoint = "count_tokens" // Anthropic /v1/messages/count_tokens
)

// Role of a segment.
const (
	RoleSystem     = "system"
	RoleUser       = "user"
	RoleAssistant  = "assistant"
	RoleToolResult = "tool_result"
	RoleInput      = "input" // embedding input
)

// Segment is one piece of text in a request: the system prompt, one message,
// one tool result.
type Segment struct {
	ID        string // position, for example "messages.3.content.0"
	Role      string
	Untrusted bool // user turns and tool results
	Text      string
	// JSON is true when Text is itself JSON text, such as tool-call arguments.
	JSON bool
	set  func(string)
}

// Set replaces the text of the segment inside the request.
func (s *Segment) Set(text string) {
	if s.set != nil {
		s.set(text)
	}
	s.Text = text
}

// Request is the internal request model.
type Request struct {
	Family   Family
	Endpoint Endpoint
	Model    string
	Stream   bool
	Body     map[string]any
	Segments []*Segment
	// Unreadable lists content KyGate cannot read yet: image, audio, file.
	Unreadable []string
	// HiddenState is set when the answer depends on state KyGate cannot see,
	// such as provider-side tools or uploaded file references. Such requests
	// are never cached (architecture §3.4).
	HiddenState string
	// Conversation identifies a conversation by its first turns, for affinity.
	Conversation []byte
}

// ErrBadRequest wraps parse errors that the client must fix.
var ErrBadRequest = errors.New("bad request")

func badRequest(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBadRequest, fmt.Sprintf(format, a...))
}

// Decode reads a JSON object, keeping numbers exact.
func Decode(r io.Reader) (map[string]any, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	var body map[string]any
	if err := dec.Decode(&body); err != nil {
		return nil, badRequest("the body is not a JSON object: %v", err)
	}
	if dec.More() {
		return nil, badRequest("the body holds more than one JSON value")
	}
	return body, nil
}

// Encode writes the request body back to JSON.
func (r *Request) Encode() []byte {
	return Marshal(r.Body)
}

// Marshal encodes JSON without HTML escaping, so text reaches the model as written.
func Marshal(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// Parse builds the request model for one endpoint.
func Parse(family Family, endpoint Endpoint, body map[string]any) (*Request, error) {
	r := &Request{Family: family, Endpoint: endpoint, Body: body}
	model, _ := body["model"].(string)
	if model == "" {
		return nil, badRequest("the request names no model")
	}
	r.Model = model
	r.Stream, _ = body["stream"].(bool)
	var err error
	switch endpoint {
	case Chat:
		err = r.parseOpenAIChat()
	case Embeddings:
		r.Stream = false
		err = r.parseOpenAIEmbeddings()
	case Messages, CountTokens:
		if endpoint == CountTokens {
			r.Stream = false
		}
		err = r.parseAnthropic()
	default:
		err = badRequest("unknown endpoint")
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Request) add(id, role string, untrusted, isJSON bool, text string, set func(string)) {
	r.Segments = append(r.Segments, &Segment{ID: id, Role: role, Untrusted: untrusted, JSON: isJSON, Text: text, set: set})
}

func (r *Request) unreadable(kind string) {
	for _, k := range r.Unreadable {
		if k == kind {
			return
		}
	}
	r.Unreadable = append(r.Unreadable, kind)
}

func (r *Request) hidden(reason string) {
	if r.HiddenState == "" {
		r.HiddenState = reason
	}
}

// ---- OpenAI ----

func (r *Request) parseOpenAIChat() error {
	msgs, ok := r.Body["messages"].([]any)
	if !ok {
		return badRequest("messages must be an array")
	}
	if _, ok := r.Body["web_search_options"]; ok {
		r.hidden("web search")
	}
	if tools, ok := r.Body["tools"].([]any); ok {
		for _, t := range tools {
			if tm, ok := t.(map[string]any); ok {
				if typ, _ := tm["type"].(string); typ != "" && typ != "function" && typ != "custom" {
					r.hidden("provider-side tool " + typ)
				}
			}
		}
	}
	var conv strings.Builder
	conv.WriteString("openai\x00" + r.Model)
	firstUser := false
	for i, m := range msgs {
		msg, ok := m.(map[string]any)
		if !ok {
			return badRequest("messages.%d must be an object", i)
		}
		role, _ := msg["role"].(string)
		segRole, untrusted := RoleUser, true
		switch role {
		case "system", "developer":
			segRole, untrusted = RoleSystem, false
		case "assistant":
			segRole, untrusted = RoleAssistant, false
		case "tool", "function":
			segRole = RoleToolResult
		}
		base := "messages." + strconv.Itoa(i)
		before := len(r.Segments)
		r.openAIContent(msg, "content", base+".content", segRole, untrusted)
		if s, ok := msg["refusal"].(string); ok && s != "" {
			r.add(base+".refusal", segRole, untrusted, false, s, func(v string) { msg["refusal"] = v })
		}
		if calls, ok := msg["tool_calls"].([]any); ok {
			for j, c := range calls {
				cm, _ := c.(map[string]any)
				fn, _ := cm["function"].(map[string]any)
				if fn == nil {
					continue
				}
				if args, ok := fn["arguments"].(string); ok {
					r.add(fmt.Sprintf("%s.tool_calls.%d.arguments", base, j), RoleAssistant, false, true, args, func(v string) { fn["arguments"] = v })
				}
			}
		}
		if (role == "system" || role == "developer" || (role == "user" && !firstUser)) && len(r.Segments) > before {
			for _, s := range r.Segments[before:] {
				conv.WriteString("\x00" + s.Text)
			}
			if role == "user" {
				firstUser = true
			}
		}
	}
	r.Conversation = []byte(conv.String())
	return nil
}

func (r *Request) openAIContent(parent map[string]any, key, id, role string, untrusted bool) {
	switch c := parent[key].(type) {
	case string:
		r.add(id, role, untrusted, false, c, func(v string) { parent[key] = v })
	case []any:
		for j, p := range c {
			part, ok := p.(map[string]any)
			if !ok {
				continue
			}
			pid := id + "." + strconv.Itoa(j)
			switch typ, _ := part["type"].(string); typ {
			case "text":
				if s, ok := part["text"].(string); ok {
					r.add(pid, role, untrusted, false, s, func(v string) { part["text"] = v })
				}
			case "refusal":
				if s, ok := part["refusal"].(string); ok {
					r.add(pid, role, untrusted, false, s, func(v string) { part["refusal"] = v })
				}
			case "image_url":
				r.unreadable("image")
			case "input_audio":
				r.unreadable("audio")
			case "file":
				r.unreadable("file")
				if f, ok := part["file"].(map[string]any); ok {
					if _, ok := f["file_id"]; ok {
						r.hidden("uploaded file reference")
					}
				}
			default:
				r.walkStrings(part, pid, role, untrusted)
			}
		}
	}
}

func (r *Request) parseOpenAIEmbeddings() error {
	switch in := r.Body["input"].(type) {
	case string:
		r.add("input", RoleInput, true, false, in, func(v string) { r.Body["input"] = v })
	case []any:
		for i, v := range in {
			switch s := v.(type) {
			case string:
				idx := i
				r.add("input."+strconv.Itoa(i), RoleInput, true, false, s, func(v string) { in[idx] = v })
			default:
				// Token arrays cannot be scanned as text.
				r.unreadable("tokens")
			}
		}
	default:
		return badRequest("input must be a string or an array")
	}
	return nil
}

// ---- Anthropic ----

func (r *Request) parseAnthropic() error {
	var conv strings.Builder
	conv.WriteString("anthropic\x00" + r.Model)
	switch s := r.Body["system"].(type) {
	case string:
		r.add("system", RoleSystem, false, false, s, func(v string) { r.Body["system"] = v })
		conv.WriteString("\x00" + s)
	case []any:
		for i, b := range s {
			if bm, ok := b.(map[string]any); ok {
				if t, ok := bm["text"].(string); ok {
					r.add("system."+strconv.Itoa(i), RoleSystem, false, false, t, func(v string) { bm["text"] = v })
					conv.WriteString("\x00" + t)
				}
			}
		}
	}
	if _, ok := r.Body["container"]; ok {
		r.hidden("code execution container")
	}
	if _, ok := r.Body["mcp_servers"]; ok {
		r.hidden("remote MCP servers")
	}
	if _, ok := r.Body["thread"]; ok {
		r.hidden("provider-kept message thread")
	}
	if tools, ok := r.Body["tools"].([]any); ok {
		for _, t := range tools {
			if tm, ok := t.(map[string]any); ok {
				if typ, _ := tm["type"].(string); typ != "" && typ != "custom" {
					r.hidden("provider-side tool " + typ)
				}
			}
		}
	}
	msgs, ok := r.Body["messages"].([]any)
	if !ok {
		return badRequest("messages must be an array")
	}
	firstUser := false
	for i, m := range msgs {
		msg, ok := m.(map[string]any)
		if !ok {
			return badRequest("messages.%d must be an object", i)
		}
		role, _ := msg["role"].(string)
		segRole, untrusted := RoleUser, true
		switch role {
		case "assistant":
			segRole, untrusted = RoleAssistant, false
		case "system":
			segRole, untrusted = RoleSystem, false
		}
		base := "messages." + strconv.Itoa(i) + ".content"
		before := len(r.Segments)
		switch c := msg["content"].(type) {
		case string:
			r.add(base, segRole, untrusted, false, c, func(v string) { msg["content"] = v })
		case []any:
			for j, b := range c {
				if bm, ok := b.(map[string]any); ok {
					r.anthropicBlock(bm, base+"."+strconv.Itoa(j), segRole, untrusted)
				}
			}
		}
		if role == "user" && !firstUser {
			firstUser = true
			for _, s := range r.Segments[before:] {
				conv.WriteString("\x00" + s.Text)
			}
		}
	}
	r.Conversation = []byte(conv.String())
	return nil
}

func (r *Request) anthropicBlock(b map[string]any, id, role string, untrusted bool) {
	switch typ, _ := b["type"].(string); typ {
	case "text":
		if s, ok := b["text"].(string); ok {
			r.add(id, role, untrusted, false, s, func(v string) { b["text"] = v })
		}
	case "thinking", "redacted_thinking":
		// Reasoning blocks and their signatures pass through untouched in
		// both directions (architecture §4.3).
	case "image":
		r.unreadable("image")
		r.fileSource(b)
	case "document":
		if src, ok := b["source"].(map[string]any); ok {
			switch st, _ := src["type"].(string); st {
			case "text":
				if s, ok := src["data"].(string); ok {
					r.add(id+".source", RoleToolResult, true, false, s, func(v string) { src["data"] = v })
				}
			case "content":
				if blocks, ok := src["content"].([]any); ok {
					for k, cb := range blocks {
						if cbm, ok := cb.(map[string]any); ok {
							r.anthropicBlock(cbm, fmt.Sprintf("%s.source.%d", id, k), RoleToolResult, true)
						}
					}
				}
			default:
				r.unreadable("file")
				r.fileSource(b)
			}
		}
		if t, ok := b["title"].(string); ok && t != "" {
			r.add(id+".title", RoleToolResult, true, false, t, func(v string) { b["title"] = v })
		}
		if t, ok := b["context"].(string); ok && t != "" {
			r.add(id+".context", RoleToolResult, true, false, t, func(v string) { b["context"] = v })
		}
	case "tool_use":
		if in, ok := b["input"].(map[string]any); ok {
			r.walkStrings(in, id+".input", RoleAssistant, false)
		}
	case "tool_result":
		switch c := b["content"].(type) {
		case string:
			r.add(id+".content", RoleToolResult, true, false, c, func(v string) { b["content"] = v })
		case []any:
			for k, cb := range c {
				if cbm, ok := cb.(map[string]any); ok {
					r.anthropicBlock(cbm, fmt.Sprintf("%s.content.%d", id, k), RoleToolResult, true)
				}
			}
		}
	case "server_tool_use", "web_search_tool_result", "web_fetch_tool_result", "code_execution_tool_result",
		"bash_code_execution_tool_result", "text_editor_code_execution_tool_result", "mcp_tool_use", "mcp_tool_result",
		"container_upload", "tool_search_tool_result", "compaction":
		// Results produced on the provider's side: the answer depends on state
		// KyGate cannot see. They are scanned where they carry plain text.
		r.hidden("provider-side tool results")
		r.walkStrings(b, id, RoleToolResult, true, "encrypted_content", "encrypted_index", "signature", "data", "file_id", "id", "tool_use_id", "type")
	default:
		// An unknown block is scanned as a whole, so that new block types
		// cannot carry text past the detectors (goal G4).
		r.walkStrings(b, id, role, untrusted, "type", "id", "signature", "data", "media_type")
	}
}

func (r *Request) fileSource(b map[string]any) {
	if src, ok := b["source"].(map[string]any); ok {
		if st, _ := src["type"].(string); st == "file" {
			r.hidden("uploaded file reference")
		}
	}
}

// walkStrings exposes every string value inside a JSON object as a segment,
// skipping the named keys.
// Keys are visited in sorted order, so that placeholder numbering is the same
// every time the same conversation is sent (principle 4).
func (r *Request) walkStrings(obj map[string]any, id, role string, untrusted bool, skip ...string) {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := obj[k]
		if contains(skip, k) {
			continue
		}
		key := k
		switch t := v.(type) {
		case string:
			if t != "" {
				r.add(id+"."+k, role, untrusted, false, t, func(s string) { obj[key] = s })
			}
		case map[string]any:
			r.walkStrings(t, id+"."+k, role, untrusted)
		case []any:
			for i, e := range t {
				idx := i
				switch et := e.(type) {
				case string:
					if et != "" {
						r.add(fmt.Sprintf("%s.%s.%d", id, k, i), role, untrusted, false, et, func(s string) { t[idx] = s })
					}
				case map[string]any:
					r.walkStrings(et, fmt.Sprintf("%s.%s.%d", id, k, i), role, untrusted)
				}
			}
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
