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
	// ID is the position, for example "messages.3.content.0". A key that holds
	// a dot or a tilde is escaped ("~1", "~0"), so two positions never share
	// an ID.
	ID        string
	Role      string
	Untrusted bool // user turns and tool results
	Text      string
	// JSON is true when Text is itself JSON text, such as tool-call arguments.
	JSON bool
	// Fixed is true when the text cannot take a placeholder, such as a
	// participant name the provider checks against a pattern: a value the
	// policy masks there refuses the request.
	Fixed bool
	set   func(string)
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

// Fields that carry no text: numbers, flags, enums, and references to
// settings. Every other field of a request or a message is scanned, at every
// depth, so that a field KyGate does not know cannot carry text past the
// detectors (goal G4).
var (
	openAISettings = setOf("model", "messages", "stream", "stream_options", "n", "temperature", "top_p", "max_tokens",
		"max_completion_tokens", "seed", "logprobs", "top_logprobs", "logit_bias", "presence_penalty", "frequency_penalty",
		"parallel_tool_calls", "tool_choice", "function_call", "service_tier", "store", "reasoning_effort", "verbosity",
		"modalities", "audio")
	openAIMessageFields = setOf("role", "content", "refusal", "tool_calls", "function_call", "name", "tool_call_id", "audio")
	anthropicSettings   = setOf("model", "messages", "system", "max_tokens", "stream", "temperature", "top_p", "top_k",
		"tool_choice", "thinking", "service_tier")
	anthropicMessageFields = setOf("role", "content")
	// structural keys name, type, or constrain something; their string and
	// list values are never free text (a JSON schema's "type", "format",
	// "pattern", and "required"; a tool's "name"). A key of this name whose
	// value is an object, such as a schema property called "name", is
	// scanned.
	structural = setOf("type", "name", "id", "role", "format", "pattern", "$ref", "$schema", "$id", "$anchor",
		"required", "strict", "tool_use_id", "tool_call_id", "media_type", "cache_control")
)

func setOf(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// idKey escapes a JSON key for a segment ID, the way a JSON pointer does, so
// {"a":{"b":..}} and {"a.b":..} get different IDs.
func idKey(k string) string {
	if !strings.ContainsAny(k, ".~") {
		return k
	}
	return strings.NewReplacer("~", "~0", ".", "~1").Replace(k)
}

// rest scans the fields of obj that known lists the fields of, or that skip
// names, as text: every string, at every depth, except the values of
// structural keys. Keys are visited in sorted order, for stable placeholder
// numbering (principle 4).
func (r *Request) rest(obj map[string]any, id string, known map[string]bool, role string, untrusted bool, skip ...string) {
	extra := setOf(skip...)
	for _, k := range sortedKeys(obj) {
		if known[k] {
			continue
		}
		kid := idKey(k)
		if id != "" {
			kid = id + "." + kid
		}
		r.walkValue(obj, k, kid, role, untrusted, extra)
	}
}

// walkValue scans obj[k] as text, skipping structural values.
func (r *Request) walkValue(obj map[string]any, k, id, role string, untrusted bool, extra map[string]bool) {
	if extra[k] {
		return
	}
	switch t := obj[k].(type) {
	case string:
		if t != "" && !structural[k] {
			r.add(id, role, untrusted, false, t, func(s string) { obj[k] = s })
		}
	case []any:
		if !structural[k] {
			r.walkText(t, id, role, untrusted, extra)
		}
	case map[string]any:
		for _, kk := range sortedKeys(t) {
			r.walkValue(t, kk, id+"."+idKey(kk), role, untrusted, extra)
		}
	}
}

func (r *Request) walkText(list []any, id, role string, untrusted bool, extra map[string]bool) {
	for i, e := range list {
		idx, eid := i, id+"."+strconv.Itoa(i)
		switch t := e.(type) {
		case string:
			if t != "" {
				r.add(eid, role, untrusted, false, t, func(s string) { list[idx] = s })
			}
		case []any:
			r.walkText(t, eid, role, untrusted, extra)
		case map[string]any:
			for _, kk := range sortedKeys(t) {
				r.walkValue(t, kk, eid+"."+idKey(kk), role, untrusted, extra)
			}
		}
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
				if fn, _ := cm["function"].(map[string]any); fn != nil {
					if args, ok := fn["arguments"].(string); ok {
						r.add(fmt.Sprintf("%s.tool_calls.%d.arguments", base, j), RoleAssistant, false, true, args, func(v string) { fn["arguments"] = v })
					}
				}
				// A custom tool's input is free text, not JSON.
				if cu, _ := cm["custom"].(map[string]any); cu != nil {
					if in, ok := cu["input"].(string); ok && in != "" {
						r.add(fmt.Sprintf("%s.tool_calls.%d.input", base, j), RoleAssistant, false, false, in, func(v string) { cu["input"] = v })
					}
				}
			}
		}
		// The conversation's identity is its content, as before the fields below were scanned.
		content := r.Segments[before:]
		// The deprecated form of a tool call carries its arguments the same way.
		if fc, ok := msg["function_call"].(map[string]any); ok {
			if args, ok := fc["arguments"].(string); ok {
				r.add(base+".function_call.arguments", RoleAssistant, false, true, args, func(v string) { fc["arguments"] = v })
			}
		}
		// A participant's name must match ^[a-zA-Z0-9_-]+$, so it cannot take
		// a placeholder: it is scanned, and a value to mask in it refuses.
		if n, ok := msg["name"].(string); ok && n != "" {
			r.add(base+".name", segRole, untrusted, false, n, func(v string) { msg["name"] = v })
			r.Segments[len(r.Segments)-1].Fixed = true
		}
		r.rest(msg, base, openAIMessageFields, segRole, untrusted)
		if (role == "system" || role == "developer" || (role == "user" && !firstUser)) && len(content) > 0 {
			for _, s := range content {
				conv.WriteString("\x00" + s.Text)
			}
			if role == "user" {
				firstUser = true
			}
		}
	}
	// Every other field that reaches the model: tool and response-format
	// definitions, a predicted output, stop sequences, identifiers such as
	// user and metadata, and fields KyGate does not know. After the messages,
	// so their placeholder numbering does not depend on them.
	r.rest(r.Body, "", openAISettings, RoleSystem, false)
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
	// Identifiers such as user, and fields KyGate does not know.
	r.rest(r.Body, "", setOf("model", "input", "encoding_format", "dimensions"), RoleSystem, false)
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
		r.rest(msg, "messages."+strconv.Itoa(i), anthropicMessageFields, segRole, untrusted)
	}
	// Every other field that reaches the model: tool definitions, stop
	// sequences, metadata, and fields KyGate does not know. After the
	// messages, so their placeholder numbering does not depend on them. A
	// remote MCP server's own credential goes to the provider on purpose, and
	// is not scanned.
	known := setOf("mcp_servers")
	for k := range anthropicSettings {
		known[k] = true
	}
	r.rest(r.Body, "", known, RoleSystem, false)
	if _, ok := r.Body["mcp_servers"]; ok {
		r.walkValue(r.Body, "mcp_servers", "mcp_servers", RoleSystem, false, setOf("authorization_token"))
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
// at every depth, lists inside lists included, skipping the named keys of the
// object itself. Keys are visited in sorted order, so that placeholder
// numbering is the same every time the same conversation is sent (principle 4).
func (r *Request) walkStrings(obj map[string]any, id, role string, untrusted bool, skip ...string) {
	for _, k := range sortedKeys(obj) {
		if contains(skip, k) {
			continue
		}
		key, kid := k, id+"."+idKey(k)
		switch t := obj[k].(type) {
		case string:
			if t != "" {
				r.add(kid, role, untrusted, false, t, func(s string) { obj[key] = s })
			}
		case map[string]any:
			r.walkStrings(t, kid, role, untrusted)
		case []any:
			r.walkList(t, kid, role, untrusted)
		}
	}
}

func (r *Request) walkList(list []any, id, role string, untrusted bool) {
	for i, e := range list {
		idx, eid := i, id+"."+strconv.Itoa(i)
		switch t := e.(type) {
		case string:
			if t != "" {
				r.add(eid, role, untrusted, false, t, func(s string) { list[idx] = s })
			}
		case map[string]any:
			r.walkStrings(t, eid, role, untrusted)
		case []any:
			r.walkList(t, eid, role, untrusted)
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
