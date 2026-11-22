package pipeline

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/Kytherion/KyGate/internal/detect"
	"github.com/Kytherion/KyGate/internal/ingress"
	"github.com/Kytherion/KyGate/internal/mask"
)

// sseEvent is one server-sent event.
type sseEvent struct {
	Event string
	Data  []byte
}

// readSSE calls fn for every event in a server-sent event stream. ReadString
// takes a line of any length, so the buffer only sets the size of each read:
// 4 KB, because the reader lives as long as the stream (eval/load measured
// 64 KB as a third of an open stream's memory).
func readSSE(r io.Reader, fn func(sseEvent) error) error {
	br := bufio.NewReaderSize(r, 4<<10)
	var ev sseEvent
	var data bytes.Buffer
	hasData := false
	dispatch := func() error {
		if !hasData && ev.Event == "" {
			return nil
		}
		ev.Data = append([]byte(nil), data.Bytes()...)
		err := fn(ev)
		ev, hasData = sseEvent{}, false
		data.Reset()
		return err
	}
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			switch {
			case line == "":
				if derr := dispatch(); derr != nil {
					return derr
				}
			case strings.HasPrefix(line, ":"):
				// comment, used as keep-alive
			case strings.HasPrefix(line, "event:"):
				ev.Event = strings.TrimSpace(line[6:])
			case strings.HasPrefix(line, "data:"):
				if hasData {
					data.WriteByte('\n')
				}
				d := line[5:]
				d = strings.TrimPrefix(d, " ")
				data.WriteString(d)
				hasData = true
			}
		}
		if err != nil {
			if err == io.EOF {
				return dispatch()
			}
			return err
		}
	}
}

func encodeSSE(family ingress.Family, ev sseEvent) []byte {
	var b bytes.Buffer
	if family == ingress.Anthropic && ev.Event != "" {
		b.WriteString("event: " + ev.Event + "\n")
	}
	b.WriteString("data: ")
	b.Write(ev.Data)
	b.WriteString("\n\n")
	return b.Bytes()
}

func decodeObj(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]any
	err := dec.Decode(&m)
	return m, err
}

// ---------------- OpenAI ----------------

// openaiStream rehydrates an OpenAI chat stream and accumulates the masked
// answer for the cache.
type openaiStream struct {
	vm        *mask.ValueMap
	out       *detect.OutputInspector
	wantUsage bool
	content   map[int]*channel
	refusal   map[int]*channel
	args      map[[2]int]*channel
	acc       openaiAcc
	failed    bool
}

type openaiAcc struct {
	id, model, sysfp string
	created          any
	choices          map[int]*oaChoice
	usage            map[string]any
	done             bool
}

type oaChoice struct {
	content, refusal strings.Builder
	hasContent       bool
	hasRefusal       bool
	tools            map[int]*oaTool
	finish           any
}

type oaTool struct {
	id, typ, name string
	args          strings.Builder
	custom        bool // a custom tool: its input is free text, under "custom"
}

func newOpenAIStream(vm *mask.ValueMap, out *detect.OutputInspector, wantUsage bool) *openaiStream {
	return &openaiStream{vm: vm, out: out, wantUsage: wantUsage, content: map[int]*channel{}, refusal: map[int]*channel{},
		args: map[[2]int]*channel{}, acc: openaiAcc{choices: map[int]*oaChoice{}}}
}

// handle transforms one event. It returns nil to drop the event.
func (s *openaiStream) handle(ev sseEvent) []sseEvent {
	if string(ev.Data) == "[DONE]" {
		s.acc.done = true
		return []sseEvent{ev}
	}
	chunk, err := decodeObj(ev.Data)
	if err != nil {
		return []sseEvent{ev}
	}
	if _, ok := chunk["error"]; ok {
		s.failed = true
		return []sseEvent{ev}
	}
	a := &s.acc
	if v := str(chunk["id"]); v != "" {
		a.id = v
	}
	if v := str(chunk["model"]); v != "" {
		a.model = v
	}
	if v, ok := chunk["created"]; ok {
		a.created = v
	}
	if v := str(chunk["system_fingerprint"]); v != "" {
		a.sysfp = v
	}
	if u := obj(chunk["usage"]); u != nil {
		a.usage = u
	}
	choices := arr(chunk["choices"])
	for _, c := range choices {
		cm := obj(c)
		idx := int(num(cm["index"]))
		ch := a.choices[idx]
		if ch == nil {
			ch = &oaChoice{tools: map[int]*oaTool{}}
			a.choices[idx] = ch
		}
		delta := obj(cm["delta"])
		if delta == nil {
			delta = map[string]any{}
			cm["delta"] = delta
		}
		if t, ok := delta["content"].(string); ok {
			ch.content.WriteString(t)
			ch.hasContent = true
			delta["content"] = s.stream(s.content, idx, s.out).Push(t)
		}
		if t, ok := delta["refusal"].(string); ok {
			ch.refusal.WriteString(t)
			ch.hasRefusal = true
			delta["refusal"] = s.stream(s.refusal, idx, nil).Push(t)
		}
		for _, tc := range arr(delta["tool_calls"]) {
			tcm := obj(tc)
			ti := int(num(tcm["index"]))
			tool := ch.tools[ti]
			if tool == nil {
				tool = &oaTool{}
				ch.tools[ti] = tool
			}
			if v := str(tcm["id"]); v != "" {
				tool.id = v
			}
			if v := str(tcm["type"]); v != "" {
				tool.typ = v
			}
			fn, field, isJSON := obj(tcm["function"]), "arguments", true
			if cu := obj(tcm["custom"]); cu != nil {
				// A custom tool's input is free text, not JSON.
				fn, field, isJSON, tool.custom = cu, "input", false, true
			}
			if fn != nil {
				if v := str(fn["name"]); v != "" {
					tool.name = v
				}
				if t, ok := fn[field].(string); ok {
					tool.args.WriteString(t)
					key := [2]int{idx, ti}
					st := s.args[key]
					if st == nil {
						st = newChannel(s.out, s.vm, true, isJSON)
						s.args[key] = st
					}
					fn[field] = st.Push(t)
				}
			}
		}
		if f := cm["finish_reason"]; f != nil {
			ch.finish = f
			s.flushChoice(idx, delta)
		}
	}
	if len(choices) == 0 && chunk["usage"] != nil && !s.wantUsage {
		// KyGate asked for the usage block; the client did not.
		return nil
	}
	if !s.wantUsage {
		if v, ok := chunk["usage"]; ok && v == nil {
			delete(chunk, "usage")
		}
	}
	return []sseEvent{{Data: ingress.Marshal(chunk)}}
}

func (s *openaiStream) stream(m map[int]*channel, idx int, out *detect.OutputInspector) *channel {
	st := m[idx]
	if st == nil {
		st = newChannel(out, s.vm, false, false)
		m[idx] = st
	}
	return st
}

// flushChoice appends text held back for a choice to its last delta.
func (s *openaiStream) flushChoice(idx int, delta map[string]any) {
	if st := s.content[idx]; st != nil && st.Pending() {
		delta["content"] = str(delta["content"]) + st.Flush()
	}
	if st := s.refusal[idx]; st != nil && st.Pending() {
		delta["refusal"] = str(delta["refusal"]) + st.Flush()
	}
	var keys [][2]int
	for k, st := range s.args {
		if k[0] == idx && st.Pending() {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][1] < keys[j][1] })
	for _, k := range keys {
		calls := arr(delta["tool_calls"])
		held := map[string]any{"index": k[1], "function": map[string]any{"arguments": s.args[k].Flush()}}
		if t := s.acc.choices[idx].tools[k[1]]; t != nil && t.custom {
			held = map[string]any{"index": k[1], "custom": map[string]any{"input": held["function"].(map[string]any)["arguments"]}}
		}
		calls = append(calls, held)
		delta["tool_calls"] = calls
	}
}

// flushAll returns a final chunk for text still held back at the end of a
// stream that never sent a finish reason.
func (s *openaiStream) flushAll() []sseEvent {
	var choices []any
	for idx := range s.acc.choices {
		delta := map[string]any{}
		s.flushChoice(idx, delta)
		if len(delta) > 0 {
			choices = append(choices, map[string]any{"index": idx, "delta": delta, "finish_reason": nil})
		}
	}
	if len(choices) == 0 {
		return nil
	}
	chunk := map[string]any{"id": s.acc.id, "object": "chat.completion.chunk", "created": s.acc.created, "model": s.acc.model, "choices": choices}
	return []sseEvent{{Data: ingress.Marshal(chunk)}}
}

// build returns the masked answer as a non-streamed chat completion.
func (a *openaiAcc) build() map[string]any {
	idxs := make([]int, 0, len(a.choices))
	for i := range a.choices {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	choices := make([]any, 0, len(idxs))
	for _, i := range idxs {
		ch := a.choices[i]
		msg := map[string]any{"role": "assistant", "content": nil}
		if ch.hasContent {
			msg["content"] = ch.content.String()
		}
		if ch.hasRefusal {
			msg["refusal"] = ch.refusal.String()
		}
		if len(ch.tools) > 0 {
			tis := make([]int, 0, len(ch.tools))
			for ti := range ch.tools {
				tis = append(tis, ti)
			}
			sort.Ints(tis)
			var calls []any
			for _, ti := range tis {
				t := ch.tools[ti]
				typ := t.typ
				if typ == "" {
					typ = "function"
				}
				if t.custom {
					calls = append(calls, map[string]any{"id": t.id, "type": typ, "custom": map[string]any{"name": t.name, "input": t.args.String()}})
					continue
				}
				calls = append(calls, map[string]any{"id": t.id, "type": typ, "function": map[string]any{"name": t.name, "arguments": t.args.String()}})
			}
			msg["tool_calls"] = calls
		}
		choices = append(choices, map[string]any{"index": i, "message": msg, "finish_reason": ch.finish, "logprobs": nil})
	}
	out := map[string]any{"id": a.id, "object": "chat.completion", "created": a.created, "model": a.model, "choices": choices}
	if a.sysfp != "" {
		out["system_fingerprint"] = a.sysfp
	}
	if a.usage != nil {
		out["usage"] = a.usage
	}
	return out
}

// synthOpenAI replays a stored chat completion as a stream.
func synthOpenAI(body map[string]any, wantUsage bool) []sseEvent {
	base := func(choices []any) map[string]any {
		return map[string]any{"id": body["id"], "object": "chat.completion.chunk", "created": body["created"], "model": body["model"],
			"system_fingerprint": body["system_fingerprint"], "choices": choices}
	}
	var out []sseEvent
	emit := func(m map[string]any) { out = append(out, sseEvent{Data: ingress.Marshal(m)}) }
	for _, c := range arr(body["choices"]) {
		cm := obj(c)
		idx := cm["index"]
		msg := obj(cm["message"])
		emit(base([]any{map[string]any{"index": idx, "delta": map[string]any{"role": "assistant", "content": ""}, "finish_reason": nil}}))
		if s, ok := msg["content"].(string); ok && s != "" {
			emit(base([]any{map[string]any{"index": idx, "delta": map[string]any{"content": s}, "finish_reason": nil}}))
		}
		if s, ok := msg["refusal"].(string); ok && s != "" {
			emit(base([]any{map[string]any{"index": idx, "delta": map[string]any{"refusal": s}, "finish_reason": nil}}))
		}
		if calls := arr(msg["tool_calls"]); len(calls) > 0 {
			var deltas []any
			for ti, tc := range calls {
				tcm := obj(tc)
				if cu := obj(tcm["custom"]); cu != nil {
					deltas = append(deltas, map[string]any{"index": ti, "id": tcm["id"], "type": tcm["type"],
						"custom": map[string]any{"name": cu["name"], "input": cu["input"]}})
					continue
				}
				fn := obj(tcm["function"])
				deltas = append(deltas, map[string]any{"index": ti, "id": tcm["id"], "type": tcm["type"],
					"function": map[string]any{"name": fn["name"], "arguments": fn["arguments"]}})
			}
			emit(base([]any{map[string]any{"index": idx, "delta": map[string]any{"tool_calls": deltas}, "finish_reason": nil}}))
		}
		emit(base([]any{map[string]any{"index": idx, "delta": map[string]any{}, "finish_reason": cm["finish_reason"]}}))
	}
	if wantUsage && body["usage"] != nil {
		m := base([]any{})
		m["usage"] = body["usage"]
		emit(m)
	}
	out = append(out, sseEvent{Data: []byte("[DONE]")})
	return out
}

// ---------------- Anthropic ----------------

// anthropicStream rehydrates an Anthropic message stream and accumulates the
// masked answer for the cache.
type anthropicStream struct {
	vm     *mask.ValueMap
	out    *detect.OutputInspector
	text   map[int]*channel
	json   map[int]*channel
	acc    anthropicAcc
	failed bool
}

type anthropicAcc struct {
	message map[string]any
	blocks  map[int]*anBlock
	stop    any
	stopSeq any
	usage   map[string]any
	done    bool
}

type anBlock struct {
	start     map[string]any
	text      strings.Builder
	partial   strings.Builder
	thinking  strings.Builder
	signature string
	citations []any
}

func newAnthropicStream(vm *mask.ValueMap, out *detect.OutputInspector) *anthropicStream {
	return &anthropicStream{vm: vm, out: out, text: map[int]*channel{}, json: map[int]*channel{}, acc: anthropicAcc{blocks: map[int]*anBlock{}}}
}

func (s *anthropicStream) handle(ev sseEvent) []sseEvent {
	m, err := decodeObj(ev.Data)
	if err != nil {
		return []sseEvent{ev}
	}
	typ := str(m["type"])
	if ev.Event == "" {
		ev.Event = typ
	}
	a := &s.acc
	switch typ {
	case "message_start":
		msg := obj(m["message"])
		if msg != nil {
			a.message = copyMap(msg)
			if u := obj(msg["usage"]); u != nil {
				a.usage = copyMap(u)
			}
		}
	case "content_block_start":
		idx := int(num(m["index"]))
		cb := obj(m["content_block"])
		b := &anBlock{start: copyMap(cb)}
		a.blocks[idx] = b
		if str(cb["type"]) == "text" {
			if t := str(cb["text"]); t != "" {
				b.text.WriteString(t)
				cb["text"] = s.stream(s.text, idx, false).Push(t)
			}
		}
	case "content_block_delta":
		idx := int(num(m["index"]))
		b := a.blocks[idx]
		if b == nil {
			b = &anBlock{start: map[string]any{"type": "text", "text": ""}}
			a.blocks[idx] = b
		}
		d := obj(m["delta"])
		switch str(d["type"]) {
		case "text_delta":
			t := str(d["text"])
			b.text.WriteString(t)
			d["text"] = s.stream(s.text, idx, false).Push(t)
		case "input_json_delta":
			t := str(d["partial_json"])
			b.partial.WriteString(t)
			d["partial_json"] = s.stream(s.json, idx, true).Push(t)
		case "thinking_delta":
			b.thinking.WriteString(str(d["thinking"]))
		case "signature_delta":
			b.signature = str(d["signature"])
		case "citations_delta":
			if c, ok := d["citation"]; ok {
				b.citations = append(b.citations, c)
			}
		}
	case "content_block_stop":
		idx := int(num(m["index"]))
		var out []sseEvent
		if st := s.text[idx]; st != nil && st.Pending() {
			out = append(out, deltaEvent(idx, map[string]any{"type": "text_delta", "text": st.Flush()}))
		}
		if st := s.json[idx]; st != nil && st.Pending() {
			out = append(out, deltaEvent(idx, map[string]any{"type": "input_json_delta", "partial_json": st.Flush()}))
		}
		return append(out, ev)
	case "message_delta":
		d := obj(m["delta"])
		if d != nil {
			a.stop, a.stopSeq = d["stop_reason"], d["stop_sequence"]
		}
		if u := obj(m["usage"]); u != nil {
			if a.usage == nil {
				a.usage = map[string]any{}
			}
			for k, v := range u {
				if v != nil {
					a.usage[k] = v
				}
			}
		}
		return []sseEvent{ev}
	case "message_stop":
		a.done = true
		return []sseEvent{ev}
	case "error":
		s.failed = true
		return []sseEvent{ev}
	default:
		return []sseEvent{ev}
	}
	return []sseEvent{{Event: ev.Event, Data: ingress.Marshal(m)}}
}

// flushAll returns deltas for text still held back, at the end of a stream
// that stopped before its blocks did.
func (s *anthropicStream) flushAll() []sseEvent {
	idxs := make([]int, 0, len(s.acc.blocks))
	for i := range s.acc.blocks {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	var out []sseEvent
	for _, idx := range idxs {
		if st := s.text[idx]; st != nil && st.Pending() {
			out = append(out, deltaEvent(idx, map[string]any{"type": "text_delta", "text": st.Flush()}))
		}
		if st := s.json[idx]; st != nil && st.Pending() {
			out = append(out, deltaEvent(idx, map[string]any{"type": "input_json_delta", "partial_json": st.Flush()}))
		}
	}
	return out
}

func (s *anthropicStream) stream(m map[int]*channel, idx int, isJSON bool) *channel {
	st := m[idx]
	if st == nil {
		st = newChannel(s.out, s.vm, isJSON, isJSON)
		m[idx] = st
	}
	return st
}

func deltaEvent(idx int, delta map[string]any) sseEvent {
	return sseEvent{Event: "content_block_delta", Data: ingress.Marshal(map[string]any{"type": "content_block_delta", "index": idx, "delta": delta})}
}

func copyMap(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	out, _ := decodeObj(b)
	return out
}

// build returns the masked answer as a non-streamed message.
func (a *anthropicAcc) build() map[string]any {
	msg := a.message
	if msg == nil {
		msg = map[string]any{"type": "message", "role": "assistant"}
	}
	msg = copyMap(msg)
	idxs := make([]int, 0, len(a.blocks))
	for i := range a.blocks {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	content := make([]any, 0, len(idxs))
	for _, i := range idxs {
		b := a.blocks[i]
		blk := copyMap(b.start)
		switch str(blk["type"]) {
		case "text":
			blk["text"] = b.text.String()
			if len(b.citations) > 0 {
				blk["citations"] = b.citations
			}
		case "tool_use", "server_tool_use", "mcp_tool_use":
			if p := strings.TrimSpace(b.partial.String()); p != "" {
				if in, err := decodeObj([]byte(p)); err == nil {
					blk["input"] = in
				}
			}
		case "thinking":
			blk["thinking"] = b.thinking.String()
			if b.signature != "" {
				blk["signature"] = b.signature
			}
		}
		content = append(content, blk)
	}
	msg["content"] = content
	msg["stop_reason"] = a.stop
	msg["stop_sequence"] = a.stopSeq
	if a.usage != nil {
		msg["usage"] = a.usage
	}
	return msg
}

// synthAnthropic replays a stored message as a stream.
func synthAnthropic(body map[string]any) []sseEvent {
	var out []sseEvent
	emit := func(event string, m map[string]any) {
		out = append(out, sseEvent{Event: event, Data: ingress.Marshal(m)})
	}
	start := copyMap(body)
	start["content"] = []any{}
	start["stop_reason"] = nil
	start["stop_sequence"] = nil
	usage := obj(body["usage"])
	if usage != nil {
		su := copyMap(usage)
		su["output_tokens"] = 1
		start["usage"] = su
	}
	emit("message_start", map[string]any{"type": "message_start", "message": start})
	for i, b := range arr(body["content"]) {
		bm := obj(b)
		typ := str(bm["type"])
		switch typ {
		case "text":
			cb := map[string]any{"type": "text", "text": ""}
			emit("content_block_start", map[string]any{"type": "content_block_start", "index": i, "content_block": cb})
			emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": i, "delta": map[string]any{"type": "text_delta", "text": bm["text"]}})
			for _, c := range arr(bm["citations"]) {
				emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": i, "delta": map[string]any{"type": "citations_delta", "citation": c}})
			}
		case "tool_use", "server_tool_use", "mcp_tool_use":
			cb := copyMap(bm)
			input := cb["input"]
			cb["input"] = map[string]any{}
			emit("content_block_start", map[string]any{"type": "content_block_start", "index": i, "content_block": cb})
			emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": i, "delta": map[string]any{"type": "input_json_delta", "partial_json": string(ingress.Marshal(input))}})
		case "thinking":
			emit("content_block_start", map[string]any{"type": "content_block_start", "index": i, "content_block": map[string]any{"type": "thinking", "thinking": ""}})
			if t := str(bm["thinking"]); t != "" {
				emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": i, "delta": map[string]any{"type": "thinking_delta", "thinking": t}})
			}
			if sig := str(bm["signature"]); sig != "" {
				emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": i, "delta": map[string]any{"type": "signature_delta", "signature": sig}})
			}
		default:
			emit("content_block_start", map[string]any{"type": "content_block_start", "index": i, "content_block": bm})
		}
		emit("content_block_stop", map[string]any{"type": "content_block_stop", "index": i})
	}
	md := map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": body["stop_reason"], "stop_sequence": body["stop_sequence"]}}
	if usage != nil {
		md["usage"] = map[string]any{"output_tokens": usage["output_tokens"]}
	}
	emit("message_delta", md)
	emit("message_stop", map[string]any{"type": "message_stop"})
	return out
}
