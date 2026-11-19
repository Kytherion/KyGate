package detect

// Output inspection (PR-6): what KyGate checks in a model's answer before the
// caller gets it. It runs on the masked answer, before rehydration, so a
// placeholder such as [EMAIL_1] is still visible inside an address.
//
// Four checks, each with its own action (alert | remove | block | allow):
//
//   - OUTPUT_SECRET: a credential written by the model (the fast detectors' secret patterns).
//   - OUTPUT_IMAGE: an image that loads from an unknown site. Clients load images
//     without a click, so an injected image carries data out by itself.
//   - OUTPUT_PROTECTED_URL: an image or link whose address carries a placeholder
//     of this request: once the real value is put back, it would leave for that
//     site. Checked on every site, known or not, and in tool-call arguments.
//   - OUTPUT_LINK: a link to an unknown site.
//
// A site is known when the policy lists it (with its subdomains) or when the
// user's own turns or the system prompt name it. Sites named only in tool
// results do not count: an injection could plant them there.

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Output finding types, as they appear in events and the console.
const (
	OutputSecret       = "OUTPUT_SECRET"
	OutputImage        = "OUTPUT_IMAGE"
	OutputProtectedURL = "OUTPUT_PROTECTED_URL"
	OutputLink         = "OUTPUT_LINK"
)

// OutputRules configures the inspector for one request.
type OutputRules struct {
	// Actions per check: alert, remove, block, allow (or empty: not checked).
	Secrets, Images, ProtectedURLs, Links string
	// Enforce applies remove and block; false (monitor mode) records only.
	Enforce bool
	// Allowed are the policy's known sites; Known the sites this request's
	// user turns and system prompt name. Each covers its subdomains.
	Allowed []string
	Known   map[string]bool
	// HasPlaceholder reports whether text contains a placeholder of this
	// request's value map. Nil when nothing was masked.
	HasPlaceholder func(string) bool
}

// OutputFinding is one problem found in an answer. Offsets are byte offsets
// into the inspected text, end exclusive.
type OutputFinding struct {
	Type        string
	Action      string
	Start, End  int
	Replacement string // what replaces the span when the action is remove
}

// OutputCount is a count per type and action, for events.
type OutputCount struct {
	Type, Action string
	Count        int
	Applied      bool
}

// OutputInspector inspects the text channels of one answer and keeps the
// counts. It is not safe for concurrent use.
type OutputInspector struct {
	r       OutputRules
	counts  map[[2]string]int
	Blocked []string // types that blocked the answer (enforce mode)
	Removed bool     // something was removed: the answer must not be cached
}

// NewOutputInspector returns an inspector, or nil when no check is on.
func NewOutputInspector(r OutputRules) *OutputInspector {
	if !active(r.Secrets) && !active(r.Images) && !active(r.ProtectedURLs) && !active(r.Links) {
		return nil
	}
	return &OutputInspector{r: r, counts: map[[2]string]int{}}
}

func active(a string) bool { return a != "" && a != "allow" }

// Counts returns the findings per type and action, sorted.
func (in *OutputInspector) Counts() []OutputCount {
	if in == nil {
		return nil
	}
	var out []OutputCount
	for k, n := range in.counts {
		out = append(out, OutputCount{Type: k[0], Action: k[1], Count: n, Applied: in.r.Enforce || k[1] == "alert"})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Action < out[j].Action
	})
	return out
}

// Alerted reports whether a finding had the action alert.
func (in *OutputInspector) Alerted() bool {
	if in == nil {
		return false
	}
	for k := range in.counts {
		if k[1] == "alert" {
			return true
		}
	}
	return false
}

// Flagged reports whether the answer was changed or blocked, so it must not be
// cached.
func (in *OutputInspector) Flagged() bool {
	return in != nil && (in.Removed || len(in.Blocked) > 0)
}

func (in *OutputInspector) note(f OutputFinding) {
	in.counts[[2]string{f.Type, f.Action}]++
	if !in.r.Enforce {
		return
	}
	switch f.Action {
	case "remove":
		in.Removed = true
	case "block":
		for _, t := range in.Blocked {
			if t == f.Type {
				return
			}
		}
		in.Blocked = append(in.Blocked, f.Type)
	}
}

// Text inspects a complete piece of answer text and returns it with removals
// applied. args is true for tool-call arguments, where only secrets and
// protected addresses are checked. After a block, the returned text is
// meaningless: the caller refuses the answer.
func (in *OutputInspector) Text(text string, args bool) string {
	if in == nil || text == "" {
		return text
	}
	fs := in.Find(text, args)
	for _, f := range fs {
		in.note(f)
	}
	return in.apply(text, fs, 0, len(text))
}

// apply rewrites text[from:to] with the remove findings that start in it.
func (in *OutputInspector) apply(text string, fs []OutputFinding, from, to int) string {
	if !in.r.Enforce {
		return text[from:to]
	}
	var b strings.Builder
	last := from
	for _, f := range fs {
		if f.Action != "remove" || f.Start < from || f.Start >= to {
			continue
		}
		b.WriteString(text[last:f.Start])
		b.WriteString(f.Replacement)
		last = min(f.End, to)
	}
	b.WriteString(text[last:to])
	return b.String()
}

// ---------------------------------------------------------------- patterns

// linkText is the text between brackets of a Markdown link or image: no
// brackets, except whole placeholders such as [PERSON_1].
const linkText = `((?:[^\[\]\n]|\[[A-Z][A-Z0-9_]*\])*)`

var (
	// ![alt](url "title") and [text](url "title"). The address may hold
	// placeholders, so brackets are allowed in it.
	mdInline = regexp.MustCompile(`(!?)\[` + linkText + `\]\(\s*<?([^\s)<>]+)>?(?:\s+(?:"[^"\n]*"|'[^'\n]*'|\([^)\n]*\)))?\s*\)`)
	// [ref]: url, a reference definition; ![alt][ref] and ![ref] use it.
	mdRefDef = regexp.MustCompile(`(?m)^[ \t]{0,3}\[([^\]\n]+)\]:[ \t]*<?([^\s<>]+)>?.*$`)
	mdRefUse = regexp.MustCompile(`(!?)\[` + linkText + `\](?:\[([^\]\n]*)\])?`)
	htmlImg  = regexp.MustCompile(`(?is)<img\b[^>]*?\bsrc\s*=\s*["']?([^"'\s>]+)[^>]*>`)
	htmlLink = regexp.MustCompile(`(?is)<a\b[^>]*?\bhref\s*=\s*["']?([^"'\s>]+)[^>]*>(.*?)</a\s*>`)
	// A bare address. Brackets only as whole placeholders.
	bareURL = regexp.MustCompile("\\bhttps?://(?:[^\\s<>\"'(){}\\[\\]`]|\\[[A-Z][A-Z0-9_]*_[0-9]+\\])+")
	// Domain names that a user turn or the system prompt mentions.
	domainName    = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b`)
	htmlLinkOpen  = regexp.MustCompile(`(?i)<a\b`)
	htmlLinkClose = regexp.MustCompile(`(?i)</a\s*>`)
	keyEnd        = regexp.MustCompile("-----END (?:[A-Z]+ )*PRIVATE KEY-----")
	placeholder   = regexp.MustCompile(`\[[A-Z][A-Z0-9_]*_[0-9]+\]`)
	refDefStart   = regexp.MustCompile(`^[ \t]{0,3}\[[^\]\n]+\]:`)
)

type construct struct {
	kind       string // image | link
	start, end int
	url, text  string
}

// imageLabels adds the labels that images use by reference (![alt][label],
// ![label]) in text, in lower case.
func imageLabels(text string, into map[string]bool) {
	if !strings.Contains(text, "![") {
		return
	}
	for _, m := range mdRefUse.FindAllStringSubmatchIndex(text, -1) {
		if m[3] <= m[2] {
			continue
		}
		label := text[m[4]:m[5]]
		if m[6] >= 0 && m[7] > m[6] {
			label = text[m[6]:m[7]]
		}
		into[strings.ToLower(strings.TrimSpace(label))] = true
	}
}

// constructs lists the images and links of a text, without overlaps, sorted.
// Each expression runs only when the text holds the literal every match of
// it contains, which gives the same result, faster. seen holds image labels
// used earlier in a stream, beyond text; nil for a whole text.
func constructs(text string, seen map[string]bool, midLine bool) []construct {
	var out []construct
	taken := func(s, e int) bool {
		for _, c := range out {
			if s < c.end && e > c.start {
				return true
			}
		}
		return false
	}
	all := func(re *regexp.Regexp, lit string) [][]int {
		if !strings.Contains(text, lit) {
			return nil
		}
		return re.FindAllStringSubmatchIndex(text, -1)
	}
	for _, m := range all(mdInline, "](") {
		kind := "link"
		if m[3] > m[2] {
			kind = "image"
		}
		out = append(out, construct{kind, m[0], m[1], text[m[6]:m[7]], text[m[4]:m[5]]})
	}
	for _, m := range all(htmlImg, "<") {
		if !taken(m[0], m[1]) {
			out = append(out, construct{"image", m[0], m[1], text[m[2]:m[3]], ""})
		}
	}
	for _, m := range all(htmlLink, "<") {
		if !taken(m[0], m[1]) {
			out = append(out, construct{"link", m[0], m[1], text[m[2]:m[3]], text[m[4]:m[5]]})
		}
	}
	// Reference definitions: an image when an image uses the label.
	if defs := all(mdRefDef, "]:"); len(defs) > 0 {
		images := map[string]bool{}
		imageLabels(text, images)
		for _, m := range defs {
			if taken(m[0], m[1]) || (midLine && m[0] == 0) {
				continue // a window that starts inside a line is no line start
			}
			kind := "link"
			if l := strings.ToLower(strings.TrimSpace(text[m[2]:m[3]])); images[l] || seen[l] {
				kind = "image"
			}
			out = append(out, construct{kind, m[0], m[1], text[m[4]:m[5]], ""})
		}
	}
	for _, m := range all(bareURL, "http") {
		s, e := m[0], m[1]
		for e > s && strings.ContainsRune(".,;:!?", rune(text[e-1])) {
			e--
		}
		if !taken(s, e) {
			out = append(out, construct{"link", s, e, text[s:e], ""})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out
}

// URLHost returns the lower-case host of an absolute or protocol-relative
// address, or "" for a relative one, a data: address, or one that does not parse.
func URLHost(raw string) string {
	raw = strings.Trim(raw, "<>")
	if strings.HasPrefix(raw, "//") {
		raw = "https:" + raw
	}
	// A placeholder in the address does not parse as a URL; it never sits in the host.
	u, err := url.Parse(placeholder.ReplaceAllString(raw, "x"))
	if err != nil {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "ftp", "ws", "wss":
	default:
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

// MentionedHosts lists the domain names a text names, in addresses or alone.
func MentionedHosts(text string, into map[string]bool) {
	for _, m := range domainName.FindAllString(text, -1) {
		into[strings.ToLower(m)] = true
	}
}

func (in *OutputInspector) known(host string) bool {
	// This machine is not an outside site.
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && ip.IsLoopback() {
		return true
	}
	for _, d := range in.r.Allowed {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	for d := range in.r.Known {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// carriesProtected reports whether an address holds a placeholder of this
// request, as written or percent-encoded.
func (in *OutputInspector) carriesProtected(addr string) bool {
	if in.r.HasPlaceholder == nil {
		return false
	}
	for i := 0; i < 3; i++ {
		if in.r.HasPlaceholder(addr) {
			return true
		}
		dec, err := url.PathUnescape(strings.ReplaceAll(addr, "+", " "))
		if err != nil || dec == addr {
			return false
		}
		addr = dec
	}
	return false
}

// Find lists the findings of a text, without overlaps, sorted by offset. Allow
// and unset checks report nothing.
func (in *OutputInspector) Find(text string, args bool) []OutputFinding {
	return in.find(text, args, nil, false)
}

// find is Find on a stream's window: seen holds the image labels the stream
// used before it; midLine says the window starts inside a line.
func (in *OutputInspector) find(text string, args bool, seen map[string]bool, midLine bool) []OutputFinding {
	var out []OutputFinding
	if active(in.r.Secrets) {
		for _, p := range secretPatterns {
			for _, m := range p.find(text) {
				out = append(out, OutputFinding{OutputSecret, in.r.Secrets, m[0], m[1], "[secret removed by KyGate]"})
			}
		}
	}
	for _, c := range constructs(text, seen, midLine) {
		if args && c.kind == "image" {
			c.kind = "link" // in tool-call arguments nothing is rendered
		}
		var f OutputFinding
		switch {
		case active(in.r.ProtectedURLs) && in.carriesProtected(c.url):
			f = OutputFinding{OutputProtectedURL, in.r.ProtectedURLs, c.start, c.end, ""}
			f.Replacement = "[" + c.kind + " removed by KyGate: its address carried protected data]"
		case args:
			continue
		case c.kind == "image" && active(in.r.Images):
			if h := URLHost(c.url); h == "" || in.known(h) {
				continue
			}
			f = OutputFinding{OutputImage, in.r.Images, c.start, c.end, "[image removed by KyGate: it loads from an unknown site]"}
		case c.kind == "link" && active(in.r.Links):
			if h := URLHost(c.url); h == "" || in.known(h) {
				continue
			}
			f = OutputFinding{OutputLink, in.r.Links, c.start, c.end, "[link removed by KyGate: unknown site]"}
		default:
			continue
		}
		if c.kind == "link" && strings.TrimSpace(c.text) != "" && f.Type != OutputProtectedURL {
			f.Replacement = c.text + " " + f.Replacement
		}
		out = append(out, f)
	}
	return resolve(out)
}

var strength = map[string]int{"block": 3, "remove": 2, "alert": 1}

// resolve removes overlaps: of two overlapping findings, the stronger action
// wins, then the earlier and longer one; the winner covers both spans.
func resolve(fs []OutputFinding) []OutputFinding {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Start != fs[j].Start {
			return fs[i].Start < fs[j].Start
		}
		return fs[i].End > fs[j].End
	})
	var out []OutputFinding
	for _, f := range fs {
		if n := len(out); n > 0 && f.Start < out[n-1].End {
			p := &out[n-1]
			end := max(p.End, f.End)
			if strength[f.Action] > strength[p.Action] {
				*p = f
				p.Start = min(p.Start, f.Start)
			}
			p.End = end
			continue
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------- streams

// holdCap is how much text a stream holds back while a link, an image, or a
// token may still be incomplete. Past it, the text goes out; a removal that
// starts in text already sent removes the rest of the construct, which breaks
// the address.
const (
	holdCap    = 2048
	holdKeyCap = 16 << 10 // a private key block
	rescan     = 8 << 10  // the furthest back before the sent mark that is scanned again
	rescanNear = 512      // how far back is scanned again when no construct outgrew its hold-back
)

// OutputStream inspects one text channel of a streamed answer. Push takes the
// next piece and returns the text that can go out now; Flush returns the rest.
//
// Each release scans the unsent text and some text before it. A finding that
// ends after the sent mark started either in the held text, or before it only
// when its construct outgrew its hold-back limit and went out unfinished:
// those starts are kept in forced, and the scan reaches back to them (at most
// rescan). Otherwise it reaches back rescanNear bytes, to the start of that
// line, so that ^ and \b see what they see in the whole text. The answer that
// comes out is the same as the whole answer inspected at once
// (eval/detection/output_test.go, TestStreamMatchesWhole).
type OutputStream struct {
	in        *OutputInspector
	args      bool
	buf       strings.Builder
	raw       string
	sent      int // bytes of raw already released
	skipUntil int // raw offset up to which a removed finding still runs
	forced    int // the earliest start of a construct released unfinished, or -1
	seen      map[seenKey]bool
	images    map[string]bool // labels that images used by reference so far
	replaced  map[int]bool    // starts of findings whose replacement went out
	// A reference definition held until its kind is settled: its start, or
	// -1, and the length of raw when that was decided. Until an image use
	// may have arrived ("![") or the hold runs out, nothing new can go out.
	refHold, refHoldAt int
}

type seenKey struct {
	start int
	typ   string
}

// NewStream returns a stream inspector for one channel. args is true for
// tool-call arguments. A nil inspector returns a stream that passes text through.
func (in *OutputInspector) NewStream(args bool) *OutputStream {
	return &OutputStream{in: in, args: args, forced: -1, refHold: -1, seen: map[seenKey]bool{}, images: map[string]bool{}, replaced: map[int]bool{}}
}

// Push takes the next piece of text.
func (s *OutputStream) Push(piece string) string {
	if s.in == nil {
		return piece
	}
	// A builder grows by doubling; String shares its bytes: no copy of the
	// whole answer per piece.
	s.buf.WriteString(piece)
	s.raw = s.buf.String()
	cut, forced := holdFrom(s.raw, s.sent)
	if forced >= 0 && (s.forced < 0 || forced < s.forced) {
		s.forced = forced
	}
	// A held reference definition keeps everything after it waiting: skip
	// the scan until an image use may have arrived or the hold runs out.
	if s.refHold >= 0 && len(s.raw)-s.refHold <= holdKeyCap && !strings.Contains(s.raw[max(0, s.refHoldAt-1):], "![") {
		return ""
	}
	return s.release(cut, false)
}

// scanBase is where a release starts scanning (see OutputStream), and whether
// that is the start of a line.
func (s *OutputStream) scanBase() (int, bool) {
	lineStart := func(i int) bool { return i == 0 || s.raw[i-1] == '\n' }
	lo := max(0, s.sent-rescan)
	if s.forced >= 0 && s.forced < s.sent-rescanNear {
		b := max(lo, s.forced)
		return b, lineStart(b)
	}
	near := max(lo, s.sent-rescanNear)
	// Back to the start of that line, within the rescan limit.
	if i := strings.LastIndexByte(s.raw[lo:near], '\n'); i >= 0 {
		return lo + i + 1, true
	}
	// A line longer than that: start after a space, so that \b sees what it
	// sees in the whole text; the caller ignores a line start at the base.
	if i := strings.LastIndexAny(s.raw[lo:near], " \t\r"); i >= 0 {
		return lo + i + 1, false
	}
	return lo, lineStart(lo)
}

// Flush releases what is held back, at the end of the channel.
func (s *OutputStream) Flush() string {
	if s.in == nil {
		return ""
	}
	return s.release(len(s.raw), true)
}

// Pending reports whether text is held back.
func (s *OutputStream) Pending() bool { return s.in != nil && s.sent < len(s.raw) }

func (s *OutputStream) release(cut int, final bool) string {
	if cut <= s.sent {
		return ""
	}
	base, atLine := s.scanBase()
	// Images used by reference anywhere earlier make a later definition of
	// their label an image, as in the whole answer. A use is held until it
	// closes, so it is complete in the unsent text when it goes out.
	imageLabels(s.raw[s.sent:], s.images)
	fs := s.in.find(s.raw[base:], s.args, s.images, !atLine)
	for i := range fs {
		fs[i].Start += base
		fs[i].End += base
	}
	if !final {
		// A finding that runs past the cut may still grow: hold it whole.
		for _, f := range fs {
			if f.Start >= s.sent && f.Start < cut && f.End > cut && len(s.raw)-f.Start <= holdCap {
				cut = f.Start
			}
		}
		// A reference definition is a link until an image uses its label,
		// and the use may come later: hold one that could matter (an unknown
		// site, or protected data) until its kind is settled, up to
		// holdKeyCap of text after it.
		s.refHold = -1
		if i := s.pendingRefDef(base, cut, !atLine); i >= 0 {
			cut, s.refHold, s.refHoldAt = i, i, len(s.raw)
		}
		if cut <= s.sent {
			return ""
		}
	}
	var b strings.Builder
	pos := s.sent
	if s.skipUntil > pos {
		pos = min(s.skipUntil, cut)
	}
	for _, f := range fs {
		if f.End <= s.sent || f.Start >= cut {
			continue
		}
		key := seenKey{f.Start, f.Type}
		if !s.seen[key] {
			s.seen[key] = true
			s.in.note(f)
		}
		if s.in.r.Enforce && f.Action == "block" {
			// The answer is refused: nothing of the finding goes out.
			if f.Start > pos {
				b.WriteString(s.raw[pos:f.Start])
			}
			s.sent = len(s.raw)
			return b.String()
		}
		if !s.in.r.Enforce || f.Action != "remove" {
			continue
		}
		if f.Start >= pos {
			b.WriteString(s.raw[pos:f.Start])
			b.WriteString(f.Replacement)
			s.replaced[f.Start] = true
		} else if f.Start < s.sent && pos == s.sent && s.skipUntil < f.End && !s.replaced[f.Start] {
			// It started in text already sent: drop the rest of it. (A finding
			// whose replacement already went out, and that grew since, such as
			// an address longer than the hold-back limit, is only dropped.)
			b.WriteString(" [removed by KyGate]")
		}
		pos = max(pos, min(f.End, cut))
		if f.End > cut {
			s.skipUntil = f.End
		}
	}
	if pos < cut {
		b.WriteString(s.raw[pos:cut])
	}
	s.sent = cut
	return b.String()
}

// pendingRefDef returns the start of the first reference definition between
// the sent mark and cut whose kind could still change what goes out: no image
// has used its label yet, and its address is on an unknown site or carries
// protected data. -1 when there is none, or when it is too far back to hold.
func (s *OutputStream) pendingRefDef(base, cut int, midLine bool) int {
	win := s.raw[base:]
	if !strings.Contains(win, "]:") || (!active(s.in.r.Images) && !active(s.in.r.ProtectedURLs)) {
		return -1
	}
	for _, m := range mdRefDef.FindAllStringSubmatchIndex(win, -1) {
		if midLine && m[0] == 0 {
			continue // not a line start in the whole text
		}
		start := base + m[0]
		if start < s.sent || start >= cut {
			continue
		}
		if len(s.raw)-start > holdKeyCap {
			continue // held long enough: it goes out as a link
		}
		if s.images[strings.ToLower(strings.TrimSpace(win[m[2]:m[3]]))] {
			continue // already an image: the inspection decided it
		}
		addr := win[m[4]:m[5]]
		if h := URLHost(addr); (h != "" && !s.in.known(h)) || (active(s.in.r.ProtectedURLs) && s.in.carriesProtected(addr)) {
			return start
		}
	}
	return -1
}

// holdFrom returns the offset from which text must be held back: the start of
// a token that may still grow (an address, a secret), of an unfinished Markdown
// link or image, of an unclosed HTML tag, or of a private key block. forced is
// the earliest start of such a construct that is too long to hold and goes
// out unfinished, or -1. Only text from the sent mark on is searched: a hold
// never starts before it.
func holdFrom(text string, from int) (cut, forced int) {
	cut, forced = len(text), -1
	consider := func(i, limit int) {
		if i < from || i >= cut {
			return
		}
		if len(text)-i <= limit {
			cut = i
		} else if forced < 0 || i < forced {
			forced = i
		}
	}
	tail := text[from:]
	if n := len(text); n > 0 && !strings.ContainsRune(" \t\r\n", rune(text[n-1])) {
		consider(from+strings.LastIndexAny(tail, " \t\r\n")+1, holdCap)
	}
	win := max(from, len(text)-holdCap)
	if i := openBracket(text, win); i >= 0 {
		consider(i, holdCap)
	} else if i := openBracket(text, from); i >= 0 && i < win {
		consider(i, holdCap) // too long to hold: noted as forced
	}
	if i := strings.LastIndexByte(tail, '<'); i >= 0 && !strings.Contains(tail[i:], ">") {
		consider(from+i, holdCap)
	}
	// An HTML link whose closing tag has not arrived.
	if ms := htmlLinkOpen.FindAllStringIndex(tail, -1); len(ms) > 0 {
		if i := from + ms[len(ms)-1][0]; !htmlLinkClose.MatchString(text[i:]) {
			consider(i, holdCap)
		}
	}
	// An unfinished reference definition line: "[1]: https://..."
	if ls := strings.LastIndexByte(text, '\n') + 1; refDefStart.MatchString(text[ls:]) {
		consider(ls, holdCap)
	}
	if i := strings.LastIndex(tail, "-----BEGIN"); i >= 0 && !keyEnd.MatchString(tail[i:]) {
		consider(from+i, holdKeyCap)
	}
	return cut, forced
}

// openBracket returns the start of the first unfinished Markdown link or image
// in text[win:], or -1.
func openBracket(text string, win int) int {
	var stack []int
	start := func(o int) int {
		if o > 0 && text[o-1] == '!' {
			return o - 1
		}
		return o
	}
	for i := win; i < len(text); i++ {
		switch text[i] {
		case '[':
			stack = append(stack, i)
		case ']':
			if len(stack) == 0 {
				continue
			}
			o := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if len(stack) > 0 {
				o = stack[0] // an outer bracket is still open
			}
			if i+1 == len(text) {
				return start(o) // "(" or "[" may follow
			}
			if text[i+1] == '(' {
				j := strings.IndexByte(text[i+1:], ')')
				if j < 0 {
					return start(o)
				}
				// A placeholder inside the address closes before the parenthesis.
				i += j + 1
			}
		}
	}
	if len(stack) > 0 {
		return start(stack[0])
	}
	return -1
}
