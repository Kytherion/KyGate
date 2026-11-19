package pipeline

import (
	"strings"
	"testing"
)

// An event far larger than readSSE's buffer arrives whole: a long tool-call
// argument or a final event with a big body must not be cut.
func TestReadSSELongEvent(t *testing.T) {
	big := strings.Repeat("x", 200<<10)
	in := "event: first\ndata: short\n\n" + "data: " + big + "\ndata: second line\n\n" + "data: last\n\n"
	var got []sseEvent
	if err := readSSE(strings.NewReader(in), func(ev sseEvent) error { got = append(got, ev); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%d events, want 3", len(got))
	}
	if got[0].Event != "first" || string(got[0].Data) != "short" {
		t.Errorf("first event %q %q", got[0].Event, got[0].Data)
	}
	if string(got[1].Data) != big+"\nsecond line" {
		t.Errorf("long event: %d bytes, want %d", len(got[1].Data), len(big)+len("\nsecond line"))
	}
	if string(got[2].Data) != "last" {
		t.Errorf("last event %q", got[2].Data)
	}
}
