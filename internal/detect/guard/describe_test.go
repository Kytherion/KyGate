package guard

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The Guard's own failures are described without their details, which could
// quote the text it inspected; the link's errors and its refusals are kept.
func TestDescribe(t *testing.T) {
	failed := Describe(status.Error(codes.Unknown, "Exception calling application: cannot read 'Alice Martin'"))
	if strings.Contains(failed, "Alice") || !strings.Contains(failed, "Unknown") {
		t.Fatalf("%q", failed)
	}
	if got := Describe(status.Error(codes.Unavailable, "connection refused")); !strings.Contains(got, "connection refused") {
		t.Fatalf("%q", got)
	}
	if got := Describe(status.Error(codes.InvalidArgument, "segment 3 is larger than 1048576 bytes")); !strings.Contains(got, "segment 3") {
		t.Fatalf("%q", got)
	}
}
