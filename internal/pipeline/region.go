package pipeline

// Region pinning (GV-4). A policy that names data.regions sends
// requests only to provider connections in those regions. A connection with
// no region is never used then: an unknown place is not an allowed one. A
// request with no connection left is refused, before the cache and before
// any call (security fails closed, invariant 2). Monitor mode changes
// nothing: it records the request that would have been refused.

import (
	"fmt"
	"strings"

	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/provider"
	"github.com/Kytherion/KyGate/internal/router"
)

// pinRegions narrows a target's connections to the policy's regions. It
// returns the refusal to send, or "" when the request may go on.
func pinRegions(pol *policy.Policy, t router.Target) (router.Target, string, bool) {
	if len(pol.Data.Regions) == 0 || len(t.Pool) == 0 {
		return t, "", false
	}
	var keep []*provider.Connection
	for _, c := range t.Pool {
		if pol.AllowsRegion(c.Region) {
			keep = append(keep, c)
		}
	}
	if len(keep) == len(t.Pool) {
		return t, "", false
	}
	if pol.Mode == policy.Monitor {
		// Change nothing; flag what enforcement would do.
		return t, "", len(keep) == 0
	}
	if len(keep) == 0 {
		return t, fmt.Sprintf("KyGate refused this request: the policy sends requests only to provider connections in %s (data.regions), and no %s connection is in one. Give a connection its region with %s or 'kygate provider region'.",
			regionList(pol.Data.Regions), t.Provider, "KYGATE_REGION_<NAME>"), false
	}
	t.Pool = keep
	return t, "", false
}

// embeddingsAllowed reports whether the semantic cache may send a message to
// its embeddings connection: only within the policy's regions, in enforce mode.
func embeddingsAllowed(pol *policy.Policy, c *provider.Connection) bool {
	return c == nil || pol.Mode == policy.Monitor || pol.AllowsRegion(c.Region)
}

func regionList(rs []string) string {
	if len(rs) == 1 && rs[0] == policy.NoRegion {
		return "no region (the policy levels name regions with nothing in common)"
	}
	if len(rs) == 1 {
		return "region " + rs[0]
	}
	return "regions " + strings.Join(rs, ", ")
}
