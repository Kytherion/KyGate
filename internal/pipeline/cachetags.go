package pipeline

// Cache labels (GV-4). Every stored answer is labelled with the
// key that stored it, and with the tags the application names in
// X-KyGate-Cache-Tags, so that a purge can remove them later. Labels are
// keyed hashes (cache.Label); tags never reach a cache store in clear. Tags
// do not change the fingerprint: an entry keeps the tags of the request that
// stored it.

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Kytherion/KyGate/internal/cache"
)

const (
	tagsHeader = "X-KyGate-Cache-Tags"
	maxTags    = 8
)

// parseCacheTags reads the comma-separated tags of a request.
func parseCacheTags(h http.Header) ([]string, error) {
	var tags []string
	for _, v := range h.Values(tagsHeader) {
		for _, t := range strings.Split(v, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if !cache.ValidTag(t) {
				return nil, fmt.Errorf("%s: %q is not a tag (1 to 64 letters, digits, and . _ : / -)", tagsHeader, t)
			}
			tags = append(tags, t)
		}
	}
	if len(tags) > maxTags {
		return nil, fmt.Errorf("%s: at most %d tags", tagsHeader, maxTags)
	}
	return tags, nil
}

// cacheLabels are the labels of an answer this request stores.
func (g *Gateway) cacheLabels(sc *serveCtx) []string {
	k := g.orgKey("cache-label", sc.caller.OrgID)
	labels := []string{cache.Label(k, cache.LabelKey, sc.caller.KeyID)}
	for _, t := range sc.tags {
		labels = append(labels, cache.Label(k, cache.LabelTag, t))
	}
	return labels
}
