// Package anthropic is the adapter for the Anthropic API family: header
// handling for messages, token counting, and the model list.
package anthropic

import "net/http"

// DefaultVersion is sent when the client does not name an API version.
const DefaultVersion = "2023-06-01"

// ForwardHeaders returns the client headers to send upstream. The API version
// and beta flags are the client's choice and pass through unchanged.
// Authentication is never forwarded: the provider key comes from the connection.
func ForwardHeaders(in http.Header) http.Header {
	out := http.Header{}
	v := in.Get("Anthropic-Version")
	if v == "" {
		v = DefaultVersion
	}
	out.Set("Anthropic-Version", v)
	for _, b := range in.Values("Anthropic-Beta") {
		out.Add("Anthropic-Beta", b)
	}
	if a := in.Get("Accept"); a != "" {
		out.Set("Accept", a)
	}
	return out
}

// ResponseHeaders are the upstream headers worth passing back to the client.
var ResponseHeaders = []string{"Request-Id", "Retry-After",
	"Anthropic-Ratelimit-Requests-Limit", "Anthropic-Ratelimit-Requests-Remaining",
	"Anthropic-Ratelimit-Tokens-Limit", "Anthropic-Ratelimit-Tokens-Remaining",
	"Anthropic-Ratelimit-Input-Tokens-Remaining", "Anthropic-Ratelimit-Output-Tokens-Remaining"}
