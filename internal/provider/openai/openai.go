// Package openai is the adapter for the OpenAI API family: header handling
// for chat completions, embeddings, and the model list.
package openai

import "net/http"

// forwarded are the client headers passed upstream unchanged.
// OpenAI-Organization and OpenAI-Project are not among them: they choose what
// the operator's key bills, so they belong to the connection
// (KYGATE_OPENAI_ORG_<NAME>, KYGATE_OPENAI_PROJECT_<NAME>).
var forwarded = []string{"OpenAI-Beta"}

// ForwardHeaders returns the client headers to send upstream. Authentication
// is never forwarded: the provider key comes from the connection.
func ForwardHeaders(in http.Header) http.Header {
	out := http.Header{}
	out.Set("Accept", in.Get("Accept"))
	for _, h := range forwarded {
		if v := in.Get(h); v != "" {
			out.Set(h, v)
		}
	}
	if out.Get("Accept") == "" {
		out.Del("Accept")
	}
	return out
}

// ResponseHeaders are the upstream headers worth passing back to the client.
var ResponseHeaders = []string{"X-Request-Id", "Openai-Processing-Ms", "Retry-After",
	"X-Ratelimit-Limit-Requests", "X-Ratelimit-Remaining-Requests",
	"X-Ratelimit-Limit-Tokens", "X-Ratelimit-Remaining-Tokens"}
