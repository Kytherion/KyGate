package provider

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// FromEnv reads provider connections from environment variables.
//
//	OPENAI_API_KEY, OPENAI_API_KEY_<SUFFIX>       one or several OpenAI keys
//	OPENAI_BASE_URL                               optional, for OpenAI-compatible services
//	ANTHROPIC_API_KEY, ANTHROPIC_API_KEY_<SUFFIX> one or several Anthropic keys
//	ANTHROPIC_BASE_URL                            optional
//	KYGATE_LOCAL_<NAME>=<url>                     a local OpenAI-compatible model server
//	KYGATE_LOCAL_<NAME>_KEY                       optional key for that server
//
// The first names are the ones the providers' own SDKs read. selfAddrs are
// this gateway's own listen addresses: a base URL that points back at KyGate,
// or a key that is a KyGate virtual key, would make KyGate call itself, so
// such values are skipped with a warning.
func FromEnv(environ []string, selfAddrs []string) ([]*Connection, []string) {
	env := map[string]string{}
	for _, kv := range environ {
		if i := strings.IndexByte(kv, '='); i > 0 {
			env[kv[:i]] = kv[i+1:]
		}
	}
	var conns []*Connection
	var warnings []string

	base := func(name string) string {
		v := strings.TrimSpace(env[name])
		if v != "" && pointsAtSelf(v, selfAddrs) {
			warnings = append(warnings, fmt.Sprintf("%s points at KyGate itself; it is ignored here (keep it for your applications)", name))
			return ""
		}
		return v
	}
	openaiBase := base("OPENAI_BASE_URL")
	anthropicBase := base("ANTHROPIC_BASE_URL")

	names := make([]string, 0, len(env))
	for k := range env {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, k := range names {
		v := strings.TrimSpace(env[k])
		if v == "" {
			continue
		}
		var prov, baseURL, conn string
		switch {
		case k == "OPENAI_API_KEY":
			prov, baseURL, conn = OpenAI, openaiBase, "openai"
		case strings.HasPrefix(k, "OPENAI_API_KEY_"):
			prov, baseURL, conn = OpenAI, openaiBase, "openai-"+strings.ToLower(strings.TrimPrefix(k, "OPENAI_API_KEY_"))
		case k == "ANTHROPIC_API_KEY":
			prov, baseURL, conn = Anthropic, anthropicBase, "anthropic"
		case strings.HasPrefix(k, "ANTHROPIC_API_KEY_"):
			prov, baseURL, conn = Anthropic, anthropicBase, "anthropic-"+strings.ToLower(strings.TrimPrefix(k, "ANTHROPIC_API_KEY_"))
		case strings.HasPrefix(k, "KYGATE_LOCAL_") && !strings.HasSuffix(k, "_KEY"):
			name := strings.ToLower(strings.TrimPrefix(k, "KYGATE_LOCAL_"))
			if pointsAtSelf(v, selfAddrs) {
				warnings = append(warnings, fmt.Sprintf("%s points at KyGate itself; it is ignored", k))
				continue
			}
			if _, err := url.ParseRequestURI(v); err != nil {
				warnings = append(warnings, fmt.Sprintf("%s is not a valid URL; it is ignored", k))
				continue
			}
			conns = append(conns, NewConnection("local-"+name, Local, v, strings.TrimSpace(env[k+"_KEY"]), "env"))
			continue
		default:
			continue
		}
		if strings.HasPrefix(v, "kg-") {
			warnings = append(warnings, fmt.Sprintf("%s holds a KyGate virtual key, not a provider key; it is ignored here (keep it for your applications)", k))
			continue
		}
		conns = append(conns, NewConnection(conn, prov, baseURL, v, "env"))
	}
	return conns, warnings
}

// pointsAtSelf reports whether a URL targets one of KyGate's listen addresses.
func pointsAtSelf(raw string, selfAddrs []string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		return false
	}
	for _, a := range selfAddrs {
		i := strings.LastIndexByte(a, ':')
		if i < 0 || a[i+1:] != port {
			continue
		}
		h := a[:i]
		if h == "" || h == "0.0.0.0" || h == "::" || h == "[::]" || h == host ||
			(isLoopback(h) && isLoopback(host)) {
			return true
		}
	}
	return false
}

func isLoopback(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]"
}

// Environ is os.Environ, replaceable in tests.
var Environ = os.Environ
