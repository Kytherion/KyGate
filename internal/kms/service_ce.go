//go:build !enterprise

package kms

import (
	"context"
	"net/url"

	"github.com/Kytherion/KyGate/internal/edition"
)

// openService: the key-management services are part of the Enterprise
// edition.
func openService(context.Context, string, string, url.Values) (Wrapper, error) {
	return nil, edition.Unavailable("keeping the master key in a key-management service")
}
