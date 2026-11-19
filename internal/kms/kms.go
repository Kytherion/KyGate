// Package kms keeps the master key wrapped by a key-management service.
// KyGate derives many keys from its master key on every request
// (cache entries, fingerprints, pseudonyms, the audit ledger), so it needs the
// key itself in memory. What a key-management service adds is that the key
// is never stored in clear: it is stored wrapped (encrypted) by a key that
// never leaves the service, and unwrapped once, at start. Revoking KyGate's
// access to the service stops every new start; the service's own audit log
// records each unwrap.
//
// A Wrapper is chosen by a URI, in the Go Cloud Development Kit's style:
//
//	hashivault://KEY?mount=transit&auth=token|approle|kubernetes   HashiCorp Vault or OpenBao Transit (VAULT_ADDR)
//	awskms://KEY-ID-OR-ARN-OR-alias/NAME?region=eu-west-1          AWS KMS
//	gcpkms://projects/P/locations/L/keyRings/R/cryptoKeys/K        Google Cloud KMS
//	azurekeyvault://NAME.vault.azure.net/keys/KEY[/VERSION]         Azure Key Vault
//
// Every wrap binds the key to the context "kygate/master-key/v1" where the
// service supports it (AWS encryption context, Google additional data), so
// a wrapped key cannot be passed off as another application's.
package kms

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Context binds wrapped master keys to KyGate.
const Context = "kygate/master-key/v1"

// Wrapper wraps and unwraps the master key with a key that stays in the
// service.
type Wrapper interface {
	// URI names the service and key, without credentials.
	URI() string
	Wrap(ctx context.Context, plain []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
}

// Open returns the Wrapper a URI names. Credentials never appear in the URI:
// each service takes them from its usual environment variables, files, or
// workload identity.
func Open(ctx context.Context, uri string) (Wrapper, error) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(uri), "://")
	if !ok {
		return nil, fmt.Errorf("%q is not a key-management URI, such as hashivault://kygate or awskms://alias/kygate", uri)
	}
	path, rawQuery, _ := strings.Cut(rest, "?")
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", uri, err)
	}
	for k := range q {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "token") || strings.Contains(lk, "secret") || strings.Contains(lk, "password") {
			return nil, errors.New("credentials never go in the key URI: use the service's environment variables or files")
		}
	}
	return openService(ctx, scheme, path, q)
}
