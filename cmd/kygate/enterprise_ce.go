//go:build !enterprise

package main

import "github.com/Kytherion/KyGate/internal/edition"

// The Enterprise commands, as the Community edition answers them.

func userCmd([]string) error { return edition.Unavailable("'kygate user' (console users and roles)") }
func ssoCmd([]string) error  { return edition.Unavailable("'kygate sso' (single sign-on)") }
func scimCmd([]string) error { return edition.Unavailable("'kygate scim' (SCIM provisioning)") }
func auditCmd([]string) error {
	return edition.Unavailable("'kygate audit' (the tamper-evident audit ledger)")
}
func masterKeyCmd([]string) error {
	return edition.Unavailable("'kygate master-key' (the master key in a key-management service)")
}
