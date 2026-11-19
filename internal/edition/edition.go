// Package edition says which edition this binary is: Community (the public
// source) or Enterprise (built with -tags enterprise and the enterprise
// sources). The Community edition answers a request for an Enterprise
// capability with Unavailable, never with a silent no-op.
package edition

import "fmt"

// Contact is where a company learns about the Enterprise edition.
const Contact = "see 'For companies' in KyGate's README"

// Unavailable is the error a Community build returns for an Enterprise
// capability.
func Unavailable(feature string) error {
	return fmt.Errorf("%s is part of KyGate Enterprise; this is the Community edition (%s)", feature, Contact)
}
