package main

import (
	"context"
	"fmt"

	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

// usersLine says how requests name the person behind them (AC-3).
func usersLine(ctx context.Context, cs store.ConfigStore, p *policy.Policy) string {
	keys, _ := cs.ListKeys(ctx)
	secrets, required := 0, 0
	for _, k := range keys {
		if k.RevokedAt != nil {
			continue
		}
		if k.HasSecret {
			secrets++
		}
		if k.RequireUser {
			required++
		}
	}
	idp := "no identity provider (identity.user_tokens in the policy)"
	if u := p.Identity.UserTokens; u.Issuer != "" {
		idp = "identity provider " + u.Issuer + ", claim " + u.UserClaim
	}
	return fmt.Sprintf("%d keys sign their own (kygate key user-secret), %d require one; %s", secrets, required, idp)
}
