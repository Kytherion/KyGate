package main

// kygate key user-secret | require-user | user-token (AC-3).

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Kytherion/KyGate/internal/control"
	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/store"
)

func keyUserCmd(ctx context.Context, c common, db store.Database, org, cmd, name string, remove, off bool, user string, ttl time.Duration) error {
	switch cmd {
	case "require-user":
		ok, err := db.SetKeyRequireUser(ctx, name, !off)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no active key named or with ID %q", name)
		}
		state := map[bool]string{true: "on", false: "off"}[!off]
		recordCLI(ctx, db, "key.require_user", name, state)
		if off {
			fmt.Printf("Key %q accepts requests that name no person again. A running KyGate applies it within a few seconds.\n", name)
		} else {
			fmt.Printf("Key %q now refuses requests without a valid %s token (401). A running KyGate applies it within a few seconds.\n", name, identity.UserHeader)
		}
		return nil
	case "user-secret":
		if remove {
			ok, err := db.SetKeyUserSecret(ctx, name, nil)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("no active key named or with ID %q", name)
			}
			recordCLI(ctx, db, "key.user_secret", name, "removed")
			fmt.Println("Removed. Application user tokens for this key are refused within a few seconds.")
			return nil
		}
	}
	master, _, _, err := control.LoadMasterKey(c.dataDir, false)
	if err != nil {
		return err
	}
	if err := control.VerifyMasterKey(ctx, db, master, org); err != nil {
		return err
	}
	if cmd == "user-secret" {
		secret, k, err := control.CreateUserSecret(ctx, db, master, org, name)
		if err != nil {
			return err
		}
		recordCLI(ctx, db, "key.user_secret", k.Name, "created; shown once")
		fmt.Printf("Signing secret for user tokens on key %q. It is shown once, and replaces any earlier one:\n\n  %s\n\n", k.Name, secret)
		fmt.Printf("The application signs a JWT with HS256 under this secret, with sub (the person) and exp (at most %s ahead),\n", identity.MaxAppTokenLife)
		fmt.Printf("and sends it in the %s header. A running KyGate accepts it within a few seconds.\n", identity.UserHeader)
		return nil
	}
	// user-token
	if user == "" {
		return errors.New("usage: kygate key user-token NAME --user ID [--ttl 1h]")
	}
	if ttl <= 0 || ttl > identity.MaxAppTokenLife {
		return fmt.Errorf("--ttl must be between 1s and %s", identity.MaxAppTokenLife)
	}
	secret, err := control.UserSecretOf(ctx, db, master, org, name)
	if err != nil {
		return err
	}
	tok, err := identity.SignAppToken(secret, user, ttl, time.Now())
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}
