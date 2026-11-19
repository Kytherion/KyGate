package control

// End-user identity (AC-3): the signing secrets of keys for
// application user tokens, sealed under the master key, and the pseudonyms
// that stand for people in events, counters, and reports.

import (
	"context"
	"fmt"

	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/store"
)

func userSecretKey(master []byte, org string) []byte {
	return store.DeriveKey(master, "user-secret", org)
}

// CreateUserSecret makes a new signing secret for a key's user tokens, stores
// it sealed, and returns it, to be shown once. A key's earlier secret stops
// working at once.
func CreateUserSecret(ctx context.Context, cs store.ConfigStore, master []byte, org, keyName string) (string, store.VirtualKey, error) {
	k, err := activeKey(ctx, cs, keyName)
	if err != nil {
		return "", k, err
	}
	secret := identity.NewUserSecret()
	sealed, err := store.Seal(userSecretKey(master, org), []byte(secret), []byte("user-secret/"+k.ID))
	if err != nil {
		return "", k, err
	}
	if _, err := cs.SetKeyUserSecret(ctx, k.ID, sealed); err != nil {
		return "", k, err
	}
	return secret, k, nil
}

// UserSecretOpener opens the sealed secrets of keys, for identity.Resolver.
func UserSecretOpener(master []byte, org string) func(sealed []byte, keyID string) ([]byte, error) {
	k := userSecretKey(master, org)
	return func(sealed []byte, keyID string) ([]byte, error) {
		return store.Open(k, sealed, []byte("user-secret/"+keyID))
	}
}

// UserSecretOf returns a key's signing secret, for 'kygate key user-token'.
func UserSecretOf(ctx context.Context, cs store.ConfigStore, master []byte, org, keyName string) (string, error) {
	k, err := activeKey(ctx, cs, keyName)
	if err != nil {
		return "", err
	}
	if len(k.UserSecret) == 0 {
		return "", fmt.Errorf("key %q has no signing secret: create one with 'kygate key user-secret %s'", k.Name, k.Name)
	}
	s, err := UserSecretOpener(master, org)(k.UserSecret, k.ID)
	if err != nil {
		return "", fmt.Errorf("the signing secret of key %q cannot be opened with this master key", k.Name)
	}
	return string(s), nil
}

// Pseudonym is how events and reports name the person with this ID.
func Pseudonym(master []byte, org, id string) string {
	return identity.Pseudonym(store.DeriveKey(master, "user", org), identity.NormalizeUserID(id))
}

func activeKey(ctx context.Context, cs store.ConfigStore, name string) (store.VirtualKey, error) {
	keys, err := cs.ListKeys(ctx)
	if err != nil {
		return store.VirtualKey{}, err
	}
	for _, k := range keys {
		if (k.Name == name || k.ID == name) && k.RevokedAt == nil {
			return k, nil
		}
	}
	return store.VirtualKey{}, fmt.Errorf("no active key named %q", name)
}
