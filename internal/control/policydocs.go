package control

// Policy documents in the database: with PostgreSQL, policies
// live in the configuration store, so that every gateway reads the same
// version without a shared volume. Gateways reload them within seconds of a
// change, as they do keys.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

// DBDocs implements policy.Docs over the configuration store.
type DBDocs struct {
	DB store.Database
	// BasePath stands for policy.yaml: relative paths in a policy, such as a
	// dictionary file, resolve against its folder, on each process's disk.
	BasePath string
}

var _ policy.Docs = DBDocs{}

const docsTimeout = 10 * time.Second

func (d DBDocs) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), docsTimeout)
}

func (d DBDocs) Base() string           { return d.BasePath }
func (d DBDocs) Where(id string) string { return "database:" + id }

func (d DBDocs) Get(id string) ([]byte, error) {
	if err := policy.ValidDocID(id); err != nil {
		return nil, err
	}
	ctx, cancel := d.ctx()
	defer cancel()
	doc, err := d.DB.GetPolicy(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fs.ErrNotExist
	}
	return doc.Body, err
}

func (d DBDocs) Put(id string, data []byte, actor string) error {
	if err := policy.ValidDocID(id); err != nil {
		return err
	}
	ctx, cancel := d.ctx()
	defer cancel()
	return d.DB.PutPolicy(ctx, store.PolicyDoc{ID: id, Body: data, Updated: time.Now(), UpdatedBy: actor})
}

func (d DBDocs) Delete(id, actor string) error {
	if err := policy.ValidDocID(id); err != nil {
		return err
	}
	if id == policy.OrgDoc {
		return errors.New("the organization's policy cannot be deleted; write a new version instead")
	}
	ctx, cancel := d.ctx()
	defer cancel()
	ok, err := d.DB.DeletePolicy(ctx, id, actor)
	if err == nil && !ok {
		return fs.ErrNotExist
	}
	return err
}

func (d DBDocs) Levels() ([]policy.LevelFile, []string, error) {
	ctx, cancel := d.ctx()
	defer cancel()
	docs, err := d.DB.ListPolicies(ctx)
	if err != nil {
		return nil, nil, err
	}
	var out []policy.LevelFile
	var warnings []string
	for _, doc := range docs {
		if doc.ID == policy.OrgDoc {
			continue
		}
		if err := policy.ValidDocID(doc.ID); err != nil {
			warnings = append(warnings, fmt.Sprintf("database policy %q: not used: %v", doc.ID, err))
			continue
		}
		kind, name, _ := strings.Cut(doc.ID, "-")
		out = append(out, policy.LevelFile{Kind: kind, Name: name, Path: d.Where(doc.ID), Data: doc.Body})
	}
	return out, warnings, nil
}

// Signature follows the configuration version, which every policy write
// changes (and key changes too: a reload then finds the policies unchanged).
func (d DBDocs) Signature() string {
	ctx, cancel := d.ctx()
	defer cancel()
	v, err := d.DB.ConfigVersion(ctx)
	if err != nil {
		return "unreadable"
	}
	return fmt.Sprint(v)
}

// SeedPolicies gives a database its policies at the first start: the files
// of an installation that used them (policy.yaml and policies/), imported
// once, or the starter policy. It reports what it did, or "" when the
// database already holds the organization's policy.
func SeedPolicies(ctx context.Context, db store.Database, policyPath string) (string, error) {
	if _, err := db.GetPolicy(ctx, policy.OrgDoc); err == nil {
		return "", nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	org, err := os.ReadFile(policyPath)
	if errors.Is(err, fs.ErrNotExist) {
		if err := db.PutPolicy(ctx, store.PolicyDoc{ID: policy.OrgDoc, Body: policy.Starter(), UpdatedBy: "first start"}); err != nil {
			return "", err
		}
		return "starter", nil
	}
	if err != nil {
		return "", err
	}
	if _, err := policy.Parse(org, policyPath); err != nil {
		return "", fmt.Errorf("%s cannot be imported into the database: %v", policyPath, err)
	}
	levels, _, err := policy.FileDocs{Path: policyPath}.Levels()
	if err != nil {
		return "", err
	}
	for _, lf := range levels {
		if err := db.PutPolicy(ctx, store.PolicyDoc{ID: lf.Kind + "-" + lf.Name, Body: lf.Data, UpdatedBy: "import"}); err != nil {
			return "", err
		}
	}
	// The organization's last, so that a gateway waiting for it finds the
	// levels already there.
	if err := db.PutPolicy(ctx, store.PolicyDoc{ID: policy.OrgDoc, Body: org, UpdatedBy: "import"}); err != nil {
		return "", err
	}
	db.RecordAdmin(ctx, store.AdminAction{Time: time.Now(), Actor: "first start", Action: "policy.import", Target: policyPath,
		Detail: fmt.Sprintf("the organization's policy and %d level files, into the database", len(levels))})
	return fmt.Sprintf("imported from %s and %d level files", policyPath, len(levels)), nil
}
