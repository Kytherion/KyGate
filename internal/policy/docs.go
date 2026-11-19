package policy

// Where policy documents live: files next to policy.yaml in
// Solo, which people edit by hand; the configuration database with
// PostgreSQL (Team, Enterprise), so that every gateway reads the same version
// without a shared volume. The Holder, the admin API, and the command line
// go through Docs, and never care which.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// OrgDoc is the ID of the organization's policy.
const OrgDoc = "org"

// Docs stores policy documents: "org", and per-level "team-NAME",
// "project-NAME", "key-NAME".
type Docs interface {
	// Base is the organization policy's path: relative paths in a policy,
	// such as a dictionary file, resolve against its folder.
	Base() string
	// Where describes a document's location, for messages.
	Where(id string) string
	// Get returns fs.ErrNotExist when there is no such document.
	Get(id string) ([]byte, error)
	// Put writes a document and keeps the previous version.
	Put(id string, data []byte, actor string) error
	// Delete keeps the document as its previous version; fs.ErrNotExist when absent.
	Delete(id, actor string) error
	// Levels returns the per-level documents, and warnings about documents
	// that are not used.
	Levels() ([]LevelFile, []string, error)
	// Signature changes whenever a document changes.
	Signature() string
}

// ValidDocID checks a document ID.
func ValidDocID(id string) error {
	if id == OrgDoc {
		return nil
	}
	kind, name, ok := strings.Cut(id, "-")
	if !ok || name == "" || !contains(levelKinds, kind) {
		return errors.New("a policy id is org, team-NAME, project-NAME, or key-NAME")
	}
	if strings.ContainsAny(name, `/\`) {
		return errors.New("a policy name has no slashes")
	}
	return nil
}

// FileDocs keeps documents as files: path for the organization's, and
// policies/ next to it for the levels. A write keeps the previous version
// as .bak.
type FileDocs struct{ Path string }

func (f FileDocs) dir() string { return filepath.Join(filepath.Dir(f.Path), LevelsDir) }

func (f FileDocs) file(id string) string {
	if id == OrgDoc {
		return f.Path
	}
	return filepath.Join(f.dir(), id+".yaml")
}

func (f FileDocs) Base() string           { return f.Path }
func (f FileDocs) Where(id string) string { return f.file(id) }

func (f FileDocs) Get(id string) ([]byte, error) {
	if err := ValidDocID(id); err != nil {
		return nil, err
	}
	return os.ReadFile(f.file(id))
}

func (f FileDocs) Put(id string, data []byte, _ string) error {
	if err := ValidDocID(id); err != nil {
		return err
	}
	path := f.file(id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	if old, err := os.ReadFile(path); err == nil {
		if err := os.WriteFile(path+".bak", old, 0o600); err != nil {
			return err
		}
	}
	// Write beside, then rename, so that a reader never sees half a file.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (f FileDocs) Delete(id, _ string) error {
	if err := ValidDocID(id); err != nil {
		return err
	}
	if id == OrgDoc {
		return errors.New("the organization's policy cannot be deleted; write a new version instead")
	}
	path := f.file(id)
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return os.Rename(path, path+".bak")
}

func (f FileDocs) Levels() ([]LevelFile, []string, error) { return ReadLevels(f.dir()) }

func (f FileDocs) Signature() string {
	var b strings.Builder
	if st, err := os.Stat(f.Path); err == nil {
		fmt.Fprintf(&b, "%d/%d;", st.ModTime().UnixNano(), st.Size())
	}
	entries, _ := os.ReadDir(f.dir())
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			fmt.Fprintf(&b, "%s/%d/%d;", e.Name(), info.ModTime().UnixNano(), info.Size())
		}
	}
	return b.String()
}

// IsNotExist reports whether a Docs error means the document is absent.
func IsNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }
