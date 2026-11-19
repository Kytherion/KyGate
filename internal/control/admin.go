package control

// The admin API (GV-1, AC-4, AC-5): the hierarchy, virtual keys,
// provider keys, and policy files, written behind the admin token on the
// console's own port. It serves the command line, scripts, and the console's
// Administration page for signed-in roles (architecture §3.8). Every change is recorded in the audit trail of administration.
// A provider key is accepted, sealed, and never returned or recorded.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func validName(kind, name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("a %s name is 1 to 64 letters, digits, dots, dashes, or underscores, starting with a letter or digit", kind)
	}
	return nil
}

// adminRoutes adds the write API to the authenticated mux.
func (c *Console) adminRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/v1/admin/hierarchy", c.adminHierarchy)
	api.HandleFunc("POST /api/v1/admin/teams", c.adminCreateTeam)
	api.HandleFunc("DELETE /api/v1/admin/teams/{name}", c.adminDeleteTeam)
	api.HandleFunc("POST /api/v1/admin/projects", c.adminCreateProject)
	api.HandleFunc("DELETE /api/v1/admin/projects/{name}", c.adminDeleteProject)
	api.HandleFunc("POST /api/v1/admin/keys", c.adminCreateKey)
	api.HandleFunc("POST /api/v1/admin/keys/{name}/revoke", c.adminRevokeKey)
	api.HandleFunc("PUT /api/v1/admin/keys/{name}/project", c.adminMoveKey)
	api.HandleFunc("POST /api/v1/admin/providers", c.adminAddProvider)
	api.HandleFunc("DELETE /api/v1/admin/providers/{name}", c.adminDeleteProvider)
	api.HandleFunc("PUT /api/v1/admin/providers/{name}/region", c.adminProviderRegion)
	api.HandleFunc("GET /api/v1/admin/policies", c.adminPolicies)
	api.HandleFunc("GET /api/v1/admin/policies/{id}", c.adminGetPolicy)
	api.HandleFunc("PUT /api/v1/admin/policies/{id}", c.adminPutPolicy)
	api.HandleFunc("DELETE /api/v1/admin/policies/{id}", c.adminDeletePolicy)
	api.HandleFunc("GET /api/v1/admin/log", c.adminLog)
	api.HandleFunc("GET /api/v1/admin/users", c.adminUsers)
	api.HandleFunc("PUT /api/v1/admin/users/{email}", c.adminPutUser)
	api.HandleFunc("DELETE /api/v1/admin/users/{email}", c.adminDeleteUser)
	c.dataRoutes(api)
	c.userRoutes(api)
	c.auditRoutes(api)
}

func (c *Console) record(r *http.Request, action, target, detail string) {
	c.recordData(r, action, target, detail, "")
}

// recordData records an action with machine-readable data for the audit
// ledger, such as a purge's filter.
func (c *Console) recordData(r *http.Request, action, target, detail, data string) {
	actor := PrincipalOf(r).Actor
	if actor == "" {
		actor = TokenActor
	}
	if err := c.Config.RecordAdmin(r.Context(), store.AdminAction{Time: time.Now(), Actor: actor, Action: action, Target: target, Detail: detail, Data: data}); err != nil && c.Logf != nil {
		c.Logf("admin: could not record %s %s: %v", action, target, err)
	}
	if c.Logf != nil {
		c.Logf("admin: %s %s", action, target)
	}
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("the body is not the expected JSON: %v", err)
	}
	return nil
}

func (c *Console) adminHierarchy(w http.ResponseWriter, r *http.Request) {
	ts, err := c.Config.ListTeams(r.Context())
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	ps, err := c.Config.ListProjects(r.Context())
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	ks, err := c.Config.ListKeys(r.Context())
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	if ts == nil {
		ts = []store.Team{}
	}
	if ps == nil {
		ps = []store.Project{}
	}
	if p := PrincipalOf(r); !p.ReadsAll() {
		var mt []store.Team
		for _, t := range ts {
			if t.ID == p.TeamID {
				mt = append(mt, t)
			}
		}
		var mp []store.Project
		for _, x := range ps {
			if x.TeamID == p.TeamID {
				mp = append(mp, x)
			}
		}
		ts, ps, ks = mt, mp, c.keysOfTeam(r, ks, p.TeamID)
	}
	if ts == nil {
		ts = []store.Team{}
	}
	if ps == nil {
		ps = []store.Project{}
	}
	if ks == nil {
		ks = []store.VirtualKey{}
	}
	writeJSON(w, map[string]any{"teams": ts, "projects": ps, "keys": ks})
}

func (c *Console) teamID(r *http.Request, name string) (string, error) {
	ts, err := c.Config.ListTeams(r.Context())
	if err != nil {
		return "", err
	}
	for _, t := range ts {
		if t.Name == name {
			return t.ID, nil
		}
	}
	return "", fmt.Errorf("no team named %q", name)
}

func (c *Console) projectID(r *http.Request, name string) (string, error) {
	ps, err := c.Config.ListProjects(r.Context())
	if err != nil {
		return "", err
	}
	for _, p := range ps {
		if p.Name == name {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("no project named %q", name)
}

func (c *Console) adminCreateTeam(w http.ResponseWriter, r *http.Request) {
	if _, ok := require(w, r, RoleAdmin); !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	if err := validName("team", in.Name); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	t := store.Team{ID: identity.NewID("team_"), Name: in.Name, OrgID: c.OrgID, CreatedAt: time.Now()}
	if err := c.Config.CreateTeam(r.Context(), t); err != nil {
		apiError(w, 409, err.Error())
		return
	}
	c.record(r, "team.create", in.Name, "")
	w.WriteHeader(201)
	writeJSON(w, t)
}

func (c *Console) adminDeleteTeam(w http.ResponseWriter, r *http.Request) {
	if _, ok := require(w, r, RoleAdmin); !ok {
		return
	}
	name := r.PathValue("name")
	ok, err := c.Config.DeleteTeam(r.Context(), name)
	switch {
	case err != nil:
		apiError(w, 409, err.Error())
	case !ok:
		apiError(w, 404, fmt.Sprintf("no team named %q", name))
	default:
		c.record(r, "team.delete", name, "")
		w.WriteHeader(204)
	}
}

func (c *Console) adminCreateProject(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		Team string `json:"team"`
	}
	if err := readJSON(r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	if err := validName("project", in.Name); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	who, ok := require(w, r, RoleAdmin, RoleTeamLead)
	if !ok {
		return
	}
	if who.Role == RoleTeamLead {
		if in.Team != "" && in.Team != who.TeamName {
			apiError(w, 403, "a team lead creates projects in their own team only")
			return
		}
		in.Team = who.TeamName
	}
	p := store.Project{ID: identity.NewID("proj_"), Name: in.Name, OrgID: c.OrgID, CreatedAt: time.Now()}
	if in.Team != "" {
		id, err := c.teamID(r, in.Team)
		if err != nil {
			apiError(w, 404, err.Error())
			return
		}
		p.TeamID = id
	}
	if err := c.Config.CreateProject(r.Context(), p); err != nil {
		apiError(w, 409, err.Error())
		return
	}
	c.record(r, "project.create", in.Name, "team "+orNone(in.Team))
	w.WriteHeader(201)
	writeJSON(w, p)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func (c *Console) adminDeleteProject(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !c.mayManageProject(w, r, name) {
		return
	}
	ok, err := c.Config.DeleteProject(r.Context(), name)
	switch {
	case err != nil:
		apiError(w, 409, err.Error())
	case !ok:
		apiError(w, 404, fmt.Sprintf("no project named %q", name))
	default:
		c.record(r, "project.delete", name, "")
		w.WriteHeader(204)
	}
}

// adminCreateKey creates a virtual key. The key is in the answer, once; only
// its hash is stored.
func (c *Console) adminCreateKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		Project string `json:"project"`
	}
	if err := readJSON(r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	if err := validName("key", in.Name); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	if PrincipalOf(r).Role == RoleTeamLead && in.Project == "" {
		apiError(w, 403, "a team lead creates keys in a project of their team")
		return
	}
	if in.Project != "" && !c.mayManageProject(w, r, in.Project) {
		return
	} else if in.Project == "" {
		if _, ok := require(w, r, RoleAdmin); !ok {
			return
		}
	}
	pid := ""
	if in.Project != "" {
		id, err := c.projectID(r, in.Project)
		if err != nil {
			apiError(w, 404, err.Error())
			return
		}
		pid = id
	}
	secret, k, err := identity.CreateKey(r.Context(), c.Config, in.Name, c.OrgID)
	if err != nil {
		apiError(w, 409, err.Error())
		return
	}
	if pid != "" {
		if _, err := c.Config.SetKeyProject(r.Context(), k.ID, pid); err != nil {
			apiError(w, 500, err.Error())
			return
		}
		k.ProjectID = pid
	}
	c.record(r, "key.create", in.Name, "project "+orNone(in.Project))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(201)
	writeJSON(w, map[string]any{"key": secret, "id": k.ID, "name": k.Name, "project_id": k.ProjectID,
		"note": "the key is shown once and stored as a hash; a lost key is replaced, never recovered"})
}

func (c *Console) adminRevokeKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !c.mayManageKey(w, r, name) {
		return
	}
	ok, err := c.Config.RevokeKey(r.Context(), name)
	switch {
	case err != nil:
		apiError(w, 500, err.Error())
	case !ok:
		apiError(w, 404, fmt.Sprintf("no active key named %q", name))
	default:
		c.record(r, "key.revoke", name, "")
		w.WriteHeader(204)
	}
}

func (c *Console) adminMoveKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		Project string `json:"project"`
	}
	if err := readJSON(r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	if !c.mayManageKey(w, r, name) {
		return
	}
	if PrincipalOf(r).Role == RoleTeamLead && (in.Project == "" || !c.mayManageProject(w, r, in.Project)) {
		if in.Project == "" {
			apiError(w, 403, "a team lead moves keys between their team's projects only")
		}
		return
	}
	pid := ""
	if in.Project != "" {
		id, err := c.projectID(r, in.Project)
		if err != nil {
			apiError(w, 404, err.Error())
			return
		}
		pid = id
	}
	ok, err := c.Config.SetKeyProject(r.Context(), name, pid)
	switch {
	case err != nil:
		apiError(w, 500, err.Error())
	case !ok:
		apiError(w, 404, fmt.Sprintf("no key named %q", name))
	default:
		c.record(r, "key.move", name, "project "+orNone(in.Project))
		w.WriteHeader(204)
	}
}

// adminAddProvider stores a provider key, sealed under the master key. It is
// never returned, logged, or recorded (invariant 10).
func (c *Console) adminAddProvider(w http.ResponseWriter, r *http.Request) {
	if _, ok := require(w, r, RoleAdmin); !ok {
		return
	}
	var in struct {
		Name     string `json:"name"`
		Provider string `json:"provider"`
		BaseURL  string `json:"base_url"`
		Region   string `json:"region"`
		Key      string `json:"key"`
	}
	if err := readJSON(r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	if err := AddCredential(r.Context(), c.Config, c.MasterKey, c.OrgID, in.Name, in.Provider, in.BaseURL, in.Region, in.Key); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	c.record(r, "provider.add", in.Name, strings.TrimSpace(in.Provider+" "+strings.ToLower(strings.TrimSpace(in.Region))))
	w.WriteHeader(201)
	writeJSON(w, map[string]any{"name": in.Name, "provider": in.Provider, "base_url": in.BaseURL})
}

// adminProviderRegion sets or clears the region of a stored provider
// connection (GV-4). Region pinning is a security setting, so the security
// role may change it too. An environment connection's region comes from
// KYGATE_REGION_<NAME>.
func (c *Console) adminProviderRegion(w http.ResponseWriter, r *http.Request) {
	if _, ok := require(w, r, RoleAdmin, RoleSecurity); !ok {
		return
	}
	var in struct {
		Region string `json:"region"`
	}
	if err := readJSON(r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	region, err := NormalizeRegion(in.Region)
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	name := r.PathValue("name")
	ok, err := c.Config.SetCredentialRegion(r.Context(), name, region)
	switch {
	case err != nil:
		apiError(w, 500, err.Error())
	case !ok:
		apiError(w, 404, fmt.Sprintf("no stored provider key named %q; a connection from an environment variable takes its region from %s", name, RegionVariable(name)))
	default:
		c.record(r, "provider.region", name, region)
		writeJSON(w, map[string]any{"name": name, "region": region})
	}
}

func (c *Console) adminDeleteProvider(w http.ResponseWriter, r *http.Request) {
	if _, ok := require(w, r, RoleAdmin); !ok {
		return
	}
	name := r.PathValue("name")
	ok, err := c.Config.DeleteCredential(r.Context(), name)
	switch {
	case err != nil:
		apiError(w, 500, err.Error())
	case !ok:
		apiError(w, 404, fmt.Sprintf("no stored provider key named %q (keys from environment variables are managed there)", name))
	default:
		c.record(r, "provider.delete", name, "")
		w.WriteHeader(204)
	}
}

// policyDoc checks a policy id ("org", "team-NAME", "project-NAME",
// "key-NAME") and returns its level file, empty for the organization's.
func (c *Console) policyDoc(id string) (policy.LevelFile, error) {
	if id == policy.OrgDoc {
		return policy.LevelFile{}, nil
	}
	kind, name, ok := strings.Cut(id, "-")
	if !ok || (kind != "team" && kind != "project" && kind != "key") {
		return policy.LevelFile{}, errors.New("a policy id is org, team-NAME, project-NAME, or key-NAME")
	}
	if err := validName(kind, name); err != nil {
		return policy.LevelFile{}, err
	}
	return policy.LevelFile{Kind: kind, Name: name, Path: c.Policies.Docs().Where(id)}, nil
}

func (c *Console) adminPolicies(w http.ResponseWriter, r *http.Request) {
	type row struct {
		ID      string `json:"id"`
		Path    string `json:"path"`
		Version string `json:"version,omitempty"`
	}
	org := c.Policies.Current()
	rows := []row{{ID: "org", Path: c.Policies.Docs().Where(policy.OrgDoc), Version: org.Version}}
	for _, lf := range c.Policies.Levels() {
		if c.mayReadPolicy(r, lf.Kind+"-"+lf.Name) {
			rows = append(rows, row{ID: lf.Kind + "-" + lf.Name, Path: lf.Path})
		}
	}
	writeJSON(w, map[string]any{"rows": rows})
}

func (c *Console) adminGetPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !c.mayReadPolicy(r, id) {
		apiError(w, 403, "a team lead reads the organization's policy and their team's files only")
		return
	}
	if _, err := c.policyDoc(id); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	data, err := c.Policies.Docs().Get(id)
	if policy.IsNotExist(err) {
		apiError(w, 404, "no such policy")
		return
	}
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Write(data)
}

// adminPutPolicy validates a policy and writes it, keeping the previous
// version (a .bak file, or the database's history). A policy that would not
// load is refused, as is an organization policy with which a level's would
// no longer merge.
func (c *Console) adminPutPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	lf, err := c.policyDoc(id)
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	if !c.mayWritePolicy(w, r, id, data) {
		return
	}
	docs := c.Policies.Docs()
	base := docs.Base()
	var warnings []string
	if id == policy.OrgDoc {
		p, err := policy.Parse(data, base)
		if err != nil {
			apiError(w, 422, err.Error())
			return
		}
		warnings = p.Warnings
		for _, l := range c.Policies.Levels() {
			if _, err := policy.Effective(data, base, []policy.LevelFile{l}); err != nil {
				apiError(w, 422, fmt.Sprintf("%s would no longer merge with this policy: %v", l.Kind+"-"+l.Name, err))
				return
			}
		}
	} else {
		org, err := docs.Get(policy.OrgDoc)
		if err != nil {
			apiError(w, 500, err.Error())
			return
		}
		lf.Data = data
		p, err := policy.Effective(org, base, []policy.LevelFile{lf})
		if err != nil {
			apiError(w, 422, err.Error())
			return
		}
		warnings = p.Warnings
	}
	if err := docs.Put(id, data, PrincipalOf(r).Actor); err != nil {
		apiError(w, 500, err.Error())
		return
	}
	c.Policies.Reload()
	c.record(r, "policy.write", id, fmt.Sprintf("%d bytes", len(data)))
	if warnings == nil {
		warnings = []string{}
	}
	writeJSON(w, map[string]any{"id": id, "path": docs.Where(id), "warnings": warnings})
}

func (c *Console) adminDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == policy.OrgDoc {
		apiError(w, 400, "the organization's policy cannot be deleted; write a new version instead")
		return
	}
	if who := PrincipalOf(r); who.Role != RoleAdmin && !(who.Role == RoleTeamLead && c.teamOwnsPolicy(r, who, id)) {
		apiError(w, 403, "your role ("+who.Role+") cannot delete this policy file")
		return
	}
	if _, err := c.policyDoc(id); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	err := c.Policies.Docs().Delete(id, PrincipalOf(r).Actor)
	if policy.IsNotExist(err) {
		apiError(w, 404, "no such policy")
		return
	}
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	c.Policies.Reload()
	c.record(r, "policy.delete", id, "the previous version is kept")
	w.WriteHeader(204)
}

func (c *Console) adminLog(w http.ResponseWriter, r *http.Request) {
	if _, ok := require(w, r, RoleAdmin, RoleSecurity); !ok {
		return
	}
	rows, err := c.Config.ListAdmin(r.Context(), 200)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	if rows == nil {
		rows = []store.AdminAction{}
	}
	writeJSON(w, map[string]any{"rows": rows})
}
