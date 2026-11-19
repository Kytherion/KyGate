package control

// Role checks of the admin API, and the users list (GV-2).

import (
	"fmt"
	"github.com/Kytherion/KyGate/internal/policy"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Kytherion/KyGate/internal/store"
)

// keysOfTeam keeps the keys that sit in a project of the team.
func (c *Console) keysOfTeam(r *http.Request, ks []store.VirtualKey, teamID string) []store.VirtualKey {
	ps, _ := c.Config.ListProjects(r.Context())
	mine := map[string]bool{}
	for _, p := range ps {
		if p.TeamID == teamID && teamID != "" {
			mine[p.ID] = true
		}
	}
	var out []store.VirtualKey
	for _, k := range ks {
		if mine[k.ProjectID] {
			out = append(out, k)
		}
	}
	return out
}

// mayManageProject: an admin, or the lead of the project's team.
func (c *Console) mayManageProject(w http.ResponseWriter, r *http.Request, name string) bool {
	p := PrincipalOf(r)
	if p.Role == RoleAdmin {
		return true
	}
	if p.Role == RoleTeamLead {
		ps, _ := c.Config.ListProjects(r.Context())
		for _, x := range ps {
			if x.Name == name {
				if x.TeamID == p.TeamID {
					return true
				}
				apiError(w, 403, fmt.Sprintf("project %q is not in your team", name))
				return false
			}
		}
		apiError(w, 404, fmt.Sprintf("no project named %q", name))
		return false
	}
	apiError(w, 403, "your role ("+p.Role+") cannot do this")
	return false
}

// mayManageKey: an admin, or the lead of the team whose project holds the key.
func (c *Console) mayManageKey(w http.ResponseWriter, r *http.Request, name string) bool {
	p := PrincipalOf(r)
	if p.Role == RoleAdmin {
		return true
	}
	if p.Role == RoleTeamLead {
		ks, _ := c.Config.ListKeys(r.Context())
		for _, k := range c.keysOfTeam(r, ks, p.TeamID) {
			if k.Name == name || k.ID == name {
				return true
			}
		}
		apiError(w, 403, fmt.Sprintf("key %q is not in your team", name))
		return false
	}
	apiError(w, 403, "your role ("+p.Role+") cannot do this")
	return false
}

// teamOwnsPolicy: the file is the lead's team's, or one of its projects'.
func (c *Console) teamOwnsPolicy(r *http.Request, p Principal, id string) bool {
	if id == "team-"+p.TeamName {
		return true
	}
	if name, ok := strings.CutPrefix(id, "project-"); ok {
		ps, _ := c.Config.ListProjects(r.Context())
		for _, x := range ps {
			if x.Name == name && x.TeamID == p.TeamID {
				return true
			}
		}
	}
	return false
}

func (c *Console) mayReadPolicy(r *http.Request, id string) bool {
	p := PrincipalOf(r)
	if p.ReadsAll() || id == "org" {
		return true
	}
	return c.teamOwnsPolicy(r, p, id)
}

// mayWritePolicy checks who may write a policy file, and that a role limited to
// some sections leaves every other section exactly as it was.
func (c *Console) mayWritePolicy(w http.ResponseWriter, r *http.Request, id string, data []byte) bool {
	p := PrincipalOf(r)
	switch p.Role {
	case RoleAdmin:
		return true
	case RoleTeamLead:
		if !c.teamOwnsPolicy(r, p, id) {
			apiError(w, 403, "a team lead writes their team's and its projects' policy files only")
			return false
		}
	case RoleSecurity, RoleFinance:
	default:
		apiError(w, 403, "your role ("+p.Role+") cannot write policies")
		return false
	}
	old, err := c.Policies.Docs().Get(id)
	if err != nil && !policy.IsNotExist(err) {
		apiError(w, 500, err.Error())
		return false
	}
	if changed, err := changedSections(old, data, policySections[p.Role]); err != nil {
		apiError(w, 422, err.Error())
		return false
	} else if len(changed) > 0 {
		apiError(w, 403, fmt.Sprintf("your role (%s) may change only %s; this file also changes %s",
			p.Role, strings.Join(policySections[p.Role][2:], ", "), strings.Join(changed, ", ")))
		return false
	}
	return true
}

// changedSections lists the top-level sections, outside allowed, that differ
// between two versions of a policy file.
func changedSections(oldData, newData []byte, allowed []string) ([]string, error) {
	var o, n map[string]any
	if len(oldData) > 0 {
		if err := yaml.Unmarshal(oldData, &o); err != nil {
			return nil, fmt.Errorf("the current file does not parse: %v", err)
		}
	}
	if err := yaml.Unmarshal(newData, &n); err != nil {
		return nil, fmt.Errorf("the new file does not parse: %v", err)
	}
	keys := map[string]bool{}
	for k := range o {
		keys[k] = true
	}
	for k := range n {
		keys[k] = true
	}
	var out []string
	for k := range keys {
		if contains(allowed, k) {
			continue
		}
		if !reflect.DeepEqual(o[k], n[k]) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
