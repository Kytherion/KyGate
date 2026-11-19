package control

// The API of end-user identity (AC-3): a key's signing secret for
// application user tokens, whether a key requires a user token, and the
// pseudonym that stands for a person in reports.

import (
	"net/http"
	"strings"
)

func (c *Console) userRoutes(api *http.ServeMux) {
	api.HandleFunc("POST /api/v1/admin/keys/{name}/user-secret", c.adminUserSecret)
	api.HandleFunc("DELETE /api/v1/admin/keys/{name}/user-secret", c.adminDeleteUserSecret)
	api.HandleFunc("PUT /api/v1/admin/keys/{name}/require-user", c.adminRequireUser)
	api.HandleFunc("POST /api/v1/users/pseudonym", c.userPseudonym)
}

// adminUserSecret creates or replaces a key's signing secret and returns it,
// once. The earlier secret stops working at once.
func (c *Console) adminUserSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !c.mayManageKey(w, r, name) {
		return
	}
	secret, k, err := CreateUserSecret(r.Context(), c.Config, c.MasterKey, c.OrgID, name)
	if err != nil {
		apiError(w, 404, err.Error())
		return
	}
	c.record(r, "key.user_secret", k.Name, "created; shown once")
	w.WriteHeader(201)
	writeJSON(w, map[string]any{"key": k.Name, "secret": secret})
}

func (c *Console) adminDeleteUserSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !c.mayManageKey(w, r, name) {
		return
	}
	ok, err := c.Config.SetKeyUserSecret(r.Context(), name, nil)
	switch {
	case err != nil:
		apiError(w, 500, err.Error())
	case !ok:
		apiError(w, 404, "no active key named "+name)
	default:
		c.record(r, "key.user_secret", name, "removed")
		w.WriteHeader(204)
	}
}

// adminRequireUser sets whether a key refuses requests that name no person.
func (c *Console) adminRequireUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !c.mayManageKey(w, r, name) {
		return
	}
	var in struct {
		Required bool `json:"required"`
	}
	if err := readJSON(r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	ok, err := c.Config.SetKeyRequireUser(r.Context(), name, in.Required)
	switch {
	case err != nil:
		apiError(w, 500, err.Error())
	case !ok:
		apiError(w, 404, "no active key named "+name)
	default:
		state := "off"
		if in.Required {
			state = "on"
		}
		c.record(r, "key.require_user", name, state)
		writeJSON(w, map[string]any{"key": name, "require_user": in.Required})
	}
}

// userPseudonym turns a person's ID into the pseudonym reports show, so that
// anyone who knows an ID can find that person's figures. The ID is neither
// stored nor recorded.
func (c *Console) userPseudonym(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &in); err != nil || strings.TrimSpace(in.ID) == "" {
		apiError(w, 400, "send {\"id\": \"the person's ID or email\"}")
		return
	}
	writeJSON(w, map[string]any{"user": Pseudonym(c.MasterKey, c.OrgID, in.ID)})
}
