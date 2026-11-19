package control

// The admin API for data handling (GV-4): what is kept and for
// how long, where requests may go, and purges. Admin and security roles.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Kytherion/KyGate/internal/cache"
)

func (c *Console) dataRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/v1/admin/data", c.adminData)
	api.HandleFunc("POST /api/v1/admin/purge/events", c.adminPurgeEvents)
	api.HandleFunc("POST /api/v1/admin/purge/cache", c.adminPurgeCache)
}

// adminData shows the organization's retention periods, the regions requests
// are pinned to, and each connection's region.
func (c *Console) adminData(w http.ResponseWriter, r *http.Request) {
	if _, ok := require(w, r, RoleAdmin, RoleSecurity); !ok {
		return
	}
	p := c.Policies.Current()
	type conn struct {
		Name     string `json:"name"`
		Provider string `json:"provider"`
		Source   string `json:"source"`
		Region   string `json:"region"`
		Allowed  bool   `json:"allowed"`
		Variable string `json:"variable,omitempty"` // for environment connections
	}
	var conns []conn
	if c.Registry != nil {
		for _, x := range c.Registry.All() {
			cn := conn{Name: x.Name, Provider: x.Provider, Source: x.Source, Region: x.Region, Allowed: p.AllowsRegion(x.Region)}
			if x.Source == "env" {
				cn.Variable = RegionVariable(x.Name)
			}
			conns = append(conns, cn)
		}
	}
	writeJSON(w, map[string]any{
		"retention": map[string]any{
			"events_days":   p.Audit.RetentionDays,
			"payloads_days": p.Audit.PayloadRetentionDays,
			"admin_days":    p.Audit.AdminRetentionDays, // 0: kept
			"capture":       p.Audit.CapturePayloads,
		},
		"regions":     p.Data.Regions, // empty: no pinning
		"mode":        p.Mode,
		"connections": conns,
		"purges":      c.Purger != nil,
	})
}

// adminPurgeEvents deletes events, or only their captured payloads, by key,
// team, project, and time. dry_run counts without deleting.
func (c *Console) adminPurgeEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := require(w, r, RoleAdmin, RoleSecurity); !ok {
		return
	}
	var in struct {
		EventPurge
		DryRun bool `json:"dry_run"`
	}
	if err := readJSON(r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	f, err := in.Filter(r.Context(), c.Config, func(id string) string { return Pseudonym(c.MasterKey, c.OrgID, id) })
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	n, err := c.Events.CountEvents(r.Context(), f)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	if in.DryRun {
		writeJSON(w, map[string]any{"matched": n, "deleted": 0, "dry_run": true})
		return
	}
	del, err := c.Events.PurgeEvents(r.Context(), f)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	data, _ := json.Marshal(f)
	c.recordData(r, "purge.events", in.Describe(), fmt.Sprintf("%d deleted", del), string(data))
	writeJSON(w, map[string]any{"matched": n, "deleted": del})
}

// adminPurgeCache deletes cache entries stored by one key, or with one tag,
// or all of them, from the exact and semantic caches of every process.
func (c *Console) adminPurgeCache(w http.ResponseWriter, r *http.Request) {
	if _, ok := require(w, r, RoleAdmin, RoleSecurity); !ok {
		return
	}
	if c.Purger == nil {
		apiError(w, 503, "cache purges are not available in this process")
		return
	}
	var in struct {
		Key string `json:"key"`
		Tag string `json:"tag"`
		All bool   `json:"all"`
	}
	if err := readJSON(r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	label, target, err := c.Purger.Resolve(r.Context(), in.Key, in.Tag, in.All)
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	res, err := c.Purger.PurgeCache(r.Context(), label)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	c.record(r, "purge.cache", target, fmt.Sprintf("%d exact, %d semantic entries deleted", res.Exact, res.Semantic))
	writeJSON(w, res)
}

// Resolve turns one of key, tag, or all into a label and a description.
func (p *Purger) Resolve(ctx context.Context, key, tag string, all bool) (label, target string, err error) {
	key, tag = strings.TrimSpace(key), strings.TrimSpace(tag)
	n := 0
	for _, set := range []bool{key != "", tag != "", all} {
		if set {
			n++
		}
	}
	if n != 1 {
		return "", "", errors.New("name exactly one of key, tag, or all")
	}
	switch {
	case all:
		return "", "all entries", nil
	case tag != "":
		if !cache.ValidTag(tag) {
			return "", "", fmt.Errorf("%q is not a cache tag", tag)
		}
		return p.CacheLabel(cache.LabelTag, tag), "tag " + tag, nil
	}
	keys, err := p.DB.ListKeys(ctx)
	if err != nil {
		return "", "", err
	}
	for _, k := range keys {
		if k.Name == key || k.ID == key {
			return p.CacheLabel(cache.LabelKey, k.ID), "key " + k.Name, nil
		}
	}
	return "", "", fmt.Errorf("no key named %q", key)
}
