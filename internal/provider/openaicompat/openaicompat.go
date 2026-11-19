// Package openaicompat is the adapter for local model servers that speak the
// OpenAI API, such as Ollama, vLLM, and llama.cpp. It discovers the models
// each server offers, so that a request naming one of them is sent there.
package openaicompat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/Kytherion/KyGate/internal/provider"
)

// Discover asks each local server for its model list and records it.
func Discover(ctx context.Context, client *http.Client, conns []*provider.Connection) {
	for _, c := range conns {
		if c.Provider != provider.Local {
			continue
		}
		models, err := list(ctx, client, c)
		if err == nil {
			c.SetModels(models)
		}
	}
}

func list(ctx context.Context, client *http.Client, c *provider.Connection) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/models", nil)
	if err != nil {
		return nil, err
	}
	provider.Authorize(c, req.Header)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(body.Data))
	for _, m := range body.Data {
		out = append(out, m.ID)
	}
	sort.Strings(out)
	return out, nil
}

// Embed asks a connection's OpenAI-compatible /v1/embeddings endpoint for one
// vector per input, in input order. The semantic cache uses it with masked
// text only.
func Embed(ctx context.Context, client *http.Client, c *provider.Connection, model string, inputs []string) ([][]float32, error) {
	body, _ := json.Marshal(map[string]any{"model": model, "input": inputs})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	provider.Authorize(c, req.Header)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil, fmt.Errorf("the embeddings endpoint of %s answered %d", c.Name, resp.StatusCode)
	}
	var out struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("the embeddings endpoint of %s: %w", c.Name, err)
	}
	vecs := make([][]float32, len(inputs))
	for i, d := range out.Data {
		idx := d.Index
		if idx < 0 || idx >= len(vecs) {
			idx = i
		}
		if idx < len(vecs) {
			vecs[idx] = d.Embedding
		}
	}
	for _, v := range vecs {
		if len(v) == 0 {
			return nil, fmt.Errorf("the embeddings endpoint of %s returned fewer vectors than inputs", c.Name)
		}
	}
	return vecs, nil
}

// Watch refreshes the model lists until ctx ends.
func Watch(ctx context.Context, client *http.Client, reg *provider.Registry, every time.Duration) {
	Discover(ctx, client, reg.All())
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			Discover(ctx, client, reg.All())
		}
	}
}
