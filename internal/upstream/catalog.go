package upstream

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

func catalogKey(a *auth.Auth) string {
	site, _ := auth.ResolveSite(a)
	key, _ := json.Marshal([4]string{site.Host, a.UID, a.EnterpriseID, fmt.Sprintf("%p", a)})
	return string(key)
}

type catalogSnapshot struct {
	models  []ModelInfo
	fetched time.Time
}

// Unknown catalogs remain permissive; a known catalog is authoritative for that account.
func (c *Client) ModelAvailable(a *auth.Auth, id string) bool {
	if id == "" {
		return true
	}
	c.effortsMu.RLock()
	defer c.effortsMu.RUnlock()
	catalog, known := c.catalogs[catalogKey(a)]
	if !known || time.Since(catalog.fetched) > time.Hour {
		return true
	}
	for _, m := range catalog.models {
		if m.ID == id {
			return true
		}
	}
	return false
}

func (c *Client) prepareBodyFor(a *auth.Auth, body []byte) []byte {
	c.effortsMu.RLock()
	catalog := c.catalogs[catalogKey(a)]
	c.effortsMu.RUnlock()
	models := catalog.models
	if time.Since(catalog.fetched) > time.Hour {
		models = nil
	}
	efforts := make(map[string][]string, len(models))
	for _, m := range models {
		if len(m.Efforts) > 0 {
			efforts[m.ID] = m.Efforts
		}
	}
	return PrepareBodyOptWithEfforts(body, c.SanitizeFingerprints, efforts)
}

type catalogModel struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Aliases           []string `json:"aliases"`
	MaxInputTokens    int64    `json:"maxInputTokens"`
	MaxOutputTokens   int64    `json:"maxOutputTokens"`
	MaxAllowedSize    int64    `json:"maxAllowedSize"`
	Disabled          bool     `json:"disabled"`
	Credits           string   `json:"credits"`
	SupportsReasoning bool     `json:"supportsReasoning"`
	Reasoning         struct {
		Effort             string   `json:"effort"`
		DefaultEffort      string   `json:"defaultEffort"`
		CanDisableThinking bool     `json:"canDisableThinking"`
		SupportedEfforts   []string `json:"supportedEfforts"`
	} `json:"reasoning"`
}

func selectProductModels(raw []byte, workBuddy bool) ([]ModelInfo, error) {
	var data struct {
		Models []catalogModel `json:"models"`
		Agents []struct {
			Name   string          `json:"name"`
			Tags   []string        `json:"tags"`
			Models json.RawMessage `json:"models"`
		} `json:"agents"`
		Available []string `json:"availableModels"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("models parse: %w", err)
	}
	if data.Models == nil {
		return nil, fmt.Errorf("models catalog missing data.models")
	}
	byID, byName, byAlias := map[string]int{}, map[string]int{}, map[string]int{}
	for i, m := range data.Models {
		if strings.TrimSpace(m.ID) == "" {
			return nil, fmt.Errorf("models catalog has an empty model ID")
		}
		if _, ok := byID[m.ID]; ok {
			return nil, fmt.Errorf("models catalog has duplicate model IDs")
		}
		byID[m.ID] = i
		if _, exists := byName[m.Name]; !exists && m.Name != "" {
			byName[m.Name] = i
		}
		for _, alias := range m.Aliases {
			if _, exists := byAlias[alias]; !exists {
				byAlias[alias] = i
			}
		}
	}
	cli, primary, fallback := -1, -1, -1
	for i, agent := range data.Agents {
		if agent.Name == "cli" {
			cli = i
		}
		for _, tag := range agent.Tags {
			if tag == "default" && primary < 0 {
				primary = i
			}
		}
		var refs []json.RawMessage
		if json.Unmarshal(agent.Models, &refs) == nil && len(refs) > 0 && fallback < 0 {
			fallback = i
		}
	}
	chosen := cli
	if workBuddy {
		if primary >= 0 {
			chosen = primary
		} else if chosen < 0 {
			chosen = fallback
		}
	}
	var indices []int
	if chosen < 0 || len(data.Agents[chosen].Models) == 0 {
		for i := range data.Models {
			indices = append(indices, i)
		}
	} else {
		var refs []json.RawMessage
		if string(data.Agents[chosen].Models) == "null" ||
			json.Unmarshal(data.Agents[chosen].Models, &refs) != nil {
			return nil, fmt.Errorf("models catalog has invalid agent references")
		}
		for _, ref := range refs {
			var name string
			var keys []string
			if json.Unmarshal(ref, &name) == nil && strings.TrimSpace(name) != "" {
				keys = []string{name}
			} else {
				var obj struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				}
				if json.Unmarshal(ref, &obj) != nil || (obj.ID == "" && obj.Name == "") {
					return nil, fmt.Errorf("models catalog has invalid model reference")
				}
				if obj.ID != "" {
					keys = append(keys, obj.ID)
				}
				if obj.Name != "" {
					keys = append(keys, obj.Name)
				}
			}
		lookup:
			for _, index := range []map[string]int{byID, byName, byAlias} {
				for _, key := range keys {
					if i, ok := index[key]; ok {
						indices = append(indices, i)
						break lookup
					}
				}
			}
		}
		if len(refs) > 0 && len(indices) == 0 {
			return nil, fmt.Errorf("models catalog has unresolved agent references")
		}
	}
	available, seen := map[string]bool{}, map[string]bool{}
	for _, id := range data.Available {
		available[id] = true
	}
	out := make([]ModelInfo, 0, len(indices))
	for _, i := range indices {
		m := data.Models[i]
		if seen[m.ID] || m.Disabled || (len(available) > 0 && !available[m.ID]) {
			continue
		}
		seen[m.ID] = true
		effort := m.Reasoning.Effort
		if effort == "" {
			effort = m.Reasoning.DefaultEffort
		}
		out = append(out, ModelInfo{
			ID: m.ID, Name: m.Name, ContextWindow: m.MaxInputTokens,
			MaxTokens: m.MaxOutputTokens, MaxAllowedSize: m.MaxAllowedSize,
			Efforts: m.Reasoning.SupportedEfforts, DefaultEffort: effort,
			CanDisableThinking: m.Reasoning.CanDisableThinking,
			SupportsReasoning:  m.SupportsReasoning, Credits: m.Credits,
		})
	}
	return out, nil
}
