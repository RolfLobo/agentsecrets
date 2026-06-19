package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/capabilities"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

type CachedToken struct {
	TokenID      string
	AgentID      string
	AgentName    string
	WorkspaceID  string
	ProjectID    string
	Environment  string
	Capabilities capabilities.AgentCapabilities
	ExpiresAt    *time.Time
	ValidatedAt  time.Time
}

type TokenCache struct {
	mu     sync.RWMutex
	tokens map[string]*CachedToken
	ttl    time.Duration
}

func NewTokenCache(ttl time.Duration) *TokenCache {
	return &TokenCache{
		tokens: make(map[string]*CachedToken),
		ttl:    ttl,
	}
}

type verifyResponse struct {
	Valid        bool                           `json:"valid"`
	Reason       string                         `json:"reason,omitempty"`
	AgentID      string                         `json:"agent_id,omitempty"`
	AgentName    string                         `json:"agent_name,omitempty"`
	WorkspaceID  string                         `json:"workspace_id,omitempty"`
	ProjectID    string                         `json:"project_id,omitempty"`
	Environment  string                         `json:"environment,omitempty"`
	Capabilities capabilities.AgentCapabilities `json:"capabilities,omitempty"`
	TokenID      string                         `json:"token_id,omitempty"`
}

func (c *TokenCache) Validate(token string, apiClient *api.Client) (*CachedToken, error) {
	c.mu.RLock()
	cached, exists := c.tokens[token]
	c.mu.RUnlock()

	if exists && time.Since(cached.ValidatedAt) < c.ttl {
		return cached, nil
	}

	if apiClient == nil {
		return nil, fmt.Errorf("API client not available for token validation")
	}

	// Make call to backend internal verify endpoint
	payload := map[string]string{
		"token": token,
	}

	resp, err := apiClient.Call("agents.token_validate", "POST", payload, nil, nil)
	if err != nil || resp.StatusCode >= 500 {
		// Network or server error — try local keyring fallback
		agentName, findErr := keyring.FindAgentNameByToken(token)
		if findErr == nil {
			capsBytes, getErr := keyring.GetAgentCapabilities(agentName)
			if getErr == nil && len(capsBytes) > 0 {
				var caps capabilities.AgentCapabilities
				if unmarshalErr := json.Unmarshal(capsBytes, &caps); unmarshalErr == nil {
					// Found locally cached capabilities!
					cachedToken := &CachedToken{
						TokenID:      "cached_" + agentName,
						AgentID:      agentName,
						AgentName:    agentName,
						Capabilities: caps,
						ValidatedAt:  time.Now(),
					}
					c.mu.Lock()
					c.tokens[token] = cachedToken
					c.mu.Unlock()
					return cachedToken, nil
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("failed to call token validation API: %w", err)
		}
		return nil, fmt.Errorf("token validation API returned status %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token validation API returned status %d", resp.StatusCode)
	}

	var res verifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode verification response: %w", err)
	}

	if !res.Valid {
		return nil, fmt.Errorf("invalid token: %s", res.Reason)
	}

	// Cache validated capabilities in the local keyring for offline fallback
	if res.AgentName != "" {
		_ = keyring.SetAgentToken(res.AgentName, token)
		capsBytes, marshalErr := json.Marshal(res.Capabilities)
		if marshalErr == nil {
			_ = keyring.SetAgentCapabilities(res.AgentName, capsBytes)
		}
	}

	cachedToken := &CachedToken{
		TokenID:      res.TokenID,
		AgentID:      res.AgentID,
		AgentName:    res.AgentName,
		WorkspaceID:  res.WorkspaceID,
		ProjectID:    res.ProjectID,
		Environment:  res.Environment,
		Capabilities: res.Capabilities,
		ValidatedAt:  time.Now(),
	}

	c.mu.Lock()
	c.tokens[token] = cachedToken
	c.mu.Unlock()

	return cachedToken, nil
}
