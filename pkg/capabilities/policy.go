package capabilities

import (
	"strings"
)

// SecretPolicy defines policy rules for a single secret.
type SecretPolicy struct {
	Domains []string          `json:"domains,omitempty"` // allowed target domains
	Methods map[string]Action `json:"methods,omitempty"` // HTTP method → action
}

type Action string

const (
	Allow             Action = "allow"
	Deny              Action = "deny"
	RequestPermission Action = "request_permission"
)

// AgentCapabilities defines which secrets an agent can access.
type AgentCapabilities struct {
	AllowedSecrets []string `json:"allowed_secrets,omitempty"`
	DeniedSecrets  []string `json:"denied_secrets,omitempty"`
}

// EvaluateSecret checks if a secret can be used for the given domain+method.
// Returns Allow if policy is empty (unconstrained).
func EvaluateSecret(c *SecretPolicy, domain, method string) Action {
	if c == nil || (len(c.Domains) == 0 && len(c.Methods) == 0) {
		return Allow // no policy = unrestricted
	}

	// Domain check
	if len(c.Domains) > 0 {
		matched := false
		for _, d := range c.Domains {
			if strings.EqualFold(d, domain) {
				matched = true
				break
			}
		}
		if !matched {
			return Deny
		}
	}

	// Method check
	if len(c.Methods) > 0 {
		action, exists := c.Methods[strings.ToUpper(method)]
		if !exists {
			return Deny // unlisted methods denied when methods are configured
		}
		return action
	}

	return Allow
}
