package capabilities

import (
	"strings"
)

// PolicyRule defines domain-specific method mappings.
type PolicyRule struct {
	Domain  string            `json:"domain"`
	Methods map[string]Action `json:"methods,omitempty"` // HTTP method → action
}

// SecretPolicy defines policy rules for a single secret.
type SecretPolicy struct {
	Domains []string          `json:"domains,omitempty"` // allowed target domains (legacy)
	Methods map[string]Action `json:"methods,omitempty"` // HTTP method → action (legacy)
	Rules   []PolicyRule      `json:"rules,omitempty"`   // domain-specific rules (v3)
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
	if c == nil {
		return Allow // no policy = unrestricted
	}

	// 1. Check domain-specific Rules if present
	if len(c.Rules) > 0 {
		var matchedRule *PolicyRule
		for i := range c.Rules {
			if strings.EqualFold(c.Rules[i].Domain, domain) {
				matchedRule = &c.Rules[i]
				break
			}
		}

		if matchedRule == nil {
			return Deny // domain not allowed by any rule
		}

		// Domain matched! Now check method inside this rule
		if len(matchedRule.Methods) > 0 {
			action, exists := matchedRule.Methods[strings.ToUpper(method)]
			if !exists {
				return Deny // unlisted methods denied for this domain
			}
			return action
		}

		return Allow // domain matched, no methods configured = allow all methods for this domain
	}

	// 2. Legacy fallback
	if len(c.Domains) == 0 && len(c.Methods) == 0 {
		return Allow
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
