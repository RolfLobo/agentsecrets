package capabilities

import (
	"testing"
)

func TestEvaluateSecret(t *testing.T) {
	// Case 1: Nil policy (unrestricted)
	if EvaluateSecret(nil, "api.stripe.com", "POST") != Allow {
		t.Error("expected nil policy to allow all")
	}

	// Case 2: Empty policy (unrestricted)
	empty := &SecretPolicy{}
	if EvaluateSecret(empty, "api.stripe.com", "POST") != Allow {
		t.Error("expected empty policy to allow all")
	}

	// Case 3: Domain matching
	policy := &SecretPolicy{
		Domains: []string{"api.stripe.com", "api.openai.com"},
	}
	if EvaluateSecret(policy, "api.stripe.com", "POST") != Allow {
		t.Error("expected api.stripe.com to be allowed")
	}
	if EvaluateSecret(policy, "API.OPENAI.COM", "GET") != Allow {
		t.Error("expected case-insensitive domain matching to allow")
	}
	if EvaluateSecret(policy, "api.github.com", "GET") != Deny {
		t.Error("expected api.github.com to be denied")
	}

	// Case 4: Method matching
	methodPolicy := &SecretPolicy{
		Methods: map[string]Action{
			"GET":  Allow,
			"POST": RequestPermission,
			"PUT":  Deny,
		},
	}
	if EvaluateSecret(methodPolicy, "any-domain.com", "GET") != Allow {
		t.Error("expected GET to be allowed")
	}
	if EvaluateSecret(methodPolicy, "any-domain.com", "get") != Allow {
		t.Error("expected case-insensitive method GET to be allowed")
	}
	if EvaluateSecret(methodPolicy, "any-domain.com", "POST") != RequestPermission {
		t.Error("expected POST to require permission")
	}
	if EvaluateSecret(methodPolicy, "any-domain.com", "PUT") != Deny {
		t.Error("expected PUT to be denied")
	}
	if EvaluateSecret(methodPolicy, "any-domain.com", "DELETE") != Allow {
		t.Error("expected unlisted method DELETE to be allowed when not configured")
	}

	// Case 5: Combined domains and methods
	combined := &SecretPolicy{
		Domains: []string{"api.stripe.com"},
		Methods: map[string]Action{
			"GET": Allow,
		},
	}
	if EvaluateSecret(combined, "api.stripe.com", "GET") != Allow {
		t.Error("expected matching domain and method to allow")
	}
	if EvaluateSecret(combined, "api.stripe.com", "POST") != Allow {
		t.Error("expected unlisted method to default to allow if domain matches")
	}
	if EvaluateSecret(combined, "api.openai.com", "GET") != Deny {
		t.Error("expected unlisted domain to deny even if method matches")
	}

	// Case 6: Domain-specific rules and fallback logic
	rulesPolicy := &SecretPolicy{
		Rules: []PolicyRule{
			{
				Domain: "api.stripe.com",
				Methods: map[string]Action{
					"POST": RequestPermission,
				},
			},
			{
				Domain: "httpbin.org",
				Methods: map[string]Action{
					"GET": Allow,
				},
			},
		},
		Methods: map[string]Action{
			"POST": RequestPermission,
		},
	}

	// Domain matches rule, method matches rule method:
	if EvaluateSecret(rulesPolicy, "api.stripe.com", "POST") != RequestPermission {
		t.Error("expected POST on stripe to require permission")
	}
	// Domain matches rule, method does not match rule method (specific rule overrides global fallback, but unlisted defaults to allow):
	if EvaluateSecret(rulesPolicy, "api.stripe.com", "GET") != Allow {
		t.Error("expected GET on stripe to allow because it is unlisted")
	}
	// Domain matches another rule:
	if EvaluateSecret(rulesPolicy, "httpbin.org", "GET") != Allow {
		t.Error("expected GET on httpbin to be allowed")
	}
	// Domain does not match any rule, method matches global method:
	if EvaluateSecret(rulesPolicy, "api.github.com", "POST") != RequestPermission {
		t.Error("expected POST on github to fall back to global and require permission")
	}
	// Domain does not match any rule, method does not match global method:
	if EvaluateSecret(rulesPolicy, "api.github.com", "GET") != Allow {
		t.Error("expected GET on github to default to allow")
	}

	// Case 7: Rules configured but no global constraints (unlisted domain should deny)
	onlyRulesPolicy := &SecretPolicy{
		Rules: []PolicyRule{
			{
				Domain: "api.stripe.com",
				Methods: map[string]Action{
					"POST": RequestPermission,
				},
			},
		},
	}
	if EvaluateSecret(onlyRulesPolicy, "api.github.com", "POST") != Deny {
		t.Error("expected unlisted domain to deny when rules are present and no global constraints exist")
	}
}
