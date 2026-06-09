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
	if EvaluateSecret(methodPolicy, "any-domain.com", "DELETE") != Deny {
		t.Error("expected unlisted method DELETE to be denied when methods are configured")
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
	if EvaluateSecret(combined, "api.stripe.com", "POST") != Deny {
		t.Error("expected unlisted method to deny even if domain matches")
	}
	if EvaluateSecret(combined, "api.openai.com", "GET") != Deny {
		t.Error("expected unlisted domain to deny even if method matches")
	}
}
