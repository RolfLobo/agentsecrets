package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/capabilities"
)

// mockResolver returns a resolver that maps key names to values.
func mockResolver(secrets map[string]string) SecretResolver {
	return func(key string) (string, error) {
		val, ok := secrets[key]
		if !ok {
			return "", fmt.Errorf("secret not found: %s", key)
		}
		return val, nil
	}
}

// mockAllowlist returns a resolver that returns the given domains (or common test domains if empty).
func mockAllowlist(domains ...string) AllowlistResolver {
	return func(workspaceID string) ([]string, error) {
		if len(domains) == 0 {
			return []string{"127.0.0.1", "localhost", "api.example.com", "example.com", "blocked.com", "approved.com"}, nil
		}
		return domains, nil
	}
}

func TestEngineExecuteBearer(t *testing.T) {
	// Upstream echo server — returns what it received
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer sk_test_123" {
			t.Errorf("upstream got Authorization = %q, want %q", auth, "Bearer sk_test_123")
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"STRIPE_KEY": "sk_test_123"}),
		ResolveAllowlist: mockAllowlist(),
	}

	result, err := engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/v1/charges",
		Method:    "POST",
		Body:      []byte(`{"amount": 1000}`),
		Injections: []Injection{
			{Style: "bearer", SecretKey: "STRIPE_KEY"},
		},
	})

	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}
	if string(result.Body) != `{"ok": true}` {
		t.Errorf("Body = %q, want %q", string(result.Body), `{"ok": true}`)
	}
}

func TestEngineExecuteMultipleInjections(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Org-ID") != "org-abc" {
			t.Errorf("missing X-Org-ID header")
		}
		if r.Header.Get("X-API-Key") != "key-xyz" {
			t.Errorf("missing X-API-Key header")
		}
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID: "test-project",
		Client:    upstream.Client(),
		ResolveSecret: mockResolver(map[string]string{
			"ORG_ID":  "org-abc",
			"API_KEY": "key-xyz",
		}),
		ResolveAllowlist: mockAllowlist(),
	}

	result, err := engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/data",
		Method:    "GET",
		Injections: []Injection{
			{Style: "header", Target: "X-Org-ID", SecretKey: "ORG_ID"},
			{Style: "header", Target: "X-API-Key", SecretKey: "API_KEY"},
		},
	})

	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}
}

func TestEngineExecuteQueryInjection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("api_key")
		if key != "gmap-key-123" {
			t.Errorf("query param api_key = %q, want %q", key, "gmap-key-123")
		}
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"GMAP_KEY": "gmap-key-123"}),
		ResolveAllowlist: mockAllowlist(),
	}

	result, err := engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/maps",
		Method:    "GET",
		Injections: []Injection{
			{Style: "query", Target: "api_key", SecretKey: "GMAP_KEY"},
		},
	})

	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}
}

func TestEngineExecuteMissingSecret(t *testing.T) {
	engine := &Engine{
		ProjectID:        "test-project",
		Client:           http.DefaultClient,
		ResolveSecret:    mockResolver(map[string]string{}), // no secrets
		ResolveAllowlist: mockAllowlist(),
	}

	_, err := engine.Execute(CallRequest{
		TargetURL: "https://api.example.com",
		Method:    "GET",
		Injections: []Injection{
			{Style: "bearer", SecretKey: "MISSING_KEY"},
		},
	})

	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestEngineExecuteMissingURL(t *testing.T) {
	engine := &Engine{
		ProjectID:        "test-project",
		Client:           http.DefaultClient,
		ResolveSecret:    mockResolver(map[string]string{}),
		ResolveAllowlist: mockAllowlist(),
	}

	_, err := engine.Execute(CallRequest{
		TargetURL:  "",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "KEY"}},
	})

	if err == nil {
		t.Fatal("expected error for missing URL")
	}
}

func TestEngineExecuteNoInjections(t *testing.T) {
	engine := &Engine{
		ProjectID:        "test-project",
		Client:           http.DefaultClient,
		ResolveSecret:    mockResolver(map[string]string{}),
		ResolveAllowlist: mockAllowlist(),
	}

	_, err := engine.Execute(CallRequest{
		TargetURL:  "https://api.example.com",
		Method:     "GET",
		Injections: []Injection{},
	})

	if err == nil {
		t.Fatal("expected error for no injections")
	}
}

func TestEngineExecuteExtraHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want %q", r.Header.Get("Content-Type"), "application/json")
		}
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"KEY": "val"}),
		ResolveAllowlist: mockAllowlist(),
	}

	result, err := engine.Execute(CallRequest{
		TargetURL: upstream.URL,
		Method:    "POST",
		Headers:   map[string]string{"Content-Type": "application/json"},
		Body:      []byte(`{"data": true}`),
		Injections: []Injection{
			{Style: "bearer", SecretKey: "KEY"},
		},
	})

	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}
}

func TestAuditNeverLogsSecretValues(t *testing.T) {
	// Create temp log file
	tmpFile, err := os.CreateTemp("", "proxy-audit-test-*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	audit, err := NewAuditLogger(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer audit.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	secretValue := "sk_live_SUPER_SECRET_VALUE_12345"

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		Audit:            audit,
		ResolveSecret:    mockResolver(map[string]string{"STRIPE_KEY": secretValue}),
		ResolveAllowlist: mockAllowlist(),
	}

	_, err = engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/v1/charges",
		Method:    "POST",
		Injections: []Injection{
			{Style: "bearer", SecretKey: "STRIPE_KEY"},
		},
		AgentID: "test-agent",
	})
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	// Read the audit log
	logBytes, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	logContent := string(logBytes)

	// The secret VALUE must NEVER appear in the log
	if strings.Contains(logContent, secretValue) {
		t.Fatal("SECURITY: secret VALUE was found in audit log!")
	}

	// The secret KEY NAME should appear
	if !strings.Contains(logContent, "STRIPE_KEY") {
		t.Error("expected secret KEY NAME to appear in audit log")
	}

	// The agent ID should appear
	if !strings.Contains(logContent, "test-agent") {
		t.Error("expected agent ID to appear in audit log")
	}
}

func TestEngineExecuteRedactBody(t *testing.T) {
	secretValue := "sk_live_ECHO_SECRET_12345"
	originalResponse := fmt.Sprintf(`{"auth": "Bearer %s", "data": "hello"}`, secretValue)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(originalResponse))
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		ResolveAllowlist: mockAllowlist(),
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"STRIPE_KEY": secretValue}),
	}

	result, err := engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/data",
		Method:    "GET",
		Injections: []Injection{
			{Style: "bearer", SecretKey: "STRIPE_KEY"},
		},
	})

	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}

	bodyStr := string(result.Body)
	if strings.Contains(bodyStr, secretValue) {
		t.Fatal("SECURITY: secret VALUE was found in response body!")
	}

	if !strings.Contains(bodyStr, "[REDACTED_BY_AGENTSECRETS]") {
		t.Error("expected response body to contain [REDACTED_BY_AGENTSECRETS]")
	}
}

func TestEngineCapabilities(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"SECRET_A": "val_a", "SECRET_B": "val_b"}),
		ResolveAllowlist: mockAllowlist(),
	}

	// 1. Unrestricted agent capabilities
	_, err := engine.Execute(CallRequest{
		TargetURL:    upstream.URL,
		Method:       "GET",
		Injections:   []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		Capabilities: nil,
	})
	if err != nil {
		t.Errorf("unrestricted agent failed: %v", err)
	}

	// 2. AllowedSecrets whitelist
	res, err := engine.Execute(CallRequest{
		TargetURL:  upstream.URL,
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_B"}},
		Capabilities: &capabilities.AgentCapabilities{
			AllowedSecrets: []string{"SECRET_A"},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 for SECRET_B (not in whitelist), got %d", res.StatusCode)
	}

	// 3. DeniedSecrets blacklist
	res, err = engine.Execute(CallRequest{
		TargetURL:  upstream.URL,
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		Capabilities: &capabilities.AgentCapabilities{
			DeniedSecrets: []string{"SECRET_A"},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 for SECRET_A (in blacklist), got %d", res.StatusCode)
	}
}

type RoundTripFunc func(req *http.Request) (*http.Response, error)

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestEnginePolicies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	upstreamHost := u.Hostname()

	engine := &Engine{
		ProjectID: "test-project",
		Client: &http.Client{
			Transport: RoundTripFunc(func(req *http.Request) (*http.Response, error) {
				target, _ := url.Parse(upstream.URL)
				req.URL.Scheme = target.Scheme
				req.URL.Host = target.Host
				transport := upstream.Client().Transport
				if transport == nil {
					transport = http.DefaultTransport
				}
				return transport.RoundTrip(req)
			}),
		},
		ResolveSecret: mockResolver(map[string]string{
			"SECRET_A": "val_a",
			"SECRET_B": "val_b",
			"SECRET_C": "val_c",
		}),
		ResolvePolicy: func(key string) (*capabilities.SecretPolicy, error) {
			if key == "SECRET_A" {
				return &capabilities.SecretPolicy{
					Domains: []string{upstreamHost},
				}, nil
			}
			if key == "SECRET_B" {
				return &capabilities.SecretPolicy{
					Domains: []string{"approved.com"},
					Methods: map[string]capabilities.Action{
						"POST": capabilities.RequestPermission,
					},
				}, nil
			}
			return nil, nil
		},
		Approvals:        NewApprovalStore(),
		ResolveAllowlist: mockAllowlist(upstreamHost, "blocked.com", "approved.com"),
	}

	// 1. Policy allow (no rules match block)
	res, err := engine.Execute(CallRequest{
		TargetURL:  upstream.URL,
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("expected 200, got %d", res.StatusCode)
	}

	// 2. Policy deny
	// Set target domain to blocked.com (by rewriting target URL or using host)
	res, err = engine.Execute(CallRequest{
		TargetURL:  "http://blocked.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 for blocked domain, got %d", res.StatusCode)
	}

	// 3. Policy request_permission (initially fails with 403)
	res, err = engine.Execute(CallRequest{
		TargetURL:  "http://approved.com/v1",
		Method:     "POST",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_B"}},
		AgentID:    "agent-1",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 (needs approval), got %d", res.StatusCode)
	}

	// 4. Grant approval and verify it passes
	engine.Approvals.Approve(ApprovalKey{
		AgentID:   "agent-1",
		SecretKey: "SECRET_B",
		Domain:    "approved.com",
		Method:    "POST",
	})
	res, err = engine.Execute(CallRequest{
		TargetURL:  "http://approved.com/v1",
		Method:     "POST",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_B"}},
		AgentID:    "agent-1",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("expected 200 after approval, got %d", res.StatusCode)
	}
}

func TestEngineCapabilitiesPriorityAndCaseInsensitivity(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"SECRET_A": "val_a"}),
		ResolveAllowlist: mockAllowlist(),
	}

	// 1. Blacklist priority: SECRET_A is in both allowed and denied lists. Deny should win.
	res, err := engine.Execute(CallRequest{
		TargetURL:  upstream.URL,
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		Capabilities: &capabilities.AgentCapabilities{
			AllowedSecrets: []string{"SECRET_A"},
			DeniedSecrets:  []string{"SECRET_A"},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 because blacklist takes priority, got %d", res.StatusCode)
	}

	// 2. Case insensitivity check: whitelist contains lowercase "secret_a"
	res, err = engine.Execute(CallRequest{
		TargetURL:  upstream.URL,
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		Capabilities: &capabilities.AgentCapabilities{
			AllowedSecrets: []string{"secret_a"},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("expected 200 (case-insensitive whitelist match), got %d", res.StatusCode)
	}

	// 3. Case insensitivity check: blacklist contains lowercase "secret_a"
	res, err = engine.Execute(CallRequest{
		TargetURL:  upstream.URL,
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		Capabilities: &capabilities.AgentCapabilities{
			DeniedSecrets: []string{"secret_a"},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 (case-insensitive blacklist match), got %d", res.StatusCode)
	}
}

func TestEngineAllowlistEnforcement(t *testing.T) {
	engine := &Engine{
		ProjectID:        "test-project",
		Client:           http.DefaultClient,
		ResolveSecret:    mockResolver(map[string]string{"SECRET_A": "val_a"}),
		ResolveAllowlist: mockAllowlist("allowed.com"),
	}

	// 1. Blocked domain
	res, err := engine.Execute(CallRequest{
		TargetURL:  "https://unauthorized.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 for unauthorized domain, got %d", res.StatusCode)
	}

	// 2. Allowed domain
	// We mock the client transport to avoid actual network request
	engine.Client = &http.Client{
		Transport: RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			w := httptest.NewRecorder()
			w.WriteHeader(200)
			w.Write([]byte("allowed"))
			return w.Result(), nil
		}),
	}
	res, err = engine.Execute(CallRequest{
		TargetURL:  "https://allowed.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("expected 200 for allowed domain, got %d", res.StatusCode)
	}
}



