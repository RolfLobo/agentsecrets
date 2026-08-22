package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeServerURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", DefaultServerURL},
		{"   ", DefaultServerURL},
		{"localhost:8000", "http://localhost:8000/api"},
		{"127.0.0.1:8080", "http://127.0.0.1:8080/api"},
		{"http://localhost:8000", "http://localhost:8000/api"},
		{"http://localhost:8000/", "http://localhost:8000/api"},
		{"http://localhost:8000/api", "http://localhost:8000/api"},
		{"http://localhost:8000/api/", "http://localhost:8000/api"},
		{"https://secrets.internal.corp", "https://secrets.internal.corp/api"},
		{"https://secrets.internal.corp/api", "https://secrets.internal.corp/api"},
		{"secrets.internal.corp/api", "https://secrets.internal.corp/api"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeServerURL(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizeServerURL(%q) = %q, expected %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestResolveServerTargetHierarchy(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := HomeDirHook
	HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { HomeDirHook = oldHome }()

	// Clean env vars
	os.Unsetenv("AGENTSECRETS_SERVER_URL")
	os.Unsetenv("AGENTSECRETS_API_URL")

	// 1. Default fallback
	target := ResolveServerTarget("")
	if target.URL != DefaultServerURL || target.IsSelfHost {
		t.Errorf("Expected cloud default, got URL: %s, IsSelfHost: %v", target.URL, target.IsSelfHost)
	}

	// 2. Global config
	if err := SetGlobalServerURL("http://localhost:8000"); err != nil {
		t.Fatalf("SetGlobalServerURL failed: %v", err)
	}
	target = ResolveServerTarget("")
	if target.URL != "http://localhost:8000/api" || !target.IsSelfHost {
		t.Errorf("Expected global server, got URL: %s, IsSelfHost: %v", target.URL, target.IsSelfHost)
	}

	// 3. Reset Global config
	if err := ResetGlobalServerURL(); err != nil {
		t.Fatalf("ResetGlobalServerURL failed: %v", err)
	}
	target = ResolveServerTarget("")
	if target.URL != DefaultServerURL || target.IsSelfHost {
		t.Errorf("Expected cloud default after reset, got URL: %s", target.URL)
	}

	// 4. Environment variable
	os.Setenv("AGENTSECRETS_SERVER_URL", "https://custom-env-server.com")
	defer os.Unsetenv("AGENTSECRETS_SERVER_URL")
	target = ResolveServerTarget("")
	if target.URL != "https://custom-env-server.com/api" || !target.IsSelfHost {
		t.Errorf("Expected env server, got URL: %s", target.URL)
	}

	// 5. CLI Flag override (highest priority)
	target = ResolveServerTarget("http://cli-override:9000")
	if target.URL != "http://cli-override:9000/api" || !target.IsSelfHost {
		t.Errorf("Expected flag override, got URL: %s", target.URL)
	}
}

func TestProjectServerConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origWd) }()

	// Create project directory
	if err := os.MkdirAll(filepath.Join(tmpDir, ".agentsecrets"), 0700); err != nil {
		t.Fatal(err)
	}
	pc := &ProjectConfig{
		ProjectID:   "proj-123",
		ProjectName: "test-proj",
	}
	if err := SaveProjectConfig(pc); err != nil {
		t.Fatal(err)
	}

	if err := SetProjectServerURL("http://project-server:5000"); err != nil {
		t.Fatalf("SetProjectServerURL failed: %v", err)
	}

	loaded, err := LoadProjectConfig()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ServerURL != "http://project-server:5000/api" {
		t.Errorf("Expected loaded ServerURL http://project-server:5000/api, got %s", loaded.ServerURL)
	}
}
