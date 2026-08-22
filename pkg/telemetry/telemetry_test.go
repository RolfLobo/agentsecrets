package telemetry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTelemetryInMemoryAndFlush(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	// Record several events in-memory
	RecordCommand("secrets list")
	RecordProxyCall()
	RecordProxyBlocked()
	RecordSecretResolved()
	RecordProxyDuration(150)

	// Before flush, flush persists state to disk
	if err := Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	path := filepath.Join(tmpDir, ".agentsecrets", "telemetry.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("Expected telemetry file at %s after Flush", path)
	}

	// Verify reading back data
	mu.Lock()
	data = nil
	dirty = false
	_ = loadLocked()
	d := currentDayLocked()
	mu.Unlock()

	if d.CommandExecutions["secrets list"] < 1 {
		t.Errorf("Expected secrets list executions >= 1, got %d", d.CommandExecutions["secrets list"])
	}
	if d.ProxyCalls < 1 {
		t.Errorf("Expected ProxyCalls >= 1, got %d", d.ProxyCalls)
	}
	if d.ProxyBlocked < 1 {
		t.Errorf("Expected ProxyBlocked >= 1, got %d", d.ProxyBlocked)
	}
	if d.SecretsResolved < 1 {
		t.Errorf("Expected SecretsResolved >= 1, got %d", d.SecretsResolved)
	}
}
