package proxy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/The-17/agentsecrets/pkg/log"
	"github.com/The-17/agentsecrets/pkg/proxy"
)

func TestForensicLogAndChainVerification(t *testing.T) {
	// Create temporary database file
	tmpDir, err := os.MkdirTemp("", "agentsecrets-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "audit_test.db")
	logger, err := proxy.NewAuditLogger(dbPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer logger.Close()

	// Initialize log service
	logSvc, err := log.NewService(nil, logger.DB())
	if err != nil {
		t.Fatalf("failed to create log service: %v", err)
	}

	// 1. Insert a chain of 10 forensic logs
	for i := 0; i < 10; i++ {
		ev := proxy.ForensicAuditEvent{
			ID:          fmt.Sprintf("log_test_%d", i),
			Version:     "2",
			CreatedAt:   time.Now().Add(time.Duration(i) * time.Second).UTC(),
			WorkspaceID: "ws-test",
			ProjectID:   "proj-test",
			Event: proxy.EventBlock{
				Type:        "proxy_call",
				KeyName:     fmt.Sprintf("KEY_%d", i),
				Domain:      "api.test.com",
				Path:        fmt.Sprintf("/path/%d", i),
				Method:      "GET",
				StatusCode:  200,
				Outcome:     "success",
				LatencyMs:   50,
				Environment: "test-env",
			},
			Snapshot: proxy.SnapshotBlock{
				CapturedAt: time.Now().UTC(),
				Workspace: proxy.WorkspaceSnapshot{
					ID:             "ws-test",
					AllowlistCount: 0,
				},
				Project: proxy.ProjectSnapshot{
					ID:          "proj-test",
					Environment: "test-env",
				},
				SecretsCount: 0,
			},
			Enforcement: proxy.EnforcementBlock{
				Decision:  "permitted",
				DecidedBy: "secrets_policy",
			},
			Resolution: proxy.ResolutionBlock{
				CredentialInjected: true,
				InjectionStyle:     "bearer",
				ResponseStatus:     200,
			},
		}

		err := logger.LogForensic(ev)
		if err != nil {
			t.Fatalf("failed to log forensic event at index %d: %v", i, err)
		}
	}

	// 2. Verify chain is OK
	err = logSvc.VerifyChain()
	if err != nil {
		t.Errorf("expected chain integrity to be OK, got error: %v", err)
	}

	// 3. Query local to verify the items map correctly back to legacy AuditEvents
	events, err := logSvc.QueryLocal(log.Filter{})
	if err != nil {
		t.Fatalf("QueryLocal failed: %v", err)
	}
	if len(events) != 10 {
		t.Errorf("expected 10 legacy audit events, got %d", len(events))
	}
	// Verify mapped values
	for idx, ev := range events {
		expectedID := fmt.Sprintf("log_test_%d", 9-idx) // QueryLocal returns DESC by default
		if ev.ID != expectedID {
			t.Errorf("mapped event ID mismatch: got %s, want %s", ev.ID, expectedID)
		}
		expectedKey := fmt.Sprintf("KEY_%d", 9-idx)
		if len(ev.SecretKeys) != 1 || ev.SecretKeys[0] != expectedKey {
			t.Errorf("mapped secret key mismatch: got %v, want [%s]", ev.SecretKeys, expectedKey)
		}
	}

	// 4. Intentionally corrupt a row's chain_hash and verify verification fails
	_, err = logger.DB().Exec("UPDATE forensic_audit_events SET chain_hash = 'invalid_hash' WHERE id = 'log_test_5'")
	if err != nil {
		t.Fatalf("failed to update row for corruption: %v", err)
	}

	err = logSvc.VerifyChain()
	if err == nil {
		t.Error("expected chain integrity verification to fail after corruption, but it succeeded")
	} else {
		t.Logf("verification failed as expected: %v", err)
	}
}

func TestLogManagementEvent(t *testing.T) {
	// Create temporary directory for home redirect
	tmpDir, err := os.MkdirTemp("", "agentsecrets-home-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Save original env vars
	origHome := os.Getenv("HOME")
	origUserProfile := os.Getenv("USERPROFILE")

	// Set home env vars to redirect DefaultLogPath
	os.Setenv("HOME", tmpDir)
	os.Setenv("USERPROFILE", tmpDir)
	defer func() {
		os.Setenv("HOME", origHome)
		os.Setenv("USERPROFILE", origUserProfile)
	}()

	// 1. Log management event
	err = proxy.LogManagementEvent(
		"ADD",
		"allowlist",
		"Added domain test.com",
		"user@example.com",
		"ws-1",
		"proj-1",
		"dev",
	)
	if err != nil {
		t.Fatalf("failed to log management event: %v", err)
	}

	// 2. Locate DB file path
	dbPath := filepath.Join(tmpDir, ".agentsecrets", "audit.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatalf("expected db file to be created at %s, but it does not exist", dbPath)
	}

	// 3. Open database and verify with LogService
	logger, err := proxy.NewAuditLogger(dbPath)
	if err != nil {
		t.Fatalf("failed to open audit logger: %v", err)
	}
	defer logger.Close()

	logSvc, err := log.NewService(nil, logger.DB())
	if err != nil {
		t.Fatalf("failed to create log service: %v", err)
	}

	// Verify chain integrity
	if err := logSvc.VerifyChain(); err != nil {
		t.Errorf("chain verification failed for management log: %v", err)
	}

	// Query local
	events, err := logSvc.QueryLocal(log.Filter{})
	if err != nil {
		t.Fatalf("failed to query local logs: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.IdentityLevel != "user" {
		t.Errorf("expected identity level 'user', got '%s'", ev.IdentityLevel)
	}
	if ev.AgentID != "user@example.com" {
		t.Errorf("expected agent ID 'user@example.com', got '%s'", ev.AgentID)
	}
	if ev.Method != "ADD" {
		t.Errorf("expected method 'ADD', got '%s'", ev.Method)
	}
	if ev.TargetURL != "Added domain test.com" {
		t.Errorf("expected target URL/action 'Added domain test.com', got '%s'", ev.TargetURL)
	}
}

