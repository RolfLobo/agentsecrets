package keyring

import (
	"testing"
)

func TestKeyringHelpers(t *testing.T) {
	// Setup: redirect home directory to a temp one and force file backend
	tmpDir := t.TempDir()
	oldHome := HomeDirHook
	HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { HomeDirHook = oldHome }()

	ForceFileBackend(true)
	defer ForceFileBackend(false)

	// 1. Test User Tokens
	tokenJSON := `{"access_token":"t-123","refresh_token":"r-456"}`
	if err := SetUserTokens(tokenJSON); err != nil {
		t.Fatalf("SetUserTokens failed: %v", err)
	}

	retrievedTokens, err := GetUserTokens()
	if err != nil {
		t.Fatalf("GetUserTokens failed: %v", err)
	}
	if retrievedTokens != tokenJSON {
		t.Errorf("GetUserTokens returned %q, expected %q", retrievedTokens, tokenJSON)
	}

	// 2. Test Workspace Key
	workspaceID := "ws-999"
	wsKey := "bXktc2VjcmV0LWtleS0zMi1jaGFycy1sb25nLWhlcmUt"
	if err := SetWorkspaceKey(workspaceID, wsKey); err != nil {
		t.Fatalf("SetWorkspaceKey failed: %v", err)
	}

	retrievedKey, err := GetWorkspaceKey(workspaceID)
	if err != nil {
		t.Fatalf("GetWorkspaceKey failed: %v", err)
	}
	if retrievedKey != wsKey {
		t.Errorf("GetWorkspaceKey returned %q, expected %q", retrievedKey, wsKey)
	}

	// 3. Test Delete
	if err := DeleteUserTokens(); err != nil {
		t.Fatalf("DeleteUserTokens failed: %v", err)
	}
	_, err = GetUserTokens()
	if err == nil {
		t.Error("GetUserTokens should have failed after DeleteUserTokens")
	}

	if err := DeleteWorkspaceKey(workspaceID); err != nil {
		t.Fatalf("DeleteWorkspaceKey failed: %v", err)
	}
	_, err = GetWorkspaceKey(workspaceID)
	if err == nil {
		t.Error("GetWorkspaceKey should have failed after DeleteWorkspaceKey")
	}
}
