package keyring

import (
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/keychainauth"
)

func TestKeyringDelegation(t *testing.T) {
	// Override socket path to nonexistent to guarantee Init() fails and returns 'not initialized' error
	keychainauth.SetSocketPathOverride("/nonexistent")
	defer keychainauth.SetSocketPathOverride("")

	// Ensure not initialized state
	keychainauth.Close()

	// Since keyring is a pure delegation layer to keychainauth,
	// calling any function when keychainauth is not initialized
	// should return a "not initialized" error.
	// This confirms that all methods correctly delegate to the daemon client.

	// 1. Test User Tokens
	err := SetUserTokens(`{"access_token":"test"}`)
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("expected 'not initialized' error, got: %v", err)
	}

	_, err = GetUserTokens()
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("expected 'not initialized' error, got: %v", err)
	}

	// 2. Test Workspace Key
	err = SetWorkspaceKey("ws-123", "key-data")
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("expected 'not initialized' error, got: %v", err)
	}

	_, err = GetWorkspaceKey("ws-123")
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("expected 'not initialized' error, got: %v", err)
	}

	// 3. Test Secrets
	err = SetSecret("proj-123", "dev", "KEY", "VAL")
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("expected 'not initialized' error, got: %v", err)
	}

	_, err = GetSecret("proj-123", "dev", "KEY")
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("expected 'not initialized' error, got: %v", err)
	}
}
