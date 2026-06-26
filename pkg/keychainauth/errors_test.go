package keychainauth

import (
	"errors"
	"strings"
	"testing"
)

func TestUserMessage_DaemonDenied(t *testing.T) {
	tests := []struct {
		reason   reasonCode
		contains string
	}{
		{reasonUnregisteredBinary, "not yet registered"},
		{reasonHashMismatch, "binary has changed"},
		{reasonActionNotInPolicy, "policy does not allow this operation"},
		{reasonServiceNotAllowed, "policy does not allow AgentSecrets"},
		{reasonTargetNotAllowed, "policy does not allow access"},
		{reasonMalformedRequest, "malformed request"},
		{reasonInternalError, "internal error"},
		{reasonCode("unknown_reason"), "unknown_reason"},
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			err := &DaemonDeniedError{Reason: tt.reason}
			got := UserMessage(err)
			if !strings.Contains(got, tt.contains) {
				t.Errorf("UserMessage() = %q, want it to contain %q", got, tt.contains)
			}
		})
	}
}

func TestDaemonDeniedError_Checks(t *testing.T) {
	unreg := &DaemonDeniedError{Reason: reasonUnregisteredBinary}
	if !unreg.IsUnregistered() {
		t.Error("IsUnregistered() should be true for unregistered_binary_pending_approval")
	}
	if unreg.IsHashMismatch() {
		t.Error("IsHashMismatch() should be false for unregistered_binary_pending_approval")
	}

	hash := &DaemonDeniedError{Reason: reasonHashMismatch}
	if hash.IsUnregistered() {
		t.Error("IsUnregistered() should be false for hash_mismatch_during_fork")
	}
	if !hash.IsHashMismatch() {
		t.Error("IsHashMismatch() should be true for hash_mismatch_during_fork")
	}
}

func TestUserMessage_DaemonNotRunning(t *testing.T) {
	err := &DaemonNotRunningError{SocketPath: "/tmp/sock", Cause: errors.New("conn refused")}
	got := UserMessage(err)
	if !strings.Contains(got, "/tmp/sock") {
		t.Errorf("Expected message to contain socket path, got: %s", got)
	}
	if !strings.Contains(got, "systemctl start keychain-auth") {
		t.Errorf("Expected message to contain start instructions, got: %s", got)
	}
}
