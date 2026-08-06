// Package keychainauth is the client-side integration with the keychain-auth daemon.
//
// keychain-auth is a standalone security daemon that mediates all secret
// operations between AgentSecrets and the OS keychain. It verifies process
// identity at connection time using kernel-level peer credentials (PID, binary
// path, binary hash). The connection itself is the authenticated session — no
// session tokens are needed.
//
// This package owns:
//   - The Unix socket connection lifecycle (connect, request, close)
//   - Auto-setup of keychain-auth (install, register, start)
//   - User-facing error messages for denial/error responses
//
// This package does NOT own:
//   - Writing secrets to the OS keychain (pkg/keyring handles that)
//   - keychain-auth's internal verification logic
//   - The daemon process itself
package keychainauth

// Service namespace used for all AgentSecrets keychain operations.
const serviceName = "AgentSecrets"

// --- Wire protocol types ---
// These mirror github.com/The-17/keychain-auth/internal/protocol/messages.go.
// Duplicated intentionally — the two codebases are decoupled by design.

const (
	typeRequest  = "REQUEST"
	typeResponse = "RESPONSE"
)

const (
	actionRead   = "read"
	actionWrite  = "write"
	actionDelete = "delete"
	actionSearch = "search"
)

const (
	matchExact  = "exact"
	matchPrefix = "prefix"
)

// reasonCode enumerates granular rejection/error reasons.
type reasonCode string

const (
	reasonUnregisteredBinary reasonCode = "unregistered_binary_pending_approval"
	reasonActionNotInPolicy  reasonCode = "action_not_in_policy"
	reasonServiceNotAllowed  reasonCode = "service_not_allowed"
	reasonTargetNotAllowed   reasonCode = "target_not_allowed"
	reasonMalformedRequest   reasonCode = "malformed_request"
	reasonHashMismatch       reasonCode = "hash_mismatch_during_fork"
	reasonInternalError      reasonCode = "internal_error"
)

// request is the single generalized structure sent to the daemon.
type request struct {
	Type       string            `json:"type"`
	Action     string            `json:"action"`
	Service    string            `json:"service"`
	Match      string            `json:"match,omitempty"`
	Targets    []string          `json:"targets,omitempty"`
	Values     []string          `json:"values,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// resultItem represents a single returned target from a read or search.
type resultItem struct {
	Target     string            `json:"target"`
	Value      string            `json:"value,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// response is sent by the daemon.
type response struct {
	Type    string       `json:"type"`
	Status  string       `json:"status"`
	Reason  reasonCode   `json:"reason,omitempty"`
	Results []resultItem `json:"results,omitempty"`
}
