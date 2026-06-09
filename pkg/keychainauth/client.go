package keychainauth

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// conn holds the persistent connection to the keychain-auth daemon.
// The connection itself is the authenticated session — no tokens needed.
var (
	conn        net.Conn
	scanner     *bufio.Scanner
	encoder     *json.Encoder
	sessionMu   sync.Mutex
	initialized bool
)

// Init connects to the keychain-auth daemon.
//
// The daemon verifies the caller process at connection time using kernel-level
// peer credentials (PID, binary path, binary hash). If the binary is not
// registered, the daemon immediately sends a denied response and closes.
//
// This must be called once per process lifetime before any secret operations.
func Init() error {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	if initialized {
		return nil
	}

	sockPath := SocketPath()

	// Step 1: Check socket exists before attempting connection
	if _, err := os.Stat(sockPath); os.IsNotExist(err) {
		return &DaemonNotRunningError{SocketPath: sockPath, Cause: err}
	}

	// Step 2: Connect to the Unix socket with SOCK_CLOEXEC to prevent
	// file descriptor leakage to child processes (agentsecrets env/exec).
	c, err := dialCLOEXEC(sockPath)
	if err != nil {
		return &DaemonNotRunningError{SocketPath: sockPath, Cause: err}
	}

	// Step 3: The daemon verifies us at connection time. If our binary is
	// unregistered, it sends a RESPONSE with status="denied" immediately.
	// We probe for this by setting a short read deadline.
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)

	// Try to read an immediate denial. Use a brief deadline so we don't
	// block forever if the daemon accepted us silently (the happy path).
	_ = c.SetReadDeadline(timeNow().Add(connectionProbeTimeout))
	if sc.Scan() {
		// The daemon sent something — this means we were denied.
		var env envelope
		if err := json.Unmarshal(sc.Bytes(), &env); err == nil {
			if env.Status == "denied" || env.Status == "error" {
				c.Close()
				return &DaemonDeniedError{Reason: env.Reason}
			}
		}
		// Unexpected message — close and report
		c.Close()
		return fmt.Errorf("keychainauth: unexpected message from daemon on connect")
	}

	// sc.Scan() returned false — either timeout (good: daemon accepted us)
	// or a real error. Check if it's a timeout.
	if err := sc.Err(); err != nil {
		// If it's a timeout, that's expected — the daemon accepted us silently.
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Good — daemon accepted the connection. Clear the deadline.
			_ = c.SetReadDeadline(timeZero)
		} else {
			c.Close()
			return fmt.Errorf("keychainauth: connection error: %w", err)
		}
	} else {
		// EOF without error — daemon closed connection
		c.Close()
		return fmt.Errorf("keychainauth: daemon closed connection immediately")
	}

	// Re-create scanner after the probe (the old one may have buffered state)
	sc = bufio.NewScanner(c)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)

	conn = c
	scanner = sc
	encoder = json.NewEncoder(c)
	initialized = true

	// Step 4: Perform a protocol sanity check (ping) to ensure the running
	// daemon understands the v2.0+ REQUEST/RESPONSE protocol.
	// We send a search request for our service namespace.
	pingReq := request{
		Type:    typeRequest,
		Action:  actionSearch,
		Service: serviceName,
	}
	if err := encoder.Encode(pingReq); err != nil {
		c.Close()
		conn = nil
		scanner = nil
		encoder = nil
		initialized = false
		return fmt.Errorf("keychainauth: protocol check failed: %w", err)
	}

	if !sc.Scan() {
		c.Close()
		conn = nil
		scanner = nil
		encoder = nil
		initialized = false
		if err := sc.Err(); err != nil {
			return fmt.Errorf("keychainauth: connection lost during protocol check: %w", err)
		}
		return fmt.Errorf("keychainauth: connection closed by daemon during protocol check")
	}

	var resp response
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		c.Close()
		conn = nil
		scanner = nil
		encoder = nil
		initialized = false
		return fmt.Errorf("keychainauth: invalid response during protocol check: %w", err)
	}

	if resp.Status == "" {
		c.Close()
		conn = nil
		scanner = nil
		encoder = nil
		initialized = false
		return fmt.Errorf("keychainauth: protocol mismatch (outdated daemon version)")
	}

	return nil
}

// Close tears down the Unix socket connection to keychain-auth.
// Safe to call multiple times. Should be deferred from main.
func Close() {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	if conn != nil {
		conn.Close()
		conn = nil
	}
	scanner = nil
	encoder = nil
	initialized = false
}

// IsAvailable checks whether the keychain-auth socket file exists on disk.
func IsAvailable() bool {
	_, err := os.Stat(SocketPath())
	return err == nil
}

// IsInitialized returns true if a connection has been successfully established.
func IsInitialized() bool {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	return initialized
}

// --- Secret CRUD operations ---

// SetSecret stores a secret in the OS keychain via keychain-auth.
func SetSecret(projectID, environment, key, value string) error {
	target := formatTarget(projectID, environment, key)
	_, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionWrite,
		Service: serviceName,
		Targets: []string{target},
		Values:  []string{value},
	})
	return err
}

// GetSecret retrieves a single secret from the OS keychain via keychain-auth.
func GetSecret(projectID, environment, key string) (string, error) {
	target := formatTarget(projectID, environment, key)
	resp, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionRead,
		Service: serviceName,
		Targets: []string{target},
	})
	if err != nil {
		return "", err
	}
	if len(resp.Results) == 0 {
		return "", fmt.Errorf("secret %q not found", key)
	}
	return resp.Results[0].Value, nil
}

// DeleteSecret removes a secret from the OS keychain via keychain-auth.
func DeleteSecret(projectID, environment, key string) error {
	target := formatTarget(projectID, environment, key)
	_, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionDelete,
		Service: serviceName,
		Targets: []string{target},
	})
	return err
}

// GetAllProjectSecrets returns all secrets for a project+environment as a
// key→value map. Uses a prefix read to fetch everything in a single round-trip.
func GetAllProjectSecrets(projectID, environment string) (map[string]string, error) {
	prefix := formatPrefix(projectID, environment)
	resp, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionRead,
		Service: serviceName,
		Match:   matchPrefix,
		Targets: []string{prefix},
	})
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, len(resp.Results))
	for _, item := range resp.Results {
		bare := stripPrefix(item.Target, prefix)
		if bare != "" {
			result[bare] = item.Value
		}
	}
	return result, nil
}

// ListProjectKeyNames returns just the key names for a project+environment.
// Uses a search operation — no secret values are read.
func ListProjectKeyNames(projectID, environment string) ([]string, error) {
	prefix := formatPrefix(projectID, environment)
	resp, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionSearch,
		Service: serviceName,
		Targets: []string{prefix},
	})
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(resp.Results))
	for _, item := range resp.Results {
		bare := stripPrefix(item.Target, prefix)
		if bare != "" {
			keys = append(keys, bare)
		}
	}
	return keys, nil
}

// SetWorkspaceAllowlist stores the domain allowlist for a workspace.
func SetWorkspaceAllowlist(workspaceID string, domains []string) error {
	target := formatAllowlistTarget(workspaceID)
	valBytes, err := json.Marshal(domains)
	if err != nil {
		return fmt.Errorf("serialize allowlist: %w", err)
	}
	_, err = sendRequest(request{
		Type:    typeRequest,
		Action:  actionWrite,
		Service: serviceName,
		Targets: []string{target},
		Values:  []string{string(valBytes)},
	})
	return err
}

// GetWorkspaceAllowlist retrieves the domain allowlist for a workspace.
func GetWorkspaceAllowlist(workspaceID string) ([]string, error) {
	target := formatAllowlistTarget(workspaceID)
	resp, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionRead,
		Service: serviceName,
		Targets: []string{target},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Results) == 0 {
		return []string{}, nil
	}

	var domains []string
	if err := json.Unmarshal([]byte(resp.Results[0].Value), &domains); err != nil {
		return nil, fmt.Errorf("parse allowlist: %w", err)
	}
	return domains, nil
}

// SetSecretPolicy stores policy in the OS keychain via keychain-auth.
func SetSecretPolicy(projectID, environment, key string, policy []byte) error {
	target := formatTarget(projectID, environment, key) + ":policy"
	_, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionWrite,
		Service: serviceName,
		Targets: []string{target},
		Values:  []string{string(policy)},
	})
	return err
}

// GetSecretPolicy retrieves policy from the OS keychain via keychain-auth.
func GetSecretPolicy(projectID, environment, key string) ([]byte, error) {
	target := formatTarget(projectID, environment, key) + ":policy"
	resp, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionRead,
		Service: serviceName,
		Targets: []string{target},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Results) == 0 {
		return nil, nil
	}
	return []byte(resp.Results[0].Value), nil
}

// --- Internal helpers ---

// sendRequest sends a request to the daemon and reads the response.
// The caller must NOT hold sessionMu.
func sendRequest(req request) (*response, error) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	if !initialized {
		return nil, fmt.Errorf("keychainauth: not initialized — call Init() first")
	}

	req.Type = typeRequest

	// Send request as a single newline-delimited JSON line
	if err := encoder.Encode(req); err != nil {
		initialized = false
		return nil, fmt.Errorf("keychainauth: failed to send request: %w", err)
	}

	// Read response
	if !scanner.Scan() {
		initialized = false
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("keychainauth: connection lost: %w", err)
		}
		return nil, fmt.Errorf("keychainauth: connection closed by daemon")
	}

	var resp response
	raw := scanner.Bytes()
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("keychainauth: invalid response: %w", err)
	}

	switch resp.Status {
	case "success":
		return &resp, nil
	case "denied":
		return nil, &DaemonDeniedError{Reason: resp.Reason}
	case "error":
		return nil, &DaemonDeniedError{Reason: resp.Reason}
	default:
		return nil, fmt.Errorf("keychainauth: unexpected response status %q", resp.Status)
	}
}

func formatTarget(projectID, environment, key string) string {
	if environment == "" {
		environment = "development"
	}
	return fmt.Sprintf("%s:%s:%s", projectID, environment, key)
}

func formatPrefix(projectID, environment string) string {
	if environment == "" {
		environment = "development"
	}
	return fmt.Sprintf("%s:%s:", projectID, environment)
}

func formatAllowlistTarget(workspaceID string) string {
	return fmt.Sprintf("agentsecrets:allowlist:%s", workspaceID)
}

func stripPrefix(target, prefix string) string {
	if strings.HasPrefix(target, prefix) {
		return target[len(prefix):]
	}
	return ""
}
