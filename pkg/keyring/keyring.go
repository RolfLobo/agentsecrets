// Package keyring handles secure storage of cryptographic keys and secrets.
//
// Secret reads and writes are performed directly via the OS keychain (go-keyring).
// On Linux/WSL (where D-Bus Secret Service is typically unavailable),
// storage falls back to file-based storage in ~/.agentsecrets/keyring.json.
//
// On Linux/WSL (where D-Bus Secret Service is typically unavailable),
// keypair storage falls back to file-based storage in ~/.agentsecrets/keyring.json.
//
// Service name: "AgentSecrets"
// Keypair naming: "{email}_private_key", "{email}_public_key"
// Secret naming: "{projectID}:{environment}:{key}"
package keyring

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/The-17/agentsecrets/pkg/keychainauth"
	gokeyring "github.com/zalando/go-keyring"
)

const serviceName = "AgentSecrets"

// useFileBackend is true when the OS keyring is unavailable (WSL, headless Linux, etc.)
var useFileBackend bool

// HomeDirHook is used to determine the home directory for file fallback.
// It can be overridden in tests.
var HomeDirHook = os.UserHomeDir

// ForceFileBackend forces keyring functions to use file-based storage.
// Exposing this allows tests to run without polluting the user's OS Keychain.
func ForceFileBackend(force bool) {
	useFileBackend = force
}

func init() {
	// On Linux, test if the keyring actually works. If not, fall back to file storage.
	// macOS and Windows have reliable keyring support.
	if runtime.GOOS == "linux" {
		// WSL specifically often hangs on dbus-based keyring calls if not set up correctly.
		if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("DISPLAY") == "" {
			useFileBackend = true
			return
		}

		// Try a test write/read/delete to see if keyring works
		testKey := "__agentsecrets_keyring_test__"
		err := gokeyring.Set(serviceName, testKey, "test")
		if err != nil {
			useFileBackend = true
		} else {
			_ = gokeyring.Delete(serviceName, testKey)
		}
	}
}

// StoreKeypair saves both private and public keys.
// Uses OS keychain when available, falls back to file on Linux/WSL.
func StoreKeypair(email string, privateKey, publicKey []byte) error {
	privB64 := base64.StdEncoding.EncodeToString(privateKey)
	pubB64 := base64.StdEncoding.EncodeToString(publicKey)

	if useFileBackend {
		return fileSet(email, privB64, pubB64)
	}

	if err := gokeyring.Set(serviceName, email+"_private_key", privB64); err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}
	if err := gokeyring.Set(serviceName, email+"_public_key", pubB64); err != nil {
		return fmt.Errorf("failed to store public key: %w", err)
	}
	return nil
}

// GetPrivateKey retrieves the user's private key.
func GetPrivateKey(email string) ([]byte, error) {
	if useFileBackend {
		return fileGetKey(email, "private")
	}
	encoded, err := gokeyring.Get(serviceName, email+"_private_key")
	if err != nil {
		return nil, fmt.Errorf("private key not found in keychain: %w", err)
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// GetPublicKey retrieves the user's public key.
func GetPublicKey(email string) ([]byte, error) {
	if useFileBackend {
		return fileGetKey(email, "public")
	}
	encoded, err := gokeyring.Get(serviceName, email+"_public_key")
	if err != nil {
		return nil, fmt.Errorf("public key not found in keychain: %w", err)
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// DeleteKeypair removes both keys (used during logout).
func DeleteKeypair(email string) error {
	if useFileBackend {
		return fileDelete(email)
	}
	_ = gokeyring.Delete(serviceName, email+"_private_key")
	_ = gokeyring.Delete(serviceName, email+"_public_key")
	return nil
}

// --- File-based fallback for Linux/WSL ---

// keyringFile stores keys as a JSON map: { "email": { "private": "b64", "public": "b64" } }
type keyEntry struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

func keyringFilePath() (string, error) {
	home, err := HomeDirHook()
	if err != nil {
		return "", err
	}
	path := filepath.Join(home, ".agentsecrets", "keyring.json")
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	return path, nil
}

func loadKeyringFile() (map[string]keyEntry, error) {
	path, err := keyringFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]keyEntry), nil
		}
		return nil, err
	}
	var entries map[string]keyEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return make(map[string]keyEntry), nil
	}
	return entries, nil
}

func saveKeyringFile(entries map[string]keyEntry) error {
	path, err := keyringFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600) // Restrictive permissions
}

func fileSet(email, privB64, pubB64 string) error {
	entries, err := loadKeyringFile()
	if err != nil {
		return fmt.Errorf("failed to load keyring file: %w", err)
	}
	entries[email] = keyEntry{Private: privB64, Public: pubB64}
	if err := saveKeyringFile(entries); err != nil {
		return fmt.Errorf("failed to save keyring file: %w", err)
	}
	return nil
}

func fileGetKey(email, keyType string) ([]byte, error) {
	entries, err := loadKeyringFile()
	if err != nil {
		return nil, err
	}
	entry, ok := entries[email]
	if !ok {
		return nil, fmt.Errorf("no keys found for %s", email)
	}

	encoded := entry.Public
	if keyType == "private" {
		encoded = entry.Private
	}

	if encoded == "" {
		return nil, fmt.Errorf("%s key not found for %s", keyType, email)
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func fileDelete(email string) error {
	entries, err := loadKeyringFile()
	if err != nil {
		return nil
	}
	delete(entries, email)
	return saveKeyringFile(entries)
}

// --- Individual Secret Storage (for Proxy support) ---

func secretKeyName(projectID, environment, key string) string {
	if environment == "" {
		environment = "development" // fallback for older data
	}
	return fmt.Sprintf("%s:%s:%s", projectID, environment, key)
}

// SetSecret stores a decrypted secret in the keyring and updates the project environment's key index.
func SetSecret(projectID, environment, key, value string) error {
	if keychainauth.IsInitialized() {
		return keychainauth.SetSecret(projectID, environment, key, value)
	}

	name := secretKeyName(projectID, environment, key)
	if useFileBackend {
		// Base64-encode before storing so fileGetKey's decode round-trips correctly.
		encoded := base64.StdEncoding.EncodeToString([]byte(value))
		if err := fileSet(name, encoded, ""); err != nil {
			return err
		}
	} else {
		if err := gokeyring.Set(serviceName, name, value); err != nil {
			return fmt.Errorf("set secret %s: %w", name, err)
		}
	}
	return addKeyToIndex(projectID, environment, key)
}

// GetSecret retrieves a secret value directly from the OS keychain.
// It handles legacy key format fallback for the development environment.
func GetSecret(projectID, environment, key string) (string, error) {
	if keychainauth.IsInitialized() {
		return keychainauth.GetSecret(projectID, environment, key)
	}

	if environment == "" {
		environment = "development"
	}

	name := secretKeyName(projectID, environment, key)
	var val string
	var err error

	if useFileBackend {
		var v []byte
		v, err = fileGetKey(name, "private")
		val = string(v)
	} else {
		val, err = gokeyring.Get(serviceName, name)
	}

	// Legacy fallback for development environment
	if err != nil && environment == "development" {
		legacyName := fmt.Sprintf("Secret_%s_%s", projectID, key)
		if useFileBackend {
			var v []byte
			v, err = fileGetKey(legacyName, "private")
			val = string(v)
		} else {
			val, err = gokeyring.Get(serviceName, legacyName)
		}
	}

	if err != nil {
		return "", fmt.Errorf("secret %q not found in keyring: %w", key, err)
	}

	return val, nil
}

// DeleteSecret removes a secret from the keyring and its index.
func DeleteSecret(projectID, environment, key string) error {
	if keychainauth.IsInitialized() {
		return keychainauth.DeleteSecret(projectID, environment, key)
	}

	name := secretKeyName(projectID, environment, key)
	legacyName := fmt.Sprintf("Secret_%s_%s", projectID, key)

	deleteKey := func(k string) {
		if useFileBackend {
			_ = fileDelete(k)
		} else {
			_ = gokeyring.Delete(serviceName, k)
		}
	}

	deleteKey(name)
	if environment == "development" || environment == "" {
		deleteKey(legacyName)
	}

	return removeKeyFromIndex(projectID, environment, key)
}

// --- Key Index Management ---
// We maintain a comma-separated list of keys per project so we can iterate them
// since go-keyring lacks a list/iterate feature.

func workspaceAllowlistKeyName(workspaceID string) string {
	return fmt.Sprintf("agentsecrets:allowlist:%s", workspaceID)
}

// SetWorkspaceAllowlist stores the allowlist for a workspace in the OS keychain.
func SetWorkspaceAllowlist(workspaceID string, domains []string) error {
	if keychainauth.IsInitialized() {
		return keychainauth.SetWorkspaceAllowlist(workspaceID, domains)
	}

	name := workspaceAllowlistKeyName(workspaceID)

	valBytes, err := json.Marshal(domains)
	if err != nil {
		return fmt.Errorf("serialize allowlist: %w", err)
	}
	val := string(valBytes)

	if useFileBackend {
		encoded := base64.StdEncoding.EncodeToString([]byte(val))
		return fileSet(name, encoded, "")
	}

	if err := gokeyring.Set(serviceName, name, val); err != nil {
		return fmt.Errorf("set allowlist %s: %w", name, err)
	}
	return nil
}

// GetWorkspaceAllowlist retrieves the allowlist for a workspace from the OS keychain.
func GetWorkspaceAllowlist(workspaceID string) ([]string, error) {
	if keychainauth.IsInitialized() {
		return keychainauth.GetWorkspaceAllowlist(workspaceID)
	}

	name := workspaceAllowlistKeyName(workspaceID)
	var val string

	if useFileBackend {
		v, err := fileGetKey(name, "private")
		if err != nil {
			if strings.Contains(err.Error(), "no keys found") {
				return []string{}, nil
			}
			return nil, fmt.Errorf("get allowlist: %w", err)
		}
		val = string(v)
	} else {
		v, err := gokeyring.Get(serviceName, name)
		if err != nil {
			if err == gokeyring.ErrNotFound || strings.Contains(err.Error(), "not found") {
				return []string{}, nil
			}
			return nil, fmt.Errorf("get allowlist: %w", err)
		}
		val = v
	}

	if val == "" {
		return []string{}, nil
	}

	var domains []string
	if err := json.Unmarshal([]byte(val), &domains); err != nil {
		return nil, fmt.Errorf("parse allowlist: %w", err)
	}
	return domains, nil
}

func projectIndexName(projectID, environment string) string {
	if environment == "" {
		environment = "development"
	}
	return fmt.Sprintf("ProjectKeys_%s_%s", projectID, environment)
}

// ListProjectKeyNames returns the key names cached in the local index
// for a given project and environment. This reads the key index only
// (no secret values are accessed, no keychain-auth session required).
// Useful for listing, .env.example generation, and count display without API calls.
func ListProjectKeyNames(projectID, environment string) ([]string, error) {
	if keychainauth.IsInitialized() {
		return keychainauth.ListProjectKeyNames(projectID, environment)
	}
	return getProjectKeys(projectID, environment), nil
}

func getProjectKeys(projectID, environment string) []string {
	name := projectIndexName(projectID, environment)
	legacyName := fmt.Sprintf("ProjectKeys_%s", projectID)

	var keys []string
	keyMap := make(map[string]bool)

	readKeys := func(keyName string) {
		var val string
		if useFileBackend {
			if v, err := fileGetKey(keyName, "private"); err == nil {
				val = string(v)
			}
		} else {
			if v, err := gokeyring.Get(serviceName, keyName); err == nil {
				val = v
			}
		}
		if val != "" {
			for _, k := range strings.Split(val, ",") {
				if !keyMap[k] {
					keys = append(keys, k)
					keyMap[k] = true
				}
			}
		}
	}

	readKeys(name)
	if environment == "development" || environment == "" {
		readKeys(legacyName)
	}

	return keys
}

func saveProjectKeys(projectID, environment string, keys []string) error {
	name := projectIndexName(projectID, environment)
	val := strings.Join(keys, ",")

	if useFileBackend {
		encoded := base64.StdEncoding.EncodeToString([]byte(val))
		return fileSet(name, encoded, "")
	}
	return gokeyring.Set(serviceName, name, val)
}

func addKeyToIndex(projectID, environment, key string) error {
	keys := getProjectKeys(projectID, environment)
	for _, k := range keys {
		if k == key {
			return nil // Already exists
		}
	}
	keys = append(keys, key)
	return saveProjectKeys(projectID, environment, keys)
}

func removeKeyFromIndex(projectID, environment, key string) error {
	keys := getProjectKeys(projectID, environment)
	var newKeys []string
	for _, k := range keys {
		if k != key {
			newKeys = append(newKeys, k)
		}
	}
	return saveProjectKeys(projectID, environment, newKeys)
}

// GetAllProjectSecrets returns all secrets mapped for a specific project and environment from the keyring.
func GetAllProjectSecrets(projectID, environment string) (map[string]string, error) {
	if keychainauth.IsInitialized() {
		return keychainauth.GetAllProjectSecrets(projectID, environment)
	}

	keys := getProjectKeys(projectID, environment)
	res := make(map[string]string)

	for _, k := range keys {
		if val, err := GetSecret(projectID, environment, k); err == nil {
			res[k] = val
		}
	}
	return res, nil
}

// SetSecretPolicy caches a secret's policy in the local keyring.
func SetSecretPolicy(projectID, environment, key string, policy []byte) error {
	if keychainauth.IsInitialized() {
		return keychainauth.SetSecretPolicy(projectID, environment, key, policy)
	}

	name := fmt.Sprintf("%s:%s:%s:policy", projectID, environment, key)
	if useFileBackend {
		encoded := base64.StdEncoding.EncodeToString(policy)
		return fileSet(name, encoded, "")
	}

	if err := gokeyring.Set(serviceName, name, string(policy)); err != nil {
		return fmt.Errorf("set policy %s: %w", name, err)
	}
	return nil
}

// GetSecretPolicy retrieves the cached policy for a secret.
func GetSecretPolicy(projectID, environment, key string) ([]byte, error) {
	if keychainauth.IsInitialized() {
		return keychainauth.GetSecretPolicy(projectID, environment, key)
	}

	name := fmt.Sprintf("%s:%s:%s:policy", projectID, environment, key)
	if useFileBackend {
		v, err := fileGetKey(name, "private")
		if err != nil {
			if strings.Contains(err.Error(), "no keys found") {
				return nil, nil
			}
			return nil, fmt.Errorf("get policy: %w", err)
		}
		return v, nil
	}

	val, err := gokeyring.Get(serviceName, name)
	if err != nil {
		if err == gokeyring.ErrNotFound || strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("get policy: %w", err)
	}
	return []byte(val), nil
}

// SetUserTokens stores the serialized user tokens in the OS keychain.
func SetUserTokens(tokensJSON string) error {
	if useFileBackend {
		encoded := base64.StdEncoding.EncodeToString([]byte(tokensJSON))
		return fileSet("user_tokens", encoded, "")
	}
	if err := gokeyring.Set(serviceName, "user_tokens", tokensJSON); err != nil {
		return fmt.Errorf("failed to store user tokens in keychain: %w", err)
	}
	return nil
}

// GetUserTokens retrieves the serialized user tokens from the OS keychain.
func GetUserTokens() (string, error) {
	if useFileBackend {
		v, err := fileGetKey("user_tokens", "private")
		if err != nil {
			return "", err
		}
		return string(v), nil
	}
	val, err := gokeyring.Get(serviceName, "user_tokens")
	if err != nil {
		return "", err
	}
	return val, nil
}

// DeleteUserTokens removes the user tokens from the OS keychain.
func DeleteUserTokens() error {
	if useFileBackend {
		return fileDelete("user_tokens")
	}
	_ = gokeyring.Delete(serviceName, "user_tokens")
	return nil
}

// SetAgentToken stores an agent token in the OS keychain.
func SetAgentToken(agentName, token string) error {
	name := "agent_token_" + agentName
	if useFileBackend {
		encoded := base64.StdEncoding.EncodeToString([]byte(token))
		return fileSet(name, encoded, "")
	}
	if err := gokeyring.Set(serviceName, name, token); err != nil {
		return fmt.Errorf("failed to store agent token for %s in keychain: %w", agentName, err)
	}
	return nil
}

// GetAgentToken retrieves an agent token from the OS keychain.
func GetAgentToken(agentName string) (string, error) {
	name := "agent_token_" + agentName
	if useFileBackend {
		v, err := fileGetKey(name, "private")
		if err != nil {
			return "", err
		}
		return string(v), nil
	}
	val, err := gokeyring.Get(serviceName, name)
	if err != nil {
		return "", err
	}
	return val, nil
}

// DeleteAgentToken removes an agent token from the OS keychain.
func DeleteAgentToken(agentName string) error {
	name := "agent_token_" + agentName
	if useFileBackend {
		return fileDelete(name)
	}
	_ = gokeyring.Delete(serviceName, name)
	return nil
}

// SetWorkspaceKey stores the base64-encoded workspace key in the OS keychain.
func SetWorkspaceKey(workspaceID, keyB64 string) error {
	name := "workspace_key_" + workspaceID
	if useFileBackend {
		encoded := base64.StdEncoding.EncodeToString([]byte(keyB64))
		return fileSet(name, encoded, "")
	}
	if err := gokeyring.Set(serviceName, name, keyB64); err != nil {
		return fmt.Errorf("failed to store workspace key for %s in keychain: %w", workspaceID, err)
	}
	return nil
}

// GetWorkspaceKey retrieves the base64-encoded workspace key from the OS keychain.
func GetWorkspaceKey(workspaceID string) (string, error) {
	name := "workspace_key_" + workspaceID
	if useFileBackend {
		v, err := fileGetKey(name, "private")
		if err != nil {
			return "", err
		}
		return string(v), nil
	}
	val, err := gokeyring.Get(serviceName, name)
	if err != nil {
		return "", err
	}
	return val, nil
}

// DeleteWorkspaceKey removes a workspace key from the OS keychain.
func DeleteWorkspaceKey(workspaceID string) error {
	name := "workspace_key_" + workspaceID
	if useFileBackend {
		return fileDelete(name)
	}
	_ = gokeyring.Delete(serviceName, name)
	return nil
}

// SetProxySessionToken stores the local proxy session token securely.
func SetProxySessionToken(token string) error {
	if useFileBackend {
		encoded := base64.StdEncoding.EncodeToString([]byte(token))
		return fileSet("proxy_session_token", encoded, "")
	}
	if err := gokeyring.Set(serviceName, "proxy_session_token", token); err != nil {
		return fmt.Errorf("failed to store proxy session token: %w", err)
	}
	return nil
}

// GetProxySessionToken retrieves the local proxy session token securely.
func GetProxySessionToken() (string, error) {
	if useFileBackend {
		v, err := fileGetKey("proxy_session_token", "private")
		if err != nil {
			return "", err
		}
		return string(v), nil
	}
	val, err := gokeyring.Get(serviceName, "proxy_session_token")
	if err != nil {
		return "", err
	}
	return val, nil
}

// DeleteProxySessionToken deletes the local proxy session token.
func DeleteProxySessionToken() error {
	if useFileBackend {
		return fileDelete("proxy_session_token")
	}
	_ = gokeyring.Delete(serviceName, "proxy_session_token")
	return nil
}
