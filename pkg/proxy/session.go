package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/The-17/agentsecrets/pkg/keyring"
)

// GenerateSessionToken generates a cryptographically secure session token.
func GenerateSessionToken() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return "as_sess_" + hex.EncodeToString(b), nil
}

// WriteSessionToken writes the session token securely to the OS Keychain.
func WriteSessionToken(token string) error {
	return keyring.SetProxySessionToken(token)
}

// ReadSessionToken reads the session token securely from the OS Keychain.
func ReadSessionToken() (string, error) {
	return keyring.GetProxySessionToken()
}
