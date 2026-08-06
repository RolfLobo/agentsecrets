package keychainauth

import (
	"os"
	"path/filepath"
	"runtime"
)

var socketPathOverride string

// SetSocketPathOverride overrides the socket path for unit testing.
func SetSocketPathOverride(path string) {
	socketPathOverride = path
}

// SocketPath returns the keychain-auth Unix socket path or named pipe path on Windows.
// It uses platform-specific, user-writable directories to avoid permission issues.
func SocketPath() string {
	if socketPathOverride != "" {
		return socketPathOverride
	}
	if runtime.GOOS == "windows" {
		return `\\.\pipe\keychain-auth`
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "keychain-auth", "agent.sock")
	}

	// Linux / WSL
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/run/keychain-auth"); err == nil {
			return "/run/keychain-auth/agent.sock"
		}
	}

	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir != "" {
		// Verify the directory actually exists (WSL often exports this env var but the directory
		// isn't created by systemd, leading to permission denied when we try to MkdirAll later).
		if info, err := os.Stat(runtimeDir); err != nil || !info.IsDir() {
			runtimeDir = ""
		}
	}

	if runtimeDir == "" {
		// Fallback to home-based cache dir
		runtimeDir = filepath.Join(os.Getenv("HOME"), ".cache")
	}
	return filepath.Join(runtimeDir, "keychain-auth", "agent.sock")
}
