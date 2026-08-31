package keychainauth

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DaemonDeniedError is returned when keychain-auth denies a connection or request.
type DaemonDeniedError struct {
	Reason reasonCode
}

func (e *DaemonDeniedError) Error() string {
	return fmt.Sprintf("keychain-auth denied request: %s", e.Reason)
}

// IsUnregistered returns true if the denial was due to an unregistered binary.
func (e *DaemonDeniedError) IsUnregistered() bool {
	return e.Reason == reasonUnregisteredBinary
}

// IsHashMismatch returns true if the denial was due to a binary hash mismatch during fork.
func (e *DaemonDeniedError) IsHashMismatch() bool {
	return e.Reason == reasonHashMismatch
}

// DaemonNotRunningError is returned when the keychain-auth socket does not exist
// or the connection is refused.
type DaemonNotRunningError struct {
	SocketPath string
	Cause      error
}

func (e *DaemonNotRunningError) Error() string {
	return "keychain-auth daemon is not running"
}

func (e *DaemonNotRunningError) Unwrap() error {
	return e.Cause
}

// UserMessage returns the full user-facing error text for keychain-auth errors.
// These messages should explain what happened and what to do next.
func UserMessage(err error) string {
	switch e := err.(type) {
	case *DaemonDeniedError:
		return deniedMessage(e.Reason)
	case *DaemonNotRunningError:
		if e.Cause != nil && (os.IsPermission(e.Cause) || strings.Contains(e.Cause.Error(), "permission denied")) {
			return "Permission denied connecting to keychain-auth socket.\n" +
				"Your user is not authorized or your active shell group membership is not active.\n" +
				"Please run:\n" +
				"  newgrp agentgroup\n" +
				"Or restart your terminal session."
		}
		return daemonNotRunningMessage(e.SocketPath)
	default:
		return err.Error()
	}
}

func getSelfPath() string {
	selfPath, err := os.Executable()
	if err == nil {
		if resolved, err := filepath.EvalSymlinks(selfPath); err == nil {
			return resolved
		}
		return selfPath
	}
	return "agentsecrets"
}

func deniedMessage(reason reasonCode) string {
	selfPath := getSelfPath()
	if runtime.GOOS == "windows" {
		switch reason {
		case reasonUnregisteredBinary:
			return fmt.Sprintf("This AgentSecrets binary is not yet registered/authorized with keychain-auth.\n"+
				"Please authorize it by running:\n"+
				"  keychain-auth authorize \"%s\" agentsecrets\n"+
				"And then start the daemon:\n"+
				"  keychain-auth start", selfPath)
		case reasonHashMismatch:
			return fmt.Sprintf("Security check failed: the AgentSecrets binary has changed since it was registered.\n"+
				"Please re-authorize it by running:\n"+
				"  keychain-auth authorize \"%s\" agentsecrets\n"+
				"And then start the daemon:\n"+
				"  keychain-auth start", selfPath)
		case reasonActionNotInPolicy:
			return "keychain-auth policy does not allow this operation for AgentSecrets.\n" +
				"Check your keychain-auth configuration."
		case reasonServiceNotAllowed:
			return "keychain-auth policy does not allow AgentSecrets to access this service namespace.\n" +
				"Check your keychain-auth configuration."
		case reasonTargetNotAllowed:
			return "keychain-auth policy does not allow access to this secret.\n" +
				"Check your keychain-auth configuration."
		case reasonMalformedRequest:
			return "keychain-auth received a malformed request. This is a bug — please report it."
		case reasonInternalError:
			return "keychain-auth encountered an internal error. Try restarting the daemon:\n" +
				"  keychain-auth start"
		default:
			return fmt.Sprintf("keychain-auth denied the request: %s", reason)
		}
	}

	switch reason {
	case reasonUnregisteredBinary:
		return fmt.Sprintf("This AgentSecrets binary is not yet registered/authorized with keychain-auth.\n"+
			"Please authorize it by running:\n"+
			"  sudo keychain-auth authorize %s agentsecrets\n"+
			"And then restart the daemon:\n"+
			"  sudo systemctl restart keychain-auth", selfPath)
	case reasonHashMismatch:
		return fmt.Sprintf("Security check failed: the AgentSecrets binary has changed since it was registered.\n"+
			"Please re-authorize it by running:\n"+
			"  sudo keychain-auth authorize %s agentsecrets\n"+
			"And then restart the daemon:\n"+
			"  sudo systemctl restart keychain-auth", selfPath)
	case reasonActionNotInPolicy:
		return "keychain-auth policy does not allow this operation for AgentSecrets.\n" +
			"Check your keychain-auth configuration."
	case reasonServiceNotAllowed:
		return "keychain-auth policy does not allow AgentSecrets to access this service namespace.\n" +
			"Check your keychain-auth configuration."
	case reasonTargetNotAllowed:
		return "keychain-auth policy does not allow access to this secret.\n" +
			"Check your keychain-auth configuration."
	case reasonMalformedRequest:
		return "keychain-auth received a malformed request. This is a bug — please report it."
	case reasonInternalError:
		return "keychain-auth encountered an internal error. Try restarting the daemon:\n" +
			"  keychain-auth start"
	default:
		return fmt.Sprintf("keychain-auth denied the request: %s", reason)
	}
}

func daemonNotRunningMessage(socketPath string) string {
	selfPath := getSelfPath()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`keychain-auth daemon is not running.

AgentSecrets requires keychain-auth to read secrets securely.

To start the keychain-auth daemon on Windows, please run:
  keychain-auth start

And then authorize this binary:
  keychain-auth authorize "%s" agentsecrets`, selfPath)
	}

	return fmt.Sprintf(`keychain-auth daemon is not running.

AgentSecrets requires keychain-auth to read secrets securely.

To install and start the keychain-auth daemon, please run:
  sudo keychain-auth install
  sudo systemctl start keychain-auth

And then authorize this binary:
  sudo keychain-auth authorize %s agentsecrets
  sudo systemctl restart keychain-auth

Socket expected at: %s`, selfPath, socketPath)
}
