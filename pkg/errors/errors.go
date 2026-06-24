package errors

import (
	"fmt"
	"net"
	"os"
)

type ErrorCode string

const (
	ErrSecretNotFound    ErrorCode = "SEC-404"
	ErrKeychainLocked    ErrorCode = "KEY-501"
	ErrKeychainHeadless  ErrorCode = "KEY-502"
	ErrUnauthorized      ErrorCode = "AUTH-401"
	ErrInvalidCredentials ErrorCode = "AUTH-402"
	ErrForbidden         ErrorCode = "AUTH-403"
	ErrServerInternal    ErrorCode = "SRV-500"
	ErrConnection        ErrorCode = "NET-101"
	ErrConnectionTimeout ErrorCode = "NET-102"
	ErrPermissionDenied  ErrorCode = "SYS-403"
	ErrFileNotFound      ErrorCode = "SYS-404"
	ErrBinaryUnapproved  ErrorCode = "SEC-403"
	ErrLogNotFound       ErrorCode = "LOG-404"
	ErrAgentNotFound     ErrorCode = "AGE-404"
	ErrUnknown           ErrorCode = "ERR-999"
)

type CLIError struct {
	Code    ErrorCode
	Message string
	Err     error
	Context map[string]string
}

func (e *CLIError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func New(code ErrorCode, message string, err error) *CLIError {
	return &CLIError{
		Code:    code,
		Message: message,
		Err:     err,
		Context: make(map[string]string),
	}
}

// FromError auto-classifies standard library errors or wraps generic errors
func FromError(err error) *CLIError {
	if err == nil {
		return nil
	}

	// Already wrapped
	if cliErr, ok := err.(*CLIError); ok {
		return cliErr
	}

	// Network failures
	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return New(ErrConnectionTimeout, "Network request timed out", err)
		}
		return New(ErrConnection, "Network connection failed", err)
	}

	// OS / Filesystem access
	if os.IsPermission(err) {
		return New(ErrPermissionDenied, "Operating system access permission denied", err)
	}
	if os.IsNotExist(err) {
		return New(ErrFileNotFound, "File or config directory not found", err)
	}

	// Unknown / Fallback
	return New(ErrUnknown, "An unexpected error occurred", err)
}
