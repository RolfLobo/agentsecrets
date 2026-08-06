package commands

import "fmt"

// ExitError lets a command request a specific process exit code without calling
// os.Exit() directly. Returning it (instead of exiting in place) lets Execute's
// deferred cleanup run — keychainauth.Close() and the telemetry flush — before
// main.go translates the code into the actual os.Exit. Silent suppresses the
// standard error rendering in Execute, for paths that have already written their
// own message to stderr (or that carry only a child process's exit code).
type ExitError struct {
	Code   int
	Silent bool
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit code %d", e.Code)
}
