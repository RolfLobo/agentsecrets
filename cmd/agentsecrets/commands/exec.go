package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

type ExecRequest struct {
	ProtocolVersion int      `json:"protocolVersion"`
	Provider        string   `json:"provider"`
	IDs             []string `json:"ids"`
}

type ExecSecretError struct {
	Message string `json:"message"`
}

type ExecResponse struct {
	ProtocolVersion int                        `json:"protocolVersion"`
	Values          map[string]string          `json:"values"`
	Errors          map[string]ExecSecretError `json:"errors,omitempty"`
}

func NewExecCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "exec",
		Short:         "Resolve secrets for OpenClaw exec provider (reads JSON from stdin, writes JSON to stdout)",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          runExec,
	}
}

// runExec implements the OpenClaw exec provider protocol. Failures return a
// silent ExitError (the human-readable message is written to stderr in the
// machine protocol's own format) so Execute's deferred keychainauth.Close still
// runs; the exit code is carried by the ExitError rather than a bare os.Exit.
func runExec(cmd *cobra.Command, args []string) error {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read stdin: %v\n", err)
		return &ExitError{Code: 1, Silent: true}
	}

	if len(input) == 0 {
		fmt.Fprintln(os.Stderr, "empty stdin")
		return &ExitError{Code: 1, Silent: true}
	}

	var req ExecRequest
	if err := json.Unmarshal(input, &req); err != nil {
		fmt.Fprintf(os.Stderr, "invalid JSON: %v\n", err)
		return &ExitError{Code: 1, Silent: true}
	}

	if req.ProtocolVersion != 1 {
		fmt.Fprintf(os.Stderr, "unsupported protocol version: %d\n", req.ProtocolVersion)
		return &ExitError{Code: 1, Silent: true}
	}

	resp := ExecResponse{
		ProtocolVersion: 1,
		Values:          make(map[string]string),
	}

	if len(req.IDs) == 0 {
		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return nil
	}

	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		// Fall back to globally selected project (set by `agentsecrets project use`)
		globalProjectID := config.GetSelectedProjectID()
		if globalProjectID == "" {
			fmt.Fprintln(os.Stderr, "no project configured in current directory")
			return &ExitError{Code: 1, Silent: true}
		}
		project = &config.ProjectConfig{ProjectID: globalProjectID}
	}

	// Ensure keychain-auth session before reading secrets.
	// exec uses DisableFlagParsing-like behavior so PersistentPreRunE may not fire.
	if err := ensureKeychainAuthForExec(); err != nil {
		fmt.Fprintf(os.Stderr, "keychain-auth: %v\n", err)
		return &ExitError{Code: 1, Silent: true}
	}

	for _, id := range req.IDs {
		envName := config.ResolveEnvironment()
		val, err := keyring.GetSecret(project.ProjectID, envName, id)
		if err != nil || val == "" {
			if resp.Errors == nil {
				resp.Errors = make(map[string]ExecSecretError)
			}
			msg := "secret not found in keychain"
			if err != nil {
				msg = err.Error()
			}
			resp.Errors[id] = ExecSecretError{Message: msg}
		} else {
			resp.Values[id] = val
		}
	}

	out, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to serialize response: %v\n", err)
		return &ExitError{Code: 1, Silent: true}
	}

	fmt.Println(string(out))
	return nil
}

// ensureKeychainAuthForExec establishes a keychain-auth connection for the exec command.
// exec is a machine-to-machine protocol (stdin/stdout JSON) so we use stderr
// for any setup messages and skip the spinner UI.
func ensureKeychainAuthForExec() error {
	if keychainauth.IsInitialized() {
		return nil
	}

	if !keychainauth.IsAvailable() {
		if err := keychainauth.AutoSetup(); err != nil {
			return fmt.Errorf("keychain-auth setup failed: %w", err)
		}
	}

	return keychainauth.Init()
}
