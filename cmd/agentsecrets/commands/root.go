package commands

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"errors"
	"fmt"
	"github.com/The-17/agentsecrets/pkg/agents"
	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/telemetry"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/workspaces"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Version is set at build time via ldflags
var Version = "dev"

var (
	authService      *auth.Service
	workspaceService *workspaces.Service
	apiClient        *api.Client
)

// rootCmd is the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "agentsecrets",
	Short: "Secure secrets management for the AI era",
	Long: lipgloss.JoinVertical(lipgloss.Left,
		"",
		ui.BrandStyle.Render("AgentSecrets"),
		ui.DimStyle.Render("   Zero-knowledge secrets manager for AI-assisted development"),
		"",
		ui.LabelStyle.Render("   Manage secrets across projects, teams, and environments."),
		ui.LabelStyle.Render("   AI assistants can use this tool without seeing secret values."),
		"",
		ui.DimStyle.Render("   Get started:"),
		"   "+ui.BrandStyle.Render("agentsecrets init")+"        "+ui.LabelStyle.Render("Create a new account"),
		"   "+ui.BrandStyle.Render("agentsecrets login")+"       "+ui.LabelStyle.Render("Login to existing account"),
		"   "+ui.BrandStyle.Render("agentsecrets status")+"      "+ui.LabelStyle.Render("Show current session info"),
		"",
	),
	Version:       Version,
	SilenceErrors: true,
	SilenceUsage:  true,
}

func Execute() error {
	ui.CLIVersion = Version
	// Ensure keychain-auth socket is closed on exit
	defer keychainauth.Close()

	// Register telemetry callbacks to avoid import cycles
	telemetry.KeychainInitializedFunc = keychainauth.IsInitialized
	telemetry.LoadProjectIDFunc = func() string {
		if project, err := config.LoadProjectConfig(); err == nil && project != nil {
			return project.ProjectID
		}
		return ""
	}
	telemetry.LoadGlobalConfigFunc = func() (string, string, string) {
		if gc, err := config.LoadGlobalConfig(); err == nil && gc != nil {
			wsType := "personal"
			if gc.SelectedWorkspaceID != "" {
				if ws, ok := gc.Workspaces[gc.SelectedWorkspaceID]; ok {
					if ws.Type != "" {
						wsType = ws.Type
					}
				}
			}
			return gc.SelectedWorkspaceID, gc.Email, wsType
		}
		return "", "", "personal"
	}
	telemetry.ResolveEnvironmentFunc = config.ResolveEnvironment

	// Run update check. It's efficient (24h interval) and has a short timeout.
	if res, _ := config.CheckForUpdates(Version); res != nil && res.NewVersionAvailable {
		ui.Banner(fmt.Sprintf("Update Available: %s → %s", res.CurrentVersion, res.LatestVersion))
		ui.Info("Run 'brew upgrade agentsecrets', 'npm install -g @the-17/agentsecrets',")
		ui.Info("or 'pip install agentsecrets-cli' to update.")
		ui.Divider()
		fmt.Println()
	}

	// Record telemetry for the executed command
	cmdName := "root"
	if len(os.Args) > 1 {
		cmdName = os.Args[1]
	}
	telemetry.RecordCommand(cmdName)

	// Sync telemetry in background if 24 hours have passed
	defer telemetry.SyncIfDue(apiClient, Version)

	if err := rootCmd.Execute(); err != nil {
		ui.ErrorWithSuggestions(err)
		os.Exit(1)
	}
	return nil
}

func init() {
	apiClient = auth.NewAuthenticatedClient()

	// Create the shared services
	authService = auth.NewService(apiClient)
	workspaceService = workspaces.NewService(apiClient)
	InitProjectService(apiClient)
	InitSecretsService(apiClient)

	// Register all subcommands
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(statusCmd)

	// Add auth middleware to commands that require it
	workspaceCmd.PersistentPreRunE = keychainAuthMiddleware
	projectCmd.PersistentPreRunE = keychainAuthMiddleware
	environmentCmd.PersistentPreRunE = keychainAuthMiddleware
	agentCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if err := keychainAuthMiddleware(cmd, args); err != nil {
			return err
		}
		// Init agent service (originally in agent.go's PersistentPreRunE)
		if agentService == nil {
			agentService = agents.NewService(apiClient)
		}
		return nil
	}

	// Commands that read secrets or display sensitive info need auth verification.
	// The keychainAuthMiddleware handles this.
	secretsCmd.PersistentPreRunE = keychainAuthMiddleware
	callCmd.PersistentPreRunE = keychainAuthMiddleware

	statusCmd.PersistentPreRunE = daemonOnlyMiddleware
	loginCmd.PersistentPreRunE = daemonOnlyMiddleware
	initCmd.PersistentPreRunE = daemonOnlyMiddleware

	rootCmd.AddCommand(workspaceCmd)
	rootCmd.AddCommand(projectCmd)
	rootCmd.AddCommand(secretsCmd)
	rootCmd.AddCommand(agentCmd)
	rootCmd.AddCommand(logsCmd)
	rootCmd.AddCommand(proxyCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(callCmd)
	rootCmd.AddCommand(environmentCmd)
	rootCmd.AddCommand(NewEnvCmd())
	rootCmd.AddCommand(NewExecCmd())
	rootCmd.AddCommand(docsCmd)
}

// ensureDaemonInitialized ensures that:
// 1. The keychain-auth daemon is set up and running (AutoSetup if missing/outdated)
// 2. The client is successfully initialized and connected to the daemon socket/named pipe
func ensureDaemonInitialized() error {
	// Step 1: Skip if connection already established
	if keychainauth.IsInitialized() {
		return nil
	}

	// Step 2: If keychain-auth isn't available, run auto-setup
	if !keychainauth.IsAvailable() {
		if runtime.GOOS == "linux" {
			// Check if sudo is cached. If not, prompt the user before starting the spinner.
			sudoCheck := exec.Command("sudo", "-n", "true")
			if err := sudoCheck.Run(); err != nil {
				fmt.Println("keychain-auth sandbox system setup is required. Please authorize when prompted.")
				sudoVal := exec.Command("sudo", "-v")
				sudoVal.Stdin = os.Stdin
				sudoVal.Stdout = os.Stdout
				sudoVal.Stderr = os.Stderr
				_ = sudoVal.Run() // Wait for password entry to cache it
			}
		}

		if err := ui.Spinner("Setting up keychain-auth...", func() error {
			return keychainauth.AutoSetup()
		}); err != nil {
			ui.Error("keychain-auth setup failed: " + err.Error())
			fmt.Println()
			ui.Info("You can set it up manually:")
			ui.Info("  brew install The-17/tap/keychain-auth")
			ui.Info("  keychain-auth start")
			fmt.Println()
			return fmt.Errorf("keychain-auth is required for secure credentials storage")
		}
	}

	err := keychainauth.Init()
	if err != nil {
		// If the daemon is not running or is outdated, clean up and attempt to start/setup the daemon transparently.
		var notRunning *keychainauth.DaemonNotRunningError
		isMismatch := strings.Contains(err.Error(), "protocol mismatch") || strings.Contains(err.Error(), "unexpected response status")

		if errors.As(err, &notRunning) || isMismatch {
			keychainauth.Close()
			if !isMismatch {
				_ = os.Remove(keychainauth.SocketPath())
			}

			if runtime.GOOS == "linux" {
				sudoCheck := exec.Command("sudo", "-n", "true")
				if err := sudoCheck.Run(); err != nil {
					fmt.Println("keychain-auth daemon restart is required. Please authorize when prompted.")
					sudoVal := exec.Command("sudo", "-v")
					sudoVal.Stdin = os.Stdin
					sudoVal.Stdout = os.Stdout
					sudoVal.Stderr = os.Stderr
					_ = sudoVal.Run()
				}
			}

			if errSetup := ui.Spinner("Starting keychain-auth daemon...", func() error {
				if isMismatch {
					return keychainauth.RestartDaemon()
				}
				return keychainauth.AutoSetup()
			}); errSetup != nil {
				ui.Error("keychain-auth setup failed: " + errSetup.Error())
				fmt.Println()
				ui.Info("You can set it up manually:")
				ui.Info("  brew install The-17/tap/keychain-auth")
				ui.Info("  keychain-auth start")
				fmt.Println()
				return fmt.Errorf("keychain-auth is required for secure credentials storage")
			}

			err = keychainauth.Init()
		}
	}
	if err != nil {
		// If the binary is unregistered or hash changed (e.g. after rebuild or upgrade),
		// re-register and restart the daemon transparently.
		var denied *keychainauth.DaemonDeniedError
		errStr := err.Error()
		isClosedOrDenied := strings.Contains(errStr, "daemon closed connection immediately") ||
			strings.Contains(errStr, "connection closed by daemon") ||
			strings.Contains(errStr, "broken pipe") ||
			strings.Contains(errStr, "connection reset by peer") ||
			(errors.As(err, &denied) && (denied.IsUnregistered() || denied.IsHashMismatch()))

		if isClosedOrDenied {
			keychainauth.Close()

			if runtime.GOOS == "linux" {
				sudoCheck := exec.Command("sudo", "-n", "true")
				if err := sudoCheck.Run(); err != nil {
					fmt.Println("keychain-auth binary registration is required. Please authorize when prompted.")
					sudoVal := exec.Command("sudo", "-v")
					sudoVal.Stdin = os.Stdin
					sudoVal.Stdout = os.Stdout
					sudoVal.Stderr = os.Stderr
					_ = sudoVal.Run()
				}
			}

			_ = ui.Spinner("Registering agentsecrets binary with daemon...", func() error {
				_ = keychainauth.AutoSetup()
				return keychainauth.RestartDaemon()
			})
			err = keychainauth.Init()
		}
	}
	if err != nil {
		return fmt.Errorf("%s", keychainauth.UserMessage(err))
	}

	return nil
}

// keychainAuthMiddleware is a PersistentPreRunE that ensures both:
// 1. The keychain-auth connection is established
// 2. The user is authenticated (EnsureAuth)
func keychainAuthMiddleware(cmd *cobra.Command, args []string) error {
	if err := ensureDaemonInitialized(); err != nil {
		return err
	}
	return authService.EnsureAuth(cmd, args)
}

// daemonOnlyMiddleware is a PersistentPreRunE that ensures the keychain-auth daemon
// connection is established (without requiring user authentication first).
// Used by bootstrap/login/logout flow.
func daemonOnlyMiddleware(cmd *cobra.Command, args []string) error {
	return ensureDaemonInitialized()
}
