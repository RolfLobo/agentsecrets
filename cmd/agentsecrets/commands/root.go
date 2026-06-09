package commands

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"errors"
	"fmt"
	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/telemetry"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/workspaces"
	"os"
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
	workspaceCmd.PersistentPreRunE = authService.EnsureAuth
	projectCmd.PersistentPreRunE = authService.EnsureAuth
	environmentCmd.PersistentPreRunE = authService.EnsureAuth
	proxyCmd.PersistentPreRunE = authService.EnsureAuth

	// Commands that read secrets or display sensitive info need auth verification.
	// The keychainAuthMiddleware (currently auth-only) handles this.
	secretsCmd.PersistentPreRunE = keychainAuthMiddleware
	callCmd.PersistentPreRunE = keychainAuthMiddleware
	statusCmd.PersistentPreRunE = keychainAuthMiddleware

	rootCmd.AddCommand(workspaceCmd)
	rootCmd.AddCommand(projectCmd)
	rootCmd.AddCommand(secretsCmd)
	rootCmd.AddCommand(agentCmd)
	rootCmd.AddCommand(logCmd)
	rootCmd.AddCommand(proxyCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(callCmd)
	rootCmd.AddCommand(environmentCmd)
	rootCmd.AddCommand(NewEnvCmd())
	rootCmd.AddCommand(NewExecCmd())
	rootCmd.AddCommand(docsCmd)
}

// keychainAuthMiddleware is a PersistentPreRunE that ensures both:
// 1. The user is authenticated (EnsureAuth)
// 2. A keychain-auth connection is established (keychainauth.Init)
//
// If keychain-auth is not installed or not running, it performs automatic
// setup with a spinner so the user never has to think about it.
func keychainAuthMiddleware(cmd *cobra.Command, args []string) error {
	// Step 1: Ensure the user is logged in
	if err := authService.EnsureAuth(cmd, args); err != nil {
		return err
	}

	// Step 2: Skip if connection already established (e.g. parent command already ran this)
	if keychainauth.IsInitialized() {
		return nil
	}

	// Step 3: If keychain-auth isn't available or we're not fully configured, run auto-setup with a spinner
	if !keychainauth.IsAvailable() || !keychainauth.IsFullyConfigured() {
		if err := ui.Spinner("Setting up keychain-auth...", func() error {
			return keychainauth.AutoSetup()
		}); err != nil {
			ui.Error("keychain-auth setup failed: " + err.Error())
			fmt.Println()
			ui.Info("You can set it up manually:")
			ui.Info("  brew install The-17/tap/keychain-auth")
			ui.Info("  keychain-auth start")
			fmt.Println()
			return fmt.Errorf("keychain-auth is required for secret operations")
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

			if errSetup := ui.Spinner("Setting up keychain-auth...", func() error {
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
				return fmt.Errorf("keychain-auth is required for secret operations")
			}

			err = keychainauth.Init()
		}
	}
	if err != nil {
		// If the binary is unregistered or hash changed (e.g. after rebuild or upgrade),
		// re-register and restart the daemon transparently.
		var denied *keychainauth.DaemonDeniedError
		if errors.As(err, &denied) && (denied.IsUnregistered() || denied.IsHashMismatch()) {
			keychainauth.Close()
			_ = keychainauth.AutoSetup()
			_ = keychainauth.RestartDaemon()
			err = keychainauth.Init()
		}
	}
	if err != nil {
		return fmt.Errorf("%s", keychainauth.UserMessage(err))
	}

	return nil
}
