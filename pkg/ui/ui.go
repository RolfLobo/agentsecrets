// Package ui provides centralized styling and output helpers for the CLI.
//
// Uses charmbracelet/lipgloss for styled terminal output.
// All commands import this package for consistent branding.
package ui

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

// CLIVersion is the version of the CLI tool, dynamically set on start.
var CLIVersion = "dev"

// Brand colors
var (
	PrimaryColor = lipgloss.Color("#00C6A5") // Brand Teal Accent
	Secondary    = lipgloss.Color("#5EEAD4") // Teal 300 — readable highlight
	SuccessColor = lipgloss.Color("#34D399") // Emerald
	ErrorColor   = lipgloss.Color("#F87171") // Red 400
	WarningColor = lipgloss.Color("#FBBF24") // Amber 400
	Dim          = lipgloss.Color("#6B7280") // Gray 500
	White        = lipgloss.Color("#F9FAFB") // Gray 50
	DimText      = lipgloss.Color("#9CA3AF") // Gray 400
	FaintBorder  = lipgloss.Color("#1F2937") // Gray 800
)

// Reusable styles
var (
	BrandStyle = lipgloss.NewStyle().
			Foreground(PrimaryColor).
			Bold(true)

	SuccessStyle = lipgloss.NewStyle().
			Foreground(SuccessColor).
			Bold(true)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(ErrorColor).
			Bold(true)

	WarningStyle = lipgloss.NewStyle().
			Foreground(WarningColor).
			Bold(true)

	DimStyle = lipgloss.NewStyle().
			Foreground(Dim)

	LabelStyle = lipgloss.NewStyle().
			Foreground(DimText)

	ValueStyle = lipgloss.NewStyle().
			Foreground(White).
			Bold(true)

	// Banner for init/welcome screens
	BannerStyle = lipgloss.NewStyle().
			Foreground(PrimaryColor).
			Bold(true).
			MarginBottom(1)

	// Status key-value pair styling
	KeyStyle = lipgloss.NewStyle().
			Foreground(DimText).
			Width(20)

	ValStyle = lipgloss.NewStyle().
			Foreground(White)

	// Divider
	DividerStyle = lipgloss.NewStyle().
			Foreground(Dim)
)

// Success prints a green success message with an asterisk.
func Success(msg string) {
	fmt.Println(SuccessStyle.Render("* " + msg))
}

// Error prints a red error message with an x.
func Error(msg string) {
	fmt.Println(ErrorStyle.Render("x " + msg))
}

// Warning prints a yellow warning message.
func Warning(msg string) {
	fmt.Println(WarningStyle.Render("! " + msg))
}

// Info prints a dimmed info message.
func Info(msg string) {
	fmt.Println(DimStyle.Render(msg))
}

// ErrorWithSuggestions prints an error message and a bulleted list of helpful suggestions.
func ErrorWithSuggestions(err error, suggestions ...string) {
	fmt.Println(ErrorStyle.Render("x " + err.Error()))

	// Dynamically resolve additional helpful suggestions based on common error patterns
	errStr := strings.ToLower(err.Error())
	dynamicSuggestions := make([]string, 0, len(suggestions)+3)

	// Add user-provided suggestions first
	dynamicSuggestions = append(dynamicSuggestions, suggestions...)

	// Skip dynamic suggestions for Cobra CLI parsing errors which might accidentally match keywords (like 'login' in 'Did you mean')
	if !strings.Contains(errStr, "unknown command") && !strings.Contains(errStr, "unknown flag") {
		if strings.Contains(errStr, "status 401") || strings.Contains(errStr, "unauthorized") {
			dynamicSuggestions = append(dynamicSuggestions,
				"Your active session may have expired. Try logging in again: 'agentsecrets login'.",
				"Verify that you are targeting the correct workspace.",
			)
		}
		if strings.Contains(errStr, "logged in") || strings.Contains(errStr, "login") || strings.Contains(errStr, "not authenticated") {
			dynamicSuggestions = append(dynamicSuggestions,
				"Run 'agentsecrets login' to authenticate your current terminal session.",
				"If you do not have an account yet, run 'agentsecrets init' to create one.",
			)
		}
		if strings.Contains(errStr, "status 403") || strings.Contains(errStr, "forbidden") {
			dynamicSuggestions = append(dynamicSuggestions,
				"You might not have sufficient permissions (Admin or Owner role) to perform this action.",
				"Check your role assignment in this workspace: 'agentsecrets workspace members'.",
			)
		}
		if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "no such host") || strings.Contains(errStr, "timeout") {
			dynamicSuggestions = append(dynamicSuggestions,
				"Verify that you have an active internet connection.",
				"Ensure the backend API service is reachable and not blocked by your firewall or proxy.",
			)
		}
		if strings.Contains(errStr, "not found") {
			dynamicSuggestions = append(dynamicSuggestions,
				"Verify the secret name is spelled correctly (keys are case-sensitive).",
				"Ensure you are working in the correct environment (run 'agentsecrets env switch').",
				"Sync your workspace by running 'agentsecrets secrets pull' or 'agentsecrets secrets push'.",
			)
		} else if strings.Contains(errStr, "keychain-auth denied") || strings.Contains(errStr, "unregistered_binary") {
			dynamicSuggestions = append(dynamicSuggestions,
				"This binary is not approved to access your secrets.",
				"Run 'agentsecrets' in your terminal to trigger the auto-approval setup flow.",
			)
		} else if strings.Contains(errStr, "keyring") || strings.Contains(errStr, "keychain") || strings.Contains(errStr, "secret service") || strings.Contains(errStr, "dbus") {
			dynamicSuggestions = append(dynamicSuggestions,
				"Verify that your OS Keychain / Credential Manager is unlocked.",
				"For SSH/headless Linux environments, configure dbus or gnome-keyring properly.",
			)
		}
		if strings.Contains(errStr, "status 500") {
			dynamicSuggestions = append(dynamicSuggestions,
				"This indicates an internal server error on the AgentSecrets API service.",
				"Please report this by emailing engineering@theseventeen.co with the template below.",
			)
		}
	}

	if len(dynamicSuggestions) > 0 {
		fmt.Println()
		fmt.Println(BrandStyle.Render("💡 Actionable suggestions to resolve this:"))
		for _, s := range dynamicSuggestions {
			fmt.Println(DimStyle.Render(fmt.Sprintf("  • %s", s)))
		}
	}

	if strings.Contains(errStr, "status 500") {
		cmdStr := scrubCmdArgs(os.Args)
		nowStr := time.Now().UTC().Format(time.RFC3339)
		fmt.Println(BrandStyle.Render("📋 Copy-paste report for engineering@theseventeen.co:"))
		fmt.Println(DimStyle.Render("--------------------------------------------------"))
		fmt.Printf("Command Run: %s\n", cmdStr)
		fmt.Printf("CLI Version: %s\n", CLIVersion)
		fmt.Printf("Timestamp:   %s\n", nowStr)
		fmt.Printf("Error:       %s\n", err.Error())
		fmt.Printf("Platform:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Println(DimStyle.Render("--------------------------------------------------"))
		fmt.Println()
	}
}

func scrubCmdArgs(args []string) string {
	scrubbed := make([]string, len(args))
	copy(scrubbed, args)

	isSecretsSet := false
	for i, arg := range args {
		lower := strings.ToLower(arg)
		if lower == "set" && i > 0 && strings.ToLower(args[i-1]) == "secrets" {
			isSecretsSet = true
			break
		}
	}

	if isSecretsSet {
		for i, arg := range scrubbed {
			if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				scrubbed[i] = parts[0] + "=[REDACTED]"
			}
		}
	}

	return strings.Join(scrubbed, " ")
}

// SuccessWithSuggestions prints a success message and a list of next steps.
func SuccessWithSuggestions(msg string, nextSteps ...string) {
	fmt.Println(SuccessStyle.Render("* " + msg))
	if len(nextSteps) > 0 {
		fmt.Println()
		fmt.Println(BrandStyle.Render("➡️ Next steps you can take:"))
		for _, step := range nextSteps {
			fmt.Println(DimStyle.Render(fmt.Sprintf("  • %s", step)))
		}
		fmt.Println()
	}
}

// Brand prints text in the brand teal color.
func Brand(msg string) string {
	return BrandStyle.Render(msg)
}

// StatusRow prints a key-value pair for status output.
func StatusRow(key, value string) {
	fmt.Printf("  %s %s\n", KeyStyle.Render(key), ValStyle.Render(value))
}

// StatusRowDim prints a key-value pair with dimmed value.
func StatusRowDim(key, value string) {
	fmt.Printf("  %s %s\n", KeyStyle.Render(key), DimStyle.Render(value))
}

// Divider prints a styled horizontal line.
func Divider() {
	fmt.Println(DividerStyle.Render("  ──────────────────────────────"))
}

// Banner prints a styled banner heading.
func Banner(text string) {
	fmt.Println(BannerStyle.Render(text))
}

// BannerStr returns a styled banner heading as a string.
func BannerStr(text string) string {
	return BannerStyle.Render(text)
}

// RenderTable returns a styled table as a string.
func RenderTable(headers []string, rows [][]string) string {
	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(FaintBorder)).
		Headers(headers...).
		Rows(rows...)

	// Style headers and rows
	t.StyleFunc(func(row, col int) lipgloss.Style {
		style := lipgloss.NewStyle().Padding(0, 1).Align(lipgloss.Left)
		if row == 0 {
			style = style.Foreground(PrimaryColor).Bold(true)
		}
		return style
	})

	return t.Render()
}
