package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/workspaces"
)

var workspaceCmd = &cobra.Command{
	Use:   "workspace",
	Short: "Manage workspaces",
	Long: `List, switch, and create workspaces.
	Workspaces allow you to separate secrets for different teams or personal use.`,
	RunE: runWorkspaceList,
}

var workspaceSwitchCmd = &cobra.Command{
	Use:   "switch [name]",
	Short: "Switch active workspace",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runWorkspaceSwitch,
	ValidArgsFunction: autocompleteWorkspaces,
}

func init() {
	workspaceCmd.AddCommand(
		&cobra.Command{
			Use:     "list",
			Aliases: []string{"ls"},
			Short:   "List all workspaces",
			RunE:    runWorkspaceList,
		},
		workspaceSwitchCmd,
		&cobra.Command{
			Use:   "create [name]",
			Short: "Create a new workspace",
			Args:  cobra.MaximumNArgs(1),
			RunE:  runWorkspaceCreate,
		},
		&cobra.Command{
			Use:   "invite [email...] ",
			Short: "Invite one or more users to the current workspace",
			Args:  cobra.MinimumNArgs(0),
			RunE:  runWorkspaceInvite,
		},
		&cobra.Command{
			Use:   "members",
			Short: "List members of the current workspace",
			RunE:  runWorkspaceMembers,
		},
		&cobra.Command{
			Use:   "remove [email]",
			Short: "Remove a member from the workspace",
			Args:  cobra.ExactArgs(1),
			RunE:  runWorkspaceRemove,
		},
		&cobra.Command{
			Use:   "promote [email]",
			Short: "Promote a member to admin",
			Args:  cobra.ExactArgs(1),
			RunE:  runWorkspacePromote,
		},
		&cobra.Command{
			Use:   "demote [email]",
			Short: "Demote an admin to member",
			Args:  cobra.ExactArgs(1),
			RunE:  runWorkspaceDemote,
		},
	)
}

// requireConfig loads the global config and returns an error if the workspace
// list is empty, printing a helpful hint in that case.
func requireConfig() (*config.GlobalConfig, error) {
	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	if len(cfg.Workspaces) == 0 {
		ui.Info("No workspaces found. Run 'agentsecrets login' to sync.")
		return nil, nil // nil config signals "nothing to do"
	}
	return cfg, nil
}

// requireWorkspaceID returns the currently selected workspace ID or an error.
func requireWorkspaceID() (string, error) {
	id := config.GetSelectedWorkspaceID()
	if id == "" {
		return "", fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
	}
	return id, nil
}

// Handlers

func runWorkspaceList(_ *cobra.Command, _ []string) error {
	cfg, err := requireConfig()
	if err != nil || cfg == nil {
		return err
	}

	// Sort workspace IDs for consistent display order.
	ids := make([]string, 0, len(cfg.Workspaces))
	for id := range cfg.Workspaces {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	fmt.Println()
	ui.Banner("Workspaces")
	ui.Divider()

	for _, id := range ids {
		ws := cfg.Workspaces[id]

		marker := "  "
		if id == cfg.SelectedWorkspaceID {
			marker = ui.BrandStyle.Render("→ ")
		}

		wsType := ws.Type
		if wsType == "" {
			wsType = "shared"
		}

		fmt.Printf("%s %s %s\n", marker, ui.ValStyle.Render(ws.Name), ui.DimStyle.Render("("+wsType+")"))
	}

	fmt.Println()
	return nil
}

func runWorkspaceSwitch(_ *cobra.Command, args []string) error {
	cfg, err := requireConfig()
	if err != nil || cfg == nil {
		return err
	}

	var selectedID string

	if len(args) > 0 {
		// Name provided — find it directly.
		name := args[0]
		for id, ws := range cfg.Workspaces {
			if ws.Name == name || (name == "personal" && strings.EqualFold(ws.Type, "personal")) {
				selectedID = id
				break
			}
		}
		if selectedID == "" {
			return fmt.Errorf("workspace %q not found", name)
		}
	} else {
		// Build sorted option list for the interactive picker.
		options := make([]huh.Option[string], 0, len(cfg.Workspaces))
		for id, ws := range cfg.Workspaces {
			label := ws.Name
			if ws.Type == "shared" {
				label += " (shared)"
			}
			options = append(options, huh.NewOption(label, id))
		}
		sort.Slice(options, func(i, j int) bool { return options[i].Key < options[j].Key })

		if err := huh.NewSelect[string]().
			Title("Switch active workspace").
			Options(options...).
			Value(&selectedID).
			Run(); err != nil {
			return nil // user cancelled
		}
	}

	if err := config.SetSelectedWorkspaceID(selectedID); err != nil {
		return fmt.Errorf("failed to update active workspace: %w", err)
	}

	ui.Success(fmt.Sprintf("Switched to workspace: %s", cfg.Workspaces[selectedID].Name))
	return nil
}

func runWorkspaceCreate(_ *cobra.Command, args []string) error {
	name := firstArg(args)

	if name == "" {
		if err := huh.NewInput().
			Title("Workspace Name").
			Description("What should we call your new workspace?").
			Value(&name).
			Run(); err != nil {
			return nil // user cancelled
		}
	}

	if err := ui.Spinner(fmt.Sprintf("Creating workspace (%s)...", name), func() error {
		return workspaceService.Create(name)
	}); err != nil {
		return err
	}

	ui.Success(fmt.Sprintf("Workspace %s created and selected!", name))
	return nil
}

func runWorkspaceInvite(_ *cobra.Command, args []string) error {
	workspaceID, err := requireWorkspaceID()
	if err != nil {
		return err
	}

	// Hard-block invites to personal workspaces
	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if ws, ok := cfg.Workspaces[workspaceID]; ok && strings.EqualFold(ws.Type, "personal") {
		return fmt.Errorf("Cannot invite members to a personal workspace.\nUse 'agentsecrets project invite <email>' to collaborate on a specific project instead.")
	}

	var emails []string
	var role string

	if len(args) > 0 {
		// Emails provided via args
		emails = args
	} else {
		// Interactive: collect a single email
		var email string
		if err := huh.NewInput().
			Title("Invite Member").
			Description("Enter the email address to invite").
			Value(&email).
			Run(); err != nil {
			return nil
		}
		emails = []string{email}
	}

	// Select role for all invitees
	if err := huh.NewSelect[string]().
		Title("Select Role").
		Options(
			huh.NewOption("Member", "member"),
			huh.NewOption("Admin", "admin"),
		).
		Value(&role).
		Run(); err != nil {
		return nil
	}

	// Password confirmation — same pattern as allowlist
	if err := verifyPasswordLocally(); err != nil {
		return err
	}

	// Execute batch invite
	var results []workspaces.InviteResult
	spinnerMsg := fmt.Sprintf("Inviting %d member(s)...", len(emails))
	if len(emails) == 1 {
		spinnerMsg = fmt.Sprintf("Inviting %s...", emails[0])
	}

	if err := ui.Spinner(spinnerMsg, func() error {
		var e error
		results, e = workspaceService.InviteBatch(workspaceID, emails, role)
		return e
	}); err != nil {
		return err
	}

	// Report results
	hasSuccess := false
	for _, r := range results {
		if r.Error != "" {
			ui.Error(fmt.Sprintf("  ✗ %s — %s", r.Email, r.Error))
		} else {
			ui.Success(fmt.Sprintf("  ✓ %s invited", r.Email))
			hasSuccess = true
		}
	}

	if hasSuccess {
		fmt.Println()
		ui.Success("Invitation process completed!")
	} else {
		fmt.Println()
	}
	return nil
}

func runWorkspaceMembers(_ *cobra.Command, _ []string) error {
	workspaceID, err := requireWorkspaceID()
	if err != nil {
		return err
	}

	var members []workspaces.WorkspaceMember
	if err := ui.Spinner("Fetching members...", func() error {
		var e error
		members, e = workspaceService.Members(workspaceID)
		return e
	}); err != nil {
		return err
	}

	fmt.Println()
	ui.Banner("👥 Workspace Members")
	ui.Divider()

	for _, m := range members {
		status := ui.DimStyle.Render(m.Status)
		if m.Status == "active" {
			status = ui.BrandStyle.Render(m.Status)
		}
		fmt.Printf("  %s %s %s\n", ui.ValStyle.Render(m.Email), ui.LabelStyle.Render("("+m.Role+")"), status)
	}

	fmt.Println()
	return nil
}

func runWorkspaceRemove(_ *cobra.Command, args []string) error {
	email := args[0]

	workspaceID, err := requireWorkspaceID()
	if err != nil {
		return err
	}

	var confirmed bool
	if err := huh.NewConfirm().
		Title(fmt.Sprintf("Remove %s from workspace?", email)).
		Value(&confirmed).
		Run(); err != nil || !confirmed {
		return nil // user cancelled or declined
	}

	if err := ui.Spinner(fmt.Sprintf("Removing %s...", email), func() error {
		userID, err := getMemberUserID(workspaceID, email)
		if err != nil {
			return err
		}
		return workspaceService.RemoveMember(workspaceID, userID)
	}); err != nil {
		return err
	}

	ui.Success(fmt.Sprintf("Removed %s from workspace.", email))
	return nil
}

func getMemberUserID(workspaceID, email string) (string, error) {
	members, err := workspaceService.Members(workspaceID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch members: %w", err)
	}

	for _, m := range members {
		if strings.EqualFold(m.Email, email) {
			if m.UserID != "" {
				return m.UserID, nil
			}
			if m.ID != "" {
				return m.ID, nil
			}
		}
	}
	return "", fmt.Errorf("user is not a member of this workspace")
}

func runWorkspacePromote(_ *cobra.Command, args []string) error {
	email := args[0]

	workspaceID, err := requireWorkspaceID()
	if err != nil {
		return err
	}

	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := ui.Spinner(fmt.Sprintf("Promoting %s...", email), func() error {
		userID, err := getMemberUserID(workspaceID, email)
		if err != nil {
			return err
		}
		if err := workspaceService.UpdateRole(workspaceID, userID, "promote"); err != nil {
			if strings.Contains(err.Error(), "403") {
				return fmt.Errorf("only admins can change member roles")
			}
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	ui.Success(fmt.Sprintf("%s is now an admin of %s", email, cfg.Workspaces[workspaceID].Name))
	return nil
}

func runWorkspaceDemote(_ *cobra.Command, args []string) error {
	email := args[0]

	workspaceID, err := requireWorkspaceID()
	if err != nil {
		return err
	}

	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := ui.Spinner(fmt.Sprintf("Demoting %s...", email), func() error {
		userID, err := getMemberUserID(workspaceID, email)
		if err != nil {
			return err
		}
		if err := workspaceService.UpdateRole(workspaceID, userID, "demote"); err != nil {
			if strings.Contains(err.Error(), "403") {
				return fmt.Errorf("only admins can change member roles")
			}
			return err // Will display exactly the message from the API on 400
		}
		return nil
	}); err != nil {
		return err
	}

	ui.Success(fmt.Sprintf("%s is now a member of %s", email, cfg.Workspaces[workspaceID].Name))
	return nil
}

// firstArg returns args[0] or "" — saves nil-check boilerplate at every call site.
func firstArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}

func autocompleteWorkspaces(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cfg, err := config.LoadGlobalConfig()
	if err != nil || cfg == nil || len(cfg.Workspaces) == 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var completions []string
	for _, ws := range cfg.Workspaces {
		if strings.HasPrefix(strings.ToLower(ws.Name), strings.ToLower(toComplete)) {
			completions = append(completions, ws.Name)
		}
		// Also allow completing "personal"
		if strings.EqualFold(ws.Type, "personal") && strings.HasPrefix("personal", strings.ToLower(toComplete)) {
			completions = append(completions, "personal")
		}
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}
