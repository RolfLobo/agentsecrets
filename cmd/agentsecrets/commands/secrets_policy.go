package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/capabilities"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var (
	policyDomains []string
	policyMethods []string
	policyAction  string
)

var secretsPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage secret-level policies",
	Long:  `Define target constraints for individual secrets (allowed domains, allowed HTTP methods, and violation actions).`,
}

var secretsPolicySetCmd = &cobra.Command{
	Use:   "set <key>",
	Short: "Set a policy for a secret key",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsPolicySet,
}

var secretsPolicyGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get the policy for a secret key",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsPolicyGet,
}

var secretsPolicyDeleteCmd = &cobra.Command{
	Use:   "delete <key>",
	Short: "Delete/clear the policy for a secret key",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsPolicyDelete,
}

var secretsPolicyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secret policies in the current project",
	RunE:  runSecretsPolicyList,
}

func init() {
	secretsPolicySetCmd.Flags().StringSliceVar(&policyDomains, "domains", nil, "Comma-separated list of allowed domains (e.g. api.stripe.com)")
	secretsPolicySetCmd.Flags().StringSliceVar(&policyMethods, "methods", nil, "Comma-separated list of allowed HTTP methods (e.g. GET,POST)")
	secretsPolicySetCmd.Flags().StringVar(&policyAction, "action", "deny", "Violation action: deny or request_permission")

	secretsPolicySetCmd.ValidArgsFunction = autocompleteSecretKeys
	secretsPolicyGetCmd.ValidArgsFunction = autocompleteSecretKeys
	secretsPolicyDeleteCmd.ValidArgsFunction = autocompleteSecretKeys

	secretsPolicyCmd.AddCommand(
		secretsPolicySetCmd,
		secretsPolicyGetCmd,
		secretsPolicyDeleteCmd,
		secretsPolicyListCmd,
	)

	secretsCmd.AddCommand(secretsPolicyCmd)
}

func runSecretsPolicySet(cmd *cobra.Command, args []string) error {
	key := args[0]

	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured in current directory")
	}

	env := config.ResolveEnvironment()
	if env == "production" {
		if err := verifyPasswordLocally(); err != nil {
			return err
		}
	}

	// Validate action
	action := capabilities.Action(strings.ToLower(policyAction))
	if action != capabilities.Deny && action != capabilities.RequestPermission {
		return fmt.Errorf("invalid action %q — must be 'deny' or 'request_permission'", policyAction)
	}

	// Build method map
	methodsMap := make(map[string]capabilities.Action)
	for _, m := range policyMethods {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		parts := strings.SplitN(m, "=", 2)
		method := strings.ToUpper(strings.TrimSpace(parts[0]))

		act := action // default action
		if len(parts) == 2 {
			customAct := capabilities.Action(strings.ToLower(strings.TrimSpace(parts[1])))
			if customAct != capabilities.Allow && customAct != capabilities.Deny && customAct != capabilities.RequestPermission {
				return fmt.Errorf("invalid action %q for method %s — must be 'allow', 'deny', or 'request_permission'", parts[1], method)
			}
			act = customAct
		}
		methodsMap[method] = act
	}

	var domains []string
	for _, d := range policyDomains {
		domains = append(domains, strings.ToLower(strings.TrimSpace(d)))
	}

	policy := capabilities.SecretPolicy{
		Domains: domains,
		Methods: methodsMap,
	}

	policyBytes, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to serialize policy: %w", err)
	}

	if err := keyring.SetSecretPolicy(project.ProjectID, env, key, policyBytes); err != nil {
		return fmt.Errorf("failed to save secret policy to keyring: %w", err)
	}

	// Log management event
	cfg, _ := config.LoadGlobalConfig()
	_ = proxy.LogManagementEvent("UPDATE", "policy", fmt.Sprintf("Updated policy for secret %s", key), cfg.Email, project.WorkspaceID, project.ProjectID, env)

	ui.Success(fmt.Sprintf("Policy updated for secret %s", key))
	return nil
}

func runSecretsPolicyGet(cmd *cobra.Command, args []string) error {
	key := args[0]

	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured in current directory")
	}

	env := config.ResolveEnvironment()
	policyBytes, err := keyring.GetSecretPolicy(project.ProjectID, env, key)
	if err != nil {
		return fmt.Errorf("failed to retrieve policy: %w", err)
	}

	if len(policyBytes) == 0 {
		fmt.Printf("No policy configured for secret %s (unrestricted)\n", key)
		return nil
	}

	var policy capabilities.SecretPolicy
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		return fmt.Errorf("failed to parse policy: %w", err)
	}

	fmt.Printf("\nSecret Policy for %s:\n", key)
	if len(policy.Domains) > 0 {
		fmt.Printf("  Allowed Domains: %s\n", strings.Join(policy.Domains, ", "))
	} else {
		fmt.Println("  Allowed Domains: (any)")
	}

	if len(policy.Methods) > 0 {
		var methods []string
		for m, act := range policy.Methods {
			methods = append(methods, fmt.Sprintf("%s (%s)", m, act))
		}
		sort.Strings(methods)
		fmt.Printf("  Allowed Methods: %s\n", strings.Join(methods, ", "))
	} else {
		fmt.Println("  Allowed Methods: (any)")
	}
	fmt.Println()

	return nil
}

func runSecretsPolicyDelete(cmd *cobra.Command, args []string) error {
	key := args[0]

	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured in current directory")
	}

	env := config.ResolveEnvironment()
	if env == "production" {
		if err := verifyPasswordLocally(); err != nil {
			return err
		}
	}

	// Deleting the policy is setting it to nil
	if err := keyring.SetSecretPolicy(project.ProjectID, env, key, nil); err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	// Log management event
	cfg, _ := config.LoadGlobalConfig()
	_ = proxy.LogManagementEvent("DELETE", "policy", fmt.Sprintf("Deleted policy for secret %s", key), cfg.Email, project.WorkspaceID, project.ProjectID, env)

	ui.Success(fmt.Sprintf("Policy deleted for secret %s", key))
	return nil
}

func runSecretsPolicyList(cmd *cobra.Command, _ []string) error {
	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured in current directory")
	}

	env := config.ResolveEnvironment()

	keys, err := keyring.ListProjectKeyNames(project.ProjectID, env)
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	if len(keys) == 0 {
		ui.Info("No secrets found in this project.")
		return nil
	}

	type keyPolicy struct {
		Key     string
		Domains string
		Methods string
	}

	var list []keyPolicy
	for _, key := range keys {
		policyBytes, err := keyring.GetSecretPolicy(project.ProjectID, env, key)
		if err == nil && len(policyBytes) > 0 {
			var policy capabilities.SecretPolicy
			if err := json.Unmarshal(policyBytes, &policy); err == nil {
				domains := "(any)"
				if len(policy.Domains) > 0 {
					domains = strings.Join(policy.Domains, ", ")
				}
				methods := "(any)"
				if len(policy.Methods) > 0 {
					var mList []string
					for m, act := range policy.Methods {
						mList = append(mList, fmt.Sprintf("%s (%s)", m, act))
					}
					sort.Strings(mList)
					methods = strings.Join(mList, ", ")
				}
				list = append(list, keyPolicy{
					Key:     key,
					Domains: domains,
					Methods: methods,
				})
			}
		}
	}

	if len(list) == 0 {
		ui.Info("No secret-level policies configured in this project.")
		return nil
	}

	headers := []string{"Secret Key", "Allowed Domains", "Allowed Methods"}
	rows := make([][]string, len(list))
	for i, item := range list {
		rows[i] = []string{ui.BrandStyle.Render(item.Key), item.Domains, item.Methods}
	}

	fmt.Printf("\nSecret Policies for Environment: %s\n\n", ui.BrandStyle.Render(env))
	fmt.Println(ui.RenderTable(headers, rows))
	fmt.Println()

	return nil
}
