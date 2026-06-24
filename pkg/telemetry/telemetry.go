package telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
)

// Hook functions registered from other packages to avoid import cycles.
var (
	KeychainInitializedFunc func() bool
	LoadProjectIDFunc       func() string
	LoadGlobalConfigFunc    func() (string, string, string) // SelectedWorkspaceID, Email, WorkspaceType
	ResolveEnvironmentFunc  func() string
)

type Day struct {
	CommandExecutions   map[string]int `json:"command_executions"`
	ProxyCalls          int            `json:"proxy_calls"`
	ProxyBlocked        int            `json:"proxy_blocked"`
	ProxyRedacted        int            `json:"proxy_redacted"`
	SecretsResolved      int            `json:"secrets_resolved"`
	TotalProxyDurationMs int64          `json:"total_proxy_duration_ms"`
	InjectionStylesUsed  []string       `json:"injection_styles_used"`
	IntegrationsActive   []string       `json:"integrations_active"`

	// Snapshot metadata for the day
	CliVersion           string `json:"cli_version"`
	OS                   string `json:"os"`
	Arch                 string `json:"arch"`
	ActiveEnvironment    string `json:"active_environment"`
	UserEmail            string `json:"user_email,omitempty"`
	ProjectID            string `json:"project_id,omitempty"`
	WorkspaceID          string `json:"workspace_id,omitempty"`
	ProjectSecretCount   int    `json:"project_secret_count"`
	WorkspaceType        string `json:"workspace_type"`
	WorkspaceMemberCount int    `json:"workspace_member_count"`

	// Execution Path Breakdown
	ProxyCallsDaemon    int `json:"proxy_calls_daemon"`
	ProxyCallsTransient int `json:"proxy_calls_transient"`
	ProxyCallsMcp       int `json:"proxy_calls_mcp"`
	ProxyCallsDirect    int `json:"proxy_calls_direct"`
	DeveloperCommands   int `json:"developer_commands"`

	// Agentic Shielding
	SSRFAttemptsBlocked        int `json:"ssrf_attempts_blocked"`
	AllowlistViolations        int `json:"allowlist_violations"`
	ResponseRedactions         int `json:"response_redactions"`
	ProcessVerificationsFailed int `json:"process_verifications_failed"`
	ProductionWriteChallenges  int `json:"production_write_challenges"`

	// Latency & Performance
	KeychainResolutionMs int64 `json:"keychain_resolution_ms"`
	SessionRefreshMs     int64 `json:"session_refresh_ms"`

	// Onboarding & Friction
	InteractivePromptsShown   int `json:"interactive_prompts_shown"`
	InteractivePromptsSkipped int `json:"interactive_prompts_skipped"`
	DriftDiffsDetected        int `json:"drift_diffs_detected"`

	// Cryptographic Integrity
	LogChainVerifications int `json:"log_chain_verifications"`
	TamperingDetected     int `json:"tampering_detected"`

	// Node Metadata
	IsHeadlessNode      bool `json:"is_headless_node"`
	KeychainInitialized bool `json:"keychain_initialized"`

	// Typos
	Typos map[string]int `json:"typos"`

	// Agent Identity & Capabilities
	IdentityAnonymousCalls      int `json:"identity_anonymous_calls"`
	IdentityDeclaredCalls       int `json:"identity_declared_calls"`
	IdentityIssuedCalls         int `json:"identity_issued_calls"`
	CapabilityViolationsBlocked int `json:"capability_violations_blocked"`
	ProcessVerificationsPassed  int `json:"process_verifications_passed"`

	// Granular Error Categories
	ErrorsAuthCount     int `json:"errors_auth_count"`
	ErrorsKeychainCount int `json:"errors_keychain_count"`
	ErrorsSecretsCount  int `json:"errors_secrets_count"`
	ErrorsNetworkCount  int `json:"errors_network_count"`
	ErrorsSystemCount   int `json:"errors_system_count"`
	ErrorsUnknownCount  int `json:"errors_unknown_count"`
}

type Data struct {
	LastSync time.Time       `json:"last_sync"`
	Daily    map[string]*Day `json:"daily"`
}

var (
	mu   sync.Mutex
	data *Data
)

func telemetryFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".agentsecrets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "telemetry.json"), nil
}

func load() error {
	path, err := telemetryFilePath()
	if err != nil {
		return err
	}

	data = &Data{
		Daily:    make(map[string]*Day),
		LastSync: time.Now(),
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return json.Unmarshal(b, data)
}

func save() error {
	path, err := telemetryFilePath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func today() string {
	return time.Now().Format("2006-01-02")
}

func currentDay() *Day {
	if data == nil {
		_ = load()
	}
	if data.Daily == nil {
		data.Daily = make(map[string]*Day)
	}

	date := today()
	d, ok := data.Daily[date]
	if !ok {
		d = &Day{
			CommandExecutions:   make(map[string]int),
			InjectionStylesUsed: []string{},
			IntegrationsActive:  []string{},
			OS:                  runtime.GOOS,
			Arch:                runtime.GOARCH,
			Typos:               make(map[string]int),
		}
		data.Daily[date] = d
	}

	// Capture current context
	if LoadProjectIDFunc != nil {
		d.ProjectID = LoadProjectIDFunc()
	}
	if LoadGlobalConfigFunc != nil {
		wsID, email, wsType := LoadGlobalConfigFunc()
		d.WorkspaceID = wsID
		if email != "" {
			d.UserEmail = email
		}
		d.WorkspaceType = wsType
	}

	return d
}

// RecordCommand increments the usage count for a CLI command.
func RecordCommand(cmdName string) {
	mu.Lock()
	defer mu.Unlock()

	d := currentDay()
	if d.CommandExecutions == nil {
		d.CommandExecutions = make(map[string]int)
	}
	d.CommandExecutions[cmdName]++
	d.DeveloperCommands++
	_ = save()
}

// RecordProxyCall increments the total proxy call counter.
func RecordProxyCall() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ProxyCalls++
	_ = save()
}

// RecordProxyBlocked increments the blocked proxy request counter.
func RecordProxyBlocked() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ProxyBlocked++
	_ = save()
}

// RecordProxyRedacted increments the redacted proxy response counter.
func RecordProxyRedacted() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ProxyRedacted++
	currentDay().ResponseRedactions++
	_ = save()
}

// RecordSecretResolved increments the resolved secrets count.
func RecordSecretResolved() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().SecretsResolved++
	_ = save()
}

// RecordProxyDuration adds proxy latency to the cumulative duration.
func RecordProxyDuration(ms int64) {
	mu.Lock()
	defer mu.Unlock()
	currentDay().TotalProxyDurationMs += ms
	_ = save()
}

// RecordInjectionStyle records a unique injection style used (e.g. "bearer", "header").
func RecordInjectionStyle(style string) {
	mu.Lock()
	defer mu.Unlock()
	d := currentDay()
	for _, s := range d.InjectionStylesUsed {
		if s == style {
			return
		}
	}
	d.InjectionStylesUsed = append(d.InjectionStylesUsed, style)
	_ = save()
}

// RecordIntegration records a unique integration (e.g. "mcp", "env", "proxy", "exec").
func RecordIntegration(name string) {
	mu.Lock()
	defer mu.Unlock()
	d := currentDay()
	for _, n := range d.IntegrationsActive {
		if n == name {
			return
		}
	}
	d.IntegrationsActive = append(d.IntegrationsActive, name)
	_ = save()
}

// RecordSecretCount records the current number of secrets in the project.
func RecordSecretCount(count int) {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ProjectSecretCount = count
	_ = save()
}

// RecordWorkspaceMemberCount records the number of members in the workspace.
func RecordWorkspaceMemberCount(count int) {
	mu.Lock()
	defer mu.Unlock()
	currentDay().WorkspaceMemberCount = count
	_ = save()
}

// RecordProxyCallDaemon records a daemon proxy call.
func RecordProxyCallDaemon() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ProxyCallsDaemon++
	_ = save()
}

// RecordProxyCallTransient records a transient proxy call.
func RecordProxyCallTransient() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ProxyCallsTransient++
	_ = save()
}

// RecordProxyCallMcp records a proxy call from MCP.
func RecordProxyCallMcp() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ProxyCallsMcp++
	_ = save()
}

// RecordProxyCallDirect records a direct proxy call.
func RecordProxyCallDirect() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ProxyCallsDirect++
	_ = save()
}

// RecordSSRFAttemptsBlocked records a blocked SSRF attempt.
func RecordSSRFAttemptsBlocked() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().SSRFAttemptsBlocked++
	_ = save()
}

// RecordAllowlistViolation records an allowlist violation.
func RecordAllowlistViolation() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().AllowlistViolations++
	_ = save()
}

// RecordResponseRedaction records a response redaction event.
func RecordResponseRedaction() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ResponseRedactions++
	currentDay().ProxyRedacted++
	_ = save()
}

// RecordProcessVerificationsFailed records a process verification failure.
func RecordProcessVerificationsFailed() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ProcessVerificationsFailed++
	_ = save()
}

// RecordProductionWriteChallenge records a production write challenge.
func RecordProductionWriteChallenge() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ProductionWriteChallenges++
	_ = save()
}

// RecordKeychainResolutionMs adds time to cumulative keychain resolution latency.
func RecordKeychainResolutionMs(ms int64) {
	mu.Lock()
	defer mu.Unlock()
	currentDay().KeychainResolutionMs += ms
	_ = save()
}

// RecordSessionRefreshMs adds time to cumulative session refresh latency.
func RecordSessionRefreshMs(ms int64) {
	mu.Lock()
	defer mu.Unlock()
	currentDay().SessionRefreshMs += ms
	_ = save()
}

// RecordInteractivePromptShown records showing an interactive prompt.
func RecordInteractivePromptShown() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().InteractivePromptsShown++
	_ = save()
}

// RecordInteractivePromptSkipped records skipping an interactive prompt.
func RecordInteractivePromptSkipped() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().InteractivePromptsSkipped++
	_ = save()
}

// RecordDriftDiffsDetected adds to detected drift diffs.
func RecordDriftDiffsDetected(count int) {
	mu.Lock()
	defer mu.Unlock()
	currentDay().DriftDiffsDetected += count
	_ = save()
}

// RecordLogChainVerification records a log chain verification.
func RecordLogChainVerification() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().LogChainVerifications++
	_ = save()
}

// RecordTamperingDetected records a tampering alert.
func RecordTamperingDetected() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().TamperingDetected++
	_ = save()
}

// RecordIdentityAnonymousCall records an anonymous identity proxy call.
func RecordIdentityAnonymousCall() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().IdentityAnonymousCalls++
	_ = save()
}

// RecordIdentityDeclaredCall records a declared identity proxy call.
func RecordIdentityDeclaredCall() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().IdentityDeclaredCalls++
	_ = save()
}

// RecordIdentityIssuedCall records an issued identity proxy call.
func RecordIdentityIssuedCall() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().IdentityIssuedCalls++
	_ = save()
}

// RecordCapabilityViolationBlocked records a capability violation block.
func RecordCapabilityViolationBlocked() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().CapabilityViolationsBlocked++
	_ = save()
}

// RecordProcessVerificationsPassed records a process verification pass.
func RecordProcessVerificationsPassed() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ProcessVerificationsPassed++
	_ = save()
}

// RecordErrorAuth records an auth error.
func RecordErrorAuth() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ErrorsAuthCount++
	_ = save()
}

// RecordErrorKeychain records a keychain error.
func RecordErrorKeychain() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ErrorsKeychainCount++
	_ = save()
}

// RecordErrorSecrets records a secrets error.
func RecordErrorSecrets() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ErrorsSecretsCount++
	_ = save()
}

// RecordErrorNetwork records a network error.
func RecordErrorNetwork() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ErrorsNetworkCount++
	_ = save()
}

// RecordErrorSystem records a system error.
func RecordErrorSystem() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ErrorsSystemCount++
	_ = save()
}

// RecordErrorUnknown records an unknown error.
func RecordErrorUnknown() {
	mu.Lock()
	defer mu.Unlock()
	currentDay().ErrorsUnknownCount++
	_ = save()
}

// RecordTypo records a typo entry.
func RecordTypo(typo string) {
	mu.Lock()
	defer mu.Unlock()
	d := currentDay()
	if d.Typos == nil {
		d.Typos = make(map[string]int)
	}
	d.Typos[typo]++
	_ = save()
}

// SyncIfDue checks if 24 hours have passed and flushes telemetry to the cloud.
func SyncIfDue(client *api.Client, cliVersion string) {
	mu.Lock()
	defer mu.Unlock()

	if client == nil {
		return
	}

	if data == nil {
		_ = load()
	}

	if time.Since(data.LastSync) >= 24*time.Hour {
		if len(data.Daily) == 0 {
			data.LastSync = time.Now()
			_ = save()
			return
		}

		// Update metadata for today's bucket before syncing
		d := currentDay()
		d.CliVersion = cliVersion
		if ResolveEnvironmentFunc != nil {
			d.ActiveEnvironment = ResolveEnvironmentFunc()
		} else {
			d.ActiveEnvironment = "development"
		}
		if KeychainInitializedFunc != nil {
			d.KeychainInitialized = KeychainInitializedFunc()
		}

		wsType := "personal"
		wsMemberCount := 1 // default, can be recorded via RecordWorkspaceMemberCount
		if LoadGlobalConfigFunc != nil {
			_, _, wType := LoadGlobalConfigFunc()
			if wType != "" {
				wsType = wType
			}
		}
		d.WorkspaceType = wsType
		// Keep the recorded WorkspaceMemberCount if set, otherwise default to 1.
		if d.WorkspaceMemberCount == 0 {
			d.WorkspaceMemberCount = wsMemberCount
		}

		// Prepare snapshots
		var snapshots []map[string]interface{}
		var syncedDates []string
		currentDate := today()

		for date, dayData := range data.Daily {
			if date == currentDate {
				// Don't send incomplete telemetry for the current day
				continue
			}
			s := map[string]interface{}{
				"date":                         date,
				"command_executions":           dayData.CommandExecutions,
				"proxy_calls":                  dayData.ProxyCalls,
				"proxy_blocked":                dayData.ProxyBlocked,
				"proxy_redacted":               dayData.ProxyRedacted,
				"secrets_resolved":             dayData.SecretsResolved,
				"total_proxy_duration_ms":      dayData.TotalProxyDurationMs,
				"injection_styles_used":        dayData.InjectionStylesUsed,
				"integrations_active":          dayData.IntegrationsActive,
				"cli_version":                  dayData.CliVersion,
				"os":                           dayData.OS,
				"arch":                         dayData.Arch,
				"active_environment":           dayData.ActiveEnvironment,
				"project_secret_count":         dayData.ProjectSecretCount,
				"workspace_type":               dayData.WorkspaceType,
				"workspace_member_count":       dayData.WorkspaceMemberCount,
				"proxy_calls_daemon":           dayData.ProxyCallsDaemon,
				"proxy_calls_transient":        dayData.ProxyCallsTransient,
				"proxy_calls_mcp":              dayData.ProxyCallsMcp,
				"proxy_calls_direct":           dayData.ProxyCallsDirect,
				"developer_commands":           dayData.DeveloperCommands,
				"ssrf_attempts_blocked":        dayData.SSRFAttemptsBlocked,
				"allowlist_violations":          dayData.AllowlistViolations,
				"response_redactions":          dayData.ResponseRedactions,
				"process_verifications_failed": dayData.ProcessVerificationsFailed,
				"production_write_challenges":  dayData.ProductionWriteChallenges,
				"keychain_resolution_ms":       dayData.KeychainResolutionMs,
				"session_refresh_ms":           dayData.SessionRefreshMs,
				"interactive_prompts_shown":    dayData.InteractivePromptsShown,
				"interactive_prompts_skipped":  dayData.InteractivePromptsSkipped,
				"drift_diffs_detected":         dayData.DriftDiffsDetected,
				"log_chain_verifications":      dayData.LogChainVerifications,
				"tampering_detected":           dayData.TamperingDetected,
				"is_headless_node":             dayData.IsHeadlessNode,
				"keychain_initialized":         dayData.KeychainInitialized,
				"typos":                        dayData.Typos,
				"identity_anonymous_calls":     dayData.IdentityAnonymousCalls,
				"identity_declared_calls":      dayData.IdentityDeclaredCalls,
				"identity_issued_calls":        dayData.IdentityIssuedCalls,
				"capability_violations_blocked": dayData.CapabilityViolationsBlocked,
				"process_verifications_passed": dayData.ProcessVerificationsPassed,
				"errors_auth_count":            dayData.ErrorsAuthCount,
				"errors_keychain_count":        dayData.ErrorsKeychainCount,
				"errors_secrets_count":         dayData.ErrorsSecretsCount,
				"errors_network_count":         dayData.ErrorsNetworkCount,
				"errors_system_count":          dayData.ErrorsSystemCount,
				"errors_unknown_count":         dayData.ErrorsUnknownCount,
			}
			if dayData.UserEmail != "" {
				s["user_email"] = dayData.UserEmail
			}
			if dayData.ProjectID != "" {
				s["project_id"] = dayData.ProjectID
			}
			if dayData.WorkspaceID != "" {
				s["workspace_id"] = dayData.WorkspaceID
			}
			snapshots = append(snapshots, s)
			syncedDates = append(syncedDates, date)
		}

		if len(snapshots) == 0 {
			data.LastSync = time.Now()
			_ = save()
			return
		}

		payload := map[string]interface{}{
			"snapshots": snapshots,
		}

		// Temporarily override HTTP client timeout to 1.5 seconds for telemetry sync to prevent broken DNS/network hangs
		originalTimeout := client.HTTPClient.Timeout
		client.HTTPClient.Timeout = 1500 * time.Millisecond
		defer func() {
			client.HTTPClient.Timeout = originalTimeout
		}()

		// Fire off the API call synchronously to ensure it completes before CLI exits.
		resp, err := client.Call("telemetry.sync", "POST", payload, nil, nil)
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Success! Clear only the synced daily buckets
			for _, date := range syncedDates {
				delete(data.Daily, date)
			}
			data.LastSync = time.Now()
			_ = save()
		} else if err == nil && resp != nil {
			if decodeErr := client.DecodeError(resp); decodeErr != nil {
				fmt.Println("\n[DEBUG] Telemetry Sync Rejected by Backend:", decodeErr)
			}
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
}
