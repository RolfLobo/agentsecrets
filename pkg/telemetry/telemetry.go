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
	"github.com/The-17/agentsecrets/pkg/config"
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
		}
		data.Daily[date] = d
	}

	// Capture current context
	if project, err := config.LoadProjectConfig(); err == nil && project != nil {
		d.ProjectID = project.ProjectID
	}
	if gc, err := config.LoadGlobalConfig(); err == nil && gc != nil {
		d.WorkspaceID = gc.SelectedWorkspaceID
		if gc.Email != "" {
			d.UserEmail = gc.Email
		}
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
		d.ActiveEnvironment = config.ResolveEnvironment()

		wsType := "personal"
		wsMemberCount := 1
		if gc, err := config.LoadGlobalConfig(); err == nil && gc != nil {
			if wsID := gc.SelectedWorkspaceID; wsID != "" {
				if ws, ok := gc.Workspaces[wsID]; ok {
					if ws.Type != "" {
						wsType = ws.Type
					}
					// Note: member count might not be in config, but we can try to guess or leave as 1
					// If we had it in config, we'd use it here.
				}
			}
		}
		d.WorkspaceType = wsType
		d.WorkspaceMemberCount = wsMemberCount

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
				"date":                   date,
				"command_executions":     dayData.CommandExecutions,
				"proxy_calls":            dayData.ProxyCalls,
				"proxy_blocked":          dayData.ProxyBlocked,
				"proxy_redacted":           dayData.ProxyRedacted,
				"secrets_resolved":         dayData.SecretsResolved,
				"total_proxy_duration_ms":   dayData.TotalProxyDurationMs,
				"injection_styles_used":    dayData.InjectionStylesUsed,
				"integrations_active":      dayData.IntegrationsActive,
				"cli_version":              dayData.CliVersion,
				"os":                     dayData.OS,
				"arch":                   dayData.Arch,
				"active_environment":     dayData.ActiveEnvironment,
				"project_secret_count":   dayData.ProjectSecretCount,
				"workspace_type":         dayData.WorkspaceType,
				"workspace_member_count": dayData.WorkspaceMemberCount,
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
