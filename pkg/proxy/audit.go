package proxy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	_ "github.com/glebarez/go-sqlite"
	"github.com/google/uuid"
)

// AuditEvent records a single proxied API call.
// Secret KEY NAMES are logged. Secret VALUES are NEVER logged.
type AuditEvent struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Environment    string    `json:"environment,omitempty"` // "development", "staging", "production"
	SecretKeys     []string  `json:"secret_keys"`           // KEY NAMES e.g. ["STRIPE_SECRET_KEY"]
	AgentID        string    `json:"agent_id,omitempty"`    // from agent identification
	IdentityLevel  string    `json:"identity_level"`        // "anonymous", "declared", "issued"
	Method         string    `json:"method"`
	TargetURL      string    `json:"target_url"`
	Domain         string    `json:"domain,omitempty"` // Target domain (e.g. "api.stripe.com")
	AuthStyles     []string  `json:"auth_styles"`      // e.g. ["bearer"]
	StatusCode     int       `json:"status_code"`
	DurationMs     int64     `json:"duration_ms"`
	Status         string    `json:"status"`           // "OK" or "BLOCKED"
	Reason         string    `json:"reason,omitempty"` // "domain_not_in_allowlist" or "-"
	Redacted       bool      `json:"redacted"`
	ResolutionPath string    `json:"resolution_path"`       // e.g. "local proxy", "cloud"
	CallerRole     string    `json:"caller_role,omitempty"` // e.g. "member"
	WorkspaceID    string    `json:"workspace_id,omitempty"`
	ProjectID      string    `json:"project_id,omitempty"`
	TokenID        string    `json:"token_id,omitempty"`
}

type ForensicAuditEvent struct {
	ID          string           `json:"id"`
	Version     string           `json:"version"`
	CreatedAt   time.Time        `json:"created_at"`
	WorkspaceID string           `json:"workspace_id"`
	ProjectID   string           `json:"project_id"`
	Event       EventBlock       `json:"event"`
	Snapshot    SnapshotBlock    `json:"snapshot"`
	Enforcement EnforcementBlock `json:"enforcement"`
	Resolution  ResolutionBlock  `json:"resolution"`
	ChainHash   string           `json:"chain_hash"`
}

type EventBlock struct {
	Type          string         `json:"type"` // "proxy_call"
	KeyName       string         `json:"key_name"`
	Domain        string         `json:"domain"`
	Path          string         `json:"path"`
	Method        string         `json:"method"`
	StatusCode    int            `json:"status_code"`
	Outcome       string         `json:"outcome"`
	LatencyMs     int64          `json:"latency_ms"`
	AgentIdentity *AgentIdentity `json:"agent_identity,omitempty"`
	Environment   string         `json:"environment"`
	SecContractID string         `json:"sec_contract_id,omitempty"`
}

type AgentIdentity struct {
	TokenName       string `json:"token_name"`
	TokenID         string `json:"token_id"`
	IdentityLevel   string `json:"identity_level"`
	ProcessVerified bool   `json:"process_verified"`
}

type SnapshotBlock struct {
	CapturedAt        time.Time             `json:"captured_at"`
	Workspace         WorkspaceSnapshot     `json:"workspace"`
	Project           ProjectSnapshot       `json:"project"`
	SecretsInScope    []string              `json:"secrets_in_scope"`
	SecretsCount      int                   `json:"secrets_count"`
	AgentCapabilities *CapabilitiesSnapshot `json:"agent_capabilities,omitempty"`
	SecretsPolicy     *PolicySnapshot       `json:"secrets_policy,omitempty"`
	KeychainAuth      KeychainAuthSnapshot  `json:"keychain_auth"`
	Proxy             ProxySnapshot         `json:"proxy"`
}

type WorkspaceSnapshot struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Allowlist      []string `json:"allowlist"`
	AllowlistCount int      `json:"allowlist_count"`
}

type ProjectSnapshot struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Environment string `json:"environment"`
}

type CapabilitiesSnapshot struct {
	TokenName       string   `json:"token_name"`
	AllowedProjects []string `json:"allowed_projects"`
	AllowedSecrets  []string `json:"allowed_secrets"`
	Scopes          []string `json:"scopes"`
}

type PolicySnapshot struct {
	KeyName         string   `json:"key_name"`
	AllowedDomains  []string `json:"allowed_domains"`
	AllowedMethods  []string `json:"allowed_methods"`
	ViolationAction string   `json:"violation_action"`
	PolicyVersion   string   `json:"policy_version"`
}

type KeychainAuthSnapshot struct {
	Authenticated       bool `json:"authenticated"`
	ProcessHashVerified bool `json:"process_hash_verified"`
	SessionBound        bool `json:"session_bound"`
}

type ProxySnapshot struct {
	Version   string `json:"version"`
	Port      int    `json:"port"`
	Transient bool   `json:"transient"`
}

type EnforcementBlock struct {
	Decision          string            `json:"decision"` // "permitted" | "blocked" | ...
	DecidedBy         string            `json:"decided_by"`
	LayersEvaluated   []EvaluationLayer `json:"layers_evaluated"`
	FirstFailureLayer string            `json:"first_failure_layer,omitempty"`
}

type EvaluationLayer struct {
	Layer          string `json:"layer"` // "agent_capabilities" | "workspace_allowlist" | "secrets_policy"
	Result         string `json:"result"` // "pass" | "fail"
	Reason         string `json:"reason"`
	ActionRequired string `json:"action_required,omitempty"`
}

type ResolutionBlock struct {
	CredentialInjected bool   `json:"credential_injected"`
	InjectionStyle     string `json:"injection_style,omitempty"`
	ResponseScanned    bool   `json:"response_scanned"`
	RedactionTriggered bool   `json:"redaction_triggered"`
	RedactionPattern   string `json:"redaction_pattern,omitempty"`
	RedactedField      string `json:"redacted_field,omitempty"`
	Replacement        string `json:"replacement,omitempty"`
	SSRFCheckPassed    bool   `json:"ssrf_check_passed"`
	ResponseStatus     int    `json:"response_status"`
}

// AuditLogger writes AuditEvents to a local SQLite database and syncs them to the cloud.
type AuditLogger struct {
	db        *sql.DB
	APIClient *api.Client
	mu        sync.Mutex
}

// DefaultLogPath returns the default audit database path: ~/.agentsecrets/audit.db
func DefaultLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".agentsecrets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create config directory: %w", err)
	}
	return filepath.Join(dir, "audit.db"), nil
}

// NewAuditLogger creates an audit logger that connects to a local SQLite database.
func NewAuditLogger(dbPath string) (*AuditLogger, error) {
	if dbPath == "" {
		var err error
		dbPath, err = DefaultLogPath()
		if err != nil {
			return nil, err
		}
	}

	// Connect to SQLite
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	if flag.Lookup("test.v") != nil {
		_, _ = db.Exec("PRAGMA journal_mode=DELETE;")
		_, _ = db.Exec("PRAGMA synchronous=OFF;")
	} else {
		_, _ = db.Exec("PRAGMA journal_mode=WAL;")
		_, _ = db.Exec("PRAGMA synchronous=NORMAL;")
	}

	// Create table if it doesn't exist
	schemaTable := `
	CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL,
		environment TEXT,
		agent_id TEXT,
		identity_level TEXT,
		method TEXT,
		target_url TEXT,
		domain TEXT,
		status_code INTEGER,
		duration_ms INTEGER,
		status TEXT,
		reason TEXT,
		redacted BOOLEAN,
		resolution_path TEXT,
		caller_role TEXT,
		workspace_id TEXT,
		project_id TEXT,
		token_id TEXT,
		secret_keys TEXT,
		auth_styles TEXT,
		synced BOOLEAN DEFAULT 0
	);`
	if _, err := db.Exec(schemaTable); err != nil {
		return nil, fmt.Errorf("failed to initialize table: %w", err)
	}

	schemaForensic := `
	CREATE TABLE IF NOT EXISTS forensic_audit_events (
		id TEXT PRIMARY KEY,
		version TEXT,
		created_at DATETIME NOT NULL,
		workspace_id TEXT,
		project_id TEXT,
		environment TEXT,
		agent_id TEXT,
		token_id TEXT,
		domain TEXT,
		method TEXT,
		status_code INTEGER,
		outcome TEXT,
		latency_ms INTEGER,
		chain_hash TEXT,
		event_json TEXT,
		snapshot_json TEXT,
		enforcement_json TEXT,
		resolution_json TEXT,
		synced BOOLEAN DEFAULT 0
	);`
	if _, err := db.Exec(schemaForensic); err != nil {
		return nil, fmt.Errorf("failed to initialize forensic table: %w", err)
	}

	schemaForensicIndexes := `
	CREATE INDEX IF NOT EXISTS idx_forensic_created_at ON forensic_audit_events(created_at);
	CREATE INDEX IF NOT EXISTS idx_forensic_outcome ON forensic_audit_events(outcome);
	CREATE INDEX IF NOT EXISTS idx_forensic_domain ON forensic_audit_events(domain);
	`
	if _, err := db.Exec(schemaForensicIndexes); err != nil {
		return nil, fmt.Errorf("failed to initialize forensic indexes: %w", err)
	}

	// Apply schema migrations for older databases
	// SQLite ignores the error if the column already exists (or we just discard it)
	columns := []string{
		"environment",
		"agent_id",
		"identity_level",
		"workspace_id",
		"project_id",
		"token_id",
		"caller_role",
		"synced",
	}
	for _, col := range columns {
		var query string
		if col == "synced" {
			query = "ALTER TABLE audit_events ADD COLUMN synced BOOLEAN DEFAULT 0;"
		} else {
			query = fmt.Sprintf("ALTER TABLE audit_events ADD COLUMN %s TEXT;", col)
		}
		_, _ = db.Exec(query) // intentionally ignore error
	}

	schemaIndexes := `
	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id);
	CREATE INDEX IF NOT EXISTS idx_audit_domain ON audit_events(domain);
	CREATE INDEX IF NOT EXISTS idx_audit_environment ON audit_events(environment);
	`
	if _, err := db.Exec(schemaIndexes); err != nil {
		return nil, fmt.Errorf("failed to initialize indexes: %w", err)
	}

	return &AuditLogger{db: db}, nil
}

// Log writes a single audit event to the SQLite database.
func (a *AuditLogger) Log(event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if event.ID == "" {
		event.ID = "log_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	}

	keysJSON, _ := json.Marshal(event.SecretKeys)
	stylesJSON, _ := json.Marshal(event.AuthStyles)

	query := `
	INSERT INTO audit_events (
		id, timestamp, environment, agent_id, identity_level, method, target_url, 
		domain, status_code, duration_ms, status, reason, redacted, 
		resolution_path, caller_role, workspace_id, project_id, token_id, 
		secret_keys, auth_styles
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := a.db.ExecContext(context.Background(), query,
		event.ID,
		event.Timestamp.UTC(), // Important standard for SQLite
		event.Environment,
		event.AgentID,
		event.IdentityLevel,
		event.Method,
		event.TargetURL,
		event.Domain,
		event.StatusCode,
		event.DurationMs,
		event.Status,
		event.Reason,
		event.Redacted,
		event.ResolutionPath,
		event.CallerRole,
		event.WorkspaceID,
		event.ProjectID,
		event.TokenID,
		string(keysJSON),
		string(stylesJSON),
	)

	return err
}

// SyncUnpushedLogs reads unsynced events from the database, pushes them to the cloud API,
// and marks them as synced if successful.
func (a *AuditLogger) SyncUnpushedLogs() error {
	if a.APIClient == nil {
		return nil // Cloud sync is not configured
	}
	if !config.IsAuthenticated() {
		return nil // Skip syncing if user has no active session
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	var payload []map[string]interface{}
	var legacyIDs []string
	var forensicIDs []string

	// 1. Fetch legacy audit events
	rowsLegacy, err := a.db.Query(`
		SELECT id, timestamp, environment, agent_id, identity_level, method, target_url,
		       domain, status_code, duration_ms, status, reason, redacted, resolution_path,
		       caller_role, workspace_id, project_id, token_id, secret_keys, auth_styles
		FROM audit_events
		WHERE synced = 0
		LIMIT 100
	`)
	if err == nil {
		defer rowsLegacy.Close()
		for rowsLegacy.Next() {
			var e AuditEvent
			var keysJSON, stylesJSON string
			var ts time.Time

			err := rowsLegacy.Scan(
				&e.ID, &ts, &e.Environment, &e.AgentID, &e.IdentityLevel, &e.Method, &e.TargetURL,
				&e.Domain, &e.StatusCode, &e.DurationMs, &e.Status, &e.Reason, &e.Redacted, &e.ResolutionPath,
				&e.CallerRole, &e.WorkspaceID, &e.ProjectID, &e.TokenID, &keysJSON, &stylesJSON,
			)
			if err != nil {
				continue // skip broken rows
			}

			e.Timestamp = ts
			json.Unmarshal([]byte(keysJSON), &e.SecretKeys)
			json.Unmarshal([]byte(stylesJSON), &e.AuthStyles)

			targetPath := ""
			if u, err := url.Parse(e.TargetURL); err == nil {
				targetPath = u.Path
			}

			mapped := map[string]interface{}{
				"id":               e.ID,
				"schema_version":   1,
				"timestamp":        e.Timestamp.UTC().Format(time.RFC3339Nano),
				"environment":      e.Environment,
				"workspace_id":     e.WorkspaceID,
				"project_id":       e.ProjectID,
				"agent_id":         e.AgentID,
				"token_id":         e.TokenID,
				"identity_level":   e.IdentityLevel,
				"credential_ref":   strings.Join(e.SecretKeys, ","),
				"injection_style":  strings.Join(e.AuthStyles, ","),
				"target_domain":    e.Domain,
				"target_url":       e.TargetURL,
				"target_path":      targetPath,
				"method":           e.Method,
				"status_code":      e.StatusCode,
				"duration_ms":      e.DurationMs,
				"redacted":         e.Redacted,
				"resolution_path":  e.ResolutionPath,
				"caller_role":      e.CallerRole,
			}
			payload = append(payload, mapped)
			legacyIDs = append(legacyIDs, e.ID)
		}
	}

	// 2. Fetch forensic audit events
	rowsForensic, err := a.db.Query(`
		SELECT id, version, created_at, workspace_id, project_id, environment, agent_id, 
		       token_id, domain, method, status_code, outcome, latency_ms, chain_hash,
		       event_json, snapshot_json, enforcement_json, resolution_json
		FROM forensic_audit_events
		WHERE synced = 0
		LIMIT 100
	`)
	if err == nil {
		defer rowsForensic.Close()
		for rowsForensic.Next() {
			var fe ForensicAuditEvent
			var eventJSON, snapshotJSON, enforcementJSON, resolutionJSON string
			var workspaceID, projectID, environment, agentID, tokenID, domain, method, outcome, chainHash sql.NullString
			var createdAt time.Time

			err := rowsForensic.Scan(
				&fe.ID,
				&fe.Version,
				&createdAt,
				&workspaceID,
				&projectID,
				&environment,
				&agentID,
				&tokenID,
				&domain,
				&method,
				&fe.Event.StatusCode,
				&outcome,
				&fe.Event.LatencyMs,
				&chainHash,
				&eventJSON,
				&snapshotJSON,
				&enforcementJSON,
				&resolutionJSON,
			)
			if err != nil {
				continue // skip broken rows
			}

			fe.CreatedAt = createdAt
			if workspaceID.Valid {
				fe.WorkspaceID = workspaceID.String
			}
			if projectID.Valid {
				fe.ProjectID = projectID.String
			}

			_ = json.Unmarshal([]byte(eventJSON), &fe.Event)
			_ = json.Unmarshal([]byte(snapshotJSON), &fe.Snapshot)
			_ = json.Unmarshal([]byte(enforcementJSON), &fe.Enforcement)
			_ = json.Unmarshal([]byte(resolutionJSON), &fe.Resolution)

			var agID, tokID, identLevel string
			if fe.Event.AgentIdentity != nil {
				agID = fe.Event.AgentIdentity.TokenName
				tokID = fe.Event.AgentIdentity.TokenID
				identLevel = fe.Event.AgentIdentity.IdentityLevel
			} else {
				identLevel = "anonymous"
			}

			allowlistSnap := map[string]interface{}{
				"domains": fe.Snapshot.Workspace.Allowlist,
			}

			var policyID string
			if fe.Snapshot.SecretsPolicy != nil {
				policyID = fe.Snapshot.SecretsPolicy.PolicyVersion
			}

			var errorVal interface{}
			if fe.Event.Outcome == "blocked" {
				errorVal = map[string]interface{}{
					"decision":      fe.Enforcement.Decision,
					"decided_by":    fe.Enforcement.DecidedBy,
					"first_failure": fe.Enforcement.FirstFailureLayer,
				}
			}

			targetURL := "https://" + fe.Event.Domain + fe.Event.Path

			mapped := map[string]interface{}{
				"id":                 fe.ID,
				"schema_version":     2,
				"timestamp":          fe.CreatedAt.UTC().Format(time.RFC3339Nano),
				"environment":        fe.Event.Environment,
				"workspace_id":       fe.WorkspaceID,
				"project_id":         fe.ProjectID,
				"agent_id":           agID,
				"token_id":           tokID,
				"identity_level":     identLevel,
				"credential_ref":     fe.Event.KeyName,
				"injection_style":    fe.Resolution.InjectionStyle,
				"target_domain":      fe.Event.Domain,
				"target_url":         targetURL,
				"target_path":        fe.Event.Path,
				"method":             fe.Event.Method,
				"status_code":        fe.Event.StatusCode,
				"duration_ms":        fe.Event.LatencyMs,
				"proxy_duration_ms":  fe.Event.LatencyMs,
				"redacted":           fe.Resolution.RedactionTriggered,
				"redaction_reason":   fe.Resolution.RedactedField,
				"resolution_path":    "local proxy",
				"allowlist_snapshot": allowlistSnap,
				"policy_snapshot_id": policyID,
				"error":              errorVal,
			}
			payload = append(payload, mapped)
			forensicIDs = append(forensicIDs, fe.ID)
		}
	}

	if len(payload) == 0 {
		return nil
	}

	// 3. POST to Cloud Backend
	resp, err := a.APIClient.Call("audit.sync", "POST", payload, nil, nil)
	if err != nil {
		return fmt.Errorf("audit.sync API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("audit.sync returned status: %s", resp.Status)
	}

	// 4. Update sync status for standard logs
	if len(legacyIDs) > 0 {
		placeholders := make([]string, len(legacyIDs))
		args := make([]interface{}, len(legacyIDs))
		for i, id := range legacyIDs {
			placeholders[i] = "?"
			args[i] = id
		}
		query := fmt.Sprintf("UPDATE audit_events SET synced = 1 WHERE id IN (%s)", strings.Join(placeholders, ","))
		if _, err := a.db.Exec(query, args...); err != nil {
			return fmt.Errorf("failed to mark legacy audit logs as synced: %w", err)
		}
	}

	// 5. Update sync status for forensic logs
	if len(forensicIDs) > 0 {
		placeholders := make([]string, len(forensicIDs))
		args := make([]interface{}, len(forensicIDs))
		for i, id := range forensicIDs {
			placeholders[i] = "?"
			args[i] = id
		}
		query := fmt.Sprintf("UPDATE forensic_audit_events SET synced = 1 WHERE id IN (%s)", strings.Join(placeholders, ","))
		if _, err := a.db.Exec(query, args...); err != nil {
			return fmt.Errorf("failed to mark forensic audit logs as synced: %w", err)
		}
	}

	return nil
}

// Close closes the underlying database connection.
func (a *AuditLogger) Close() error {
	if a.db != nil {
		return a.db.Close()
	}
	return nil
}

// DB returns the underlying database for querying.
func (a *AuditLogger) DB() *sql.DB {
	return a.db
}

// LogForensic writes a forensic audit event with snapshot state and a cryptographic hash chain.
func (a *AuditLogger) LogForensic(event ForensicAuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if event.ID == "" {
		event.ID = "log_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	}
	if event.Version == "" {
		event.Version = "2"
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}

	// 1. Get previous entry's ID to compute the chain hash
	prevID := "genesis_block"
	var lastID string
	err := a.db.QueryRowContext(context.Background(),
		"SELECT id FROM forensic_audit_events ORDER BY created_at DESC, id DESC LIMIT 1",
	).Scan(&lastID)
	if err == nil && lastID != "" {
		prevID = lastID
	}

	// 2. Compute chain hash: sha256(prevID + currentID + created_at_RFC3339)
	tsStr := event.CreatedAt.Format(time.RFC3339Nano)
	h := sha256.New()
	h.Write([]byte(prevID + event.ID + tsStr))
	event.ChainHash = fmt.Sprintf("%x", h.Sum(nil))

	// 3. Marshal nested blocks to JSON strings
	eventJSON, _ := json.Marshal(event.Event)
	snapshotJSON, _ := json.Marshal(event.Snapshot)
	enforcementJSON, _ := json.Marshal(event.Enforcement)
	resolutionJSON, _ := json.Marshal(event.Resolution)

	var agentID, tokenID string
	if event.Event.AgentIdentity != nil {
		agentID = event.Event.AgentIdentity.TokenName
		tokenID = event.Event.AgentIdentity.TokenID
	}

	// 4. Insert into DB
	query := `
	INSERT INTO forensic_audit_events (
		id, version, created_at, workspace_id, project_id, environment, agent_id, 
		token_id, domain, method, status_code, outcome, latency_ms, chain_hash,
		event_json, snapshot_json, enforcement_json, resolution_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err = a.db.ExecContext(context.Background(), query,
		event.ID,
		event.Version,
		event.CreatedAt.UTC(),
		event.WorkspaceID,
		event.ProjectID,
		event.Event.Environment,
		agentID,
		tokenID,
		event.Event.Domain,
		event.Event.Method,
		event.Event.StatusCode,
		event.Event.Outcome,
		event.Event.LatencyMs,
		event.ChainHash,
		string(eventJSON),
		string(snapshotJSON),
		string(enforcementJSON),
		string(resolutionJSON),
	)
	return err
}

// LogManagementEvent logs a workspace management action to the local forensic database.
func LogManagementEvent(method, domain, path, userEmail, workspaceID, projectID, environment string) error {
	logger, err := NewAuditLogger("")
	if err != nil {
		return err
	}
	defer logger.Close()

	ev := ForensicAuditEvent{
		ID:          "log_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
		Version:     "2",
		CreatedAt:   time.Now().UTC(),
		WorkspaceID: workspaceID,
		ProjectID:   projectID,
		Event: EventBlock{
			Type:        "management",
			Domain:      domain,
			Path:        path,
			Method:      method,
			StatusCode:  200,
			Outcome:     "success",
			Environment: environment,
			AgentIdentity: &AgentIdentity{
				TokenName:     userEmail,
				IdentityLevel: "user",
			},
		},
		Enforcement: EnforcementBlock{
			Decision:  "permitted",
			DecidedBy: "local cli",
		},
		Resolution: ResolutionBlock{
			ResponseStatus: 200,
		},
	}

	if err := logger.LogForensic(ev); err != nil {
		return err
	}

	// Try to sync management events immediately to the cloud if we can authenticate
	if apiClient := auth.NewAuthenticatedClient(); apiClient != nil {
		logger.APIClient = apiClient
		_ = logger.SyncUnpushedLogs()
	}

	return nil
}

