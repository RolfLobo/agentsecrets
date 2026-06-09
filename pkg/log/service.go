// Package log provides audit log querying for both local SQLite and remote API sources.
package log

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/proxy"
)

// Filter holds all options for querying audit logs.
type Filter struct {
	Agent       string
	Token       string
	Identity    string // "anonymous", "declared", "issued"
	Credential  string
	Domain      string
	Method      string
	Environment string // "development", "staging", "production"
	Status      int
	StatusClass string // "2xx", "4xx", "5xx", "error"
	Failed      bool
	Blocked     bool
	Redacted    bool
	ProjectID   string
	Since       time.Time
	Until       time.Time
	Limit       int
	Offset      int
}

// Service provides methods to query local and cloud audit logs.
type Service struct {
	client *api.Client
	db     *sql.DB
}

// NewService creates a new log service. If db is nil, it tries to connect to the default local SQLite DB.
func NewService(client *api.Client, db *sql.DB) (*Service, error) {
	if db == nil {
		logger, err := proxy.NewAuditLogger("")
		if err != nil {
			return nil, err
		}
		db = logger.DB()
	}
	return &Service{
		client: client,
		db:     db,
	}, nil
}

// Close closes the local database connection.
func (s *Service) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// mapForensicToLegacy maps a ForensicAuditEvent to the legacy AuditEvent structure.
func mapForensicToLegacy(fe proxy.ForensicAuditEvent) proxy.AuditEvent {
	var secretKeys []string
	if fe.Event.KeyName != "" {
		secretKeys = strings.Split(fe.Event.KeyName, ",")
	} else {
		secretKeys = []string{}
	}

	status := "OK"
	if fe.Event.Outcome == "blocked" {
		status = "BLOCKED"
	}

	reason := ""
	if fe.Enforcement.FirstFailureLayer != "" {
		reason = fe.Enforcement.FirstFailureLayer
	}
	if fe.Event.Outcome == "redacted" {
		reason = "credential_echo"
	}

	var authStyles []string
	if fe.Resolution.InjectionStyle != "" {
		authStyles = strings.Split(fe.Resolution.InjectionStyle, ",")
	} else {
		authStyles = []string{}
	}

	agentID := ""
	tokenID := ""
	identityLevel := "anonymous"
	if fe.Event.AgentIdentity != nil {
		agentID = fe.Event.AgentIdentity.TokenName
		tokenID = fe.Event.AgentIdentity.TokenID
		identityLevel = fe.Event.AgentIdentity.IdentityLevel
	}

	return proxy.AuditEvent{
		ID:             fe.ID,
		Timestamp:      fe.CreatedAt,
		Environment:    fe.Event.Environment,
		SecretKeys:     secretKeys,
		AgentID:        agentID,
		IdentityLevel:  identityLevel,
		Method:         fe.Event.Method,
		TargetURL:      "https://" + fe.Event.Domain + fe.Event.Path,
		Domain:         fe.Event.Domain,
		AuthStyles:     authStyles,
		StatusCode:     fe.Event.StatusCode,
		DurationMs:     fe.Event.LatencyMs,
		Status:         status,
		Reason:         reason,
		Redacted:       fe.Resolution.RedactionTriggered,
		ResolutionPath: "local proxy",
		WorkspaceID:    fe.WorkspaceID,
		ProjectID:      fe.ProjectID,
		TokenID:        tokenID,
	}
}

// QueryLocal fetches audit events from the local SQLite database.
func (s *Service) QueryLocal(f Filter) ([]proxy.AuditEvent, error) {
	// Query the forensic table by default
	forensics, err := s.QueryLocalForensic(f)
	if err != nil {
		// If query fails, fall back to querying the legacy table
		return s.queryLocalLegacy(f)
	}

	results := make([]proxy.AuditEvent, 0, len(forensics))
	for _, fe := range forensics {
		results = append(results, mapForensicToLegacy(fe))
	}
	return results, nil
}

// queryLocalLegacy fetches legacy audit events from the local SQLite database.
func (s *Service) queryLocalLegacy(f Filter) ([]proxy.AuditEvent, error) {
	query := "SELECT id, timestamp, COALESCE(environment, '') as environment, agent_id, identity_level, method, target_url, domain, status_code, duration_ms, status, reason, redacted, resolution_path, caller_role, workspace_id, project_id, token_id, secret_keys, auth_styles FROM audit_events WHERE 1=1"
	args := []interface{}{}

	if f.Agent != "" {
		if f.Agent == "anonymous" || f.Agent == "(anon)" || f.Agent == "(anonymous)" {
			query += " AND (agent_id = ? OR agent_id = '' OR agent_id IS NULL)"
			args = append(args, f.Agent)
		} else {
			query += " AND agent_id = ?"
			args = append(args, f.Agent)
		}
	}
	if f.Token != "" {
		query += " AND token_id = ?"
		args = append(args, f.Token)
	}
	if f.Identity != "" {
		if f.Identity == "anonymous" {
			query += " AND (identity_level = ? OR identity_level = '' OR identity_level IS NULL)"
			args = append(args, f.Identity)
		} else {
			query += " AND identity_level = ?"
			args = append(args, f.Identity)
		}
	}
	if f.Credential != "" {
		query += " AND secret_keys LIKE ?"
		args = append(args, "%\""+f.Credential+"\"%")
	}
	if f.Domain != "" {
		query += " AND domain = ?"
		args = append(args, f.Domain)
	}
	if f.Method != "" {
		query += " AND method = ?"
		args = append(args, f.Method)
	}
	if f.Status != 0 {
		query += " AND status_code = ?"
		args = append(args, f.Status)
	}
	if f.StatusClass != "" {
		switch f.StatusClass {
		case "2xx":
			query += " AND status_code >= 200 AND status_code < 300"
		case "3xx":
			query += " AND status_code >= 300 AND status_code < 400"
		case "4xx":
			query += " AND status_code >= 400 AND status_code < 500"
		case "5xx":
			query += " AND status_code >= 500 AND status_code < 600"
		case "error":
			query += " AND (status_code >= 400 OR status = 'BLOCKED')"
		}
	}
	if f.Failed {
		query += " AND (status_code >= 400 OR status = 'BLOCKED')"
	}
	if f.Blocked {
		query += " AND status = 'BLOCKED'"
	}
	if f.Redacted {
		query += " AND redacted = 1"
	}
	if f.ProjectID != "" {
		query += " AND project_id = ?"
		args = append(args, f.ProjectID)
	}
	if f.Environment != "" {
		query += " AND environment = ?"
		args = append(args, f.Environment)
	}
	if !f.Since.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, f.Since.UTC())
	}
	if !f.Until.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, f.Until.UTC())
	}

	query += " ORDER BY timestamp DESC"

	if f.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, f.Limit)
	} else {
		query += " LIMIT 50"
	}

	if f.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, f.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		if err.Error() == "no such table: audit_events" {
			return nil, nil
		}
		return nil, fmt.Errorf("local db query failed: %w", err)
	}
	defer rows.Close()

	var results []proxy.AuditEvent
	for rows.Next() {
		var ev proxy.AuditEvent
		var secretKeysJSON, authStylesJSON string
		var environment, agentID, identityLevel, method, targetURL, domain, status, reason, resolutionPath, callerRole, workspaceID, projectID, tokenID sql.NullString

		err := rows.Scan(
			&ev.ID,
			&ev.Timestamp,
			&environment,
			&agentID,
			&identityLevel,
			&method,
			&targetURL,
			&domain,
			&ev.StatusCode,
			&ev.DurationMs,
			&status,
			&reason,
			&ev.Redacted,
			&resolutionPath,
			&callerRole,
			&workspaceID,
			&projectID,
			&tokenID,
			&secretKeysJSON,
			&authStylesJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}

		if environment.Valid {
			ev.Environment = environment.String
		}
		if agentID.Valid {
			ev.AgentID = agentID.String
		}
		if identityLevel.Valid {
			ev.IdentityLevel = identityLevel.String
		}
		if method.Valid {
			ev.Method = method.String
		}
		if targetURL.Valid {
			ev.TargetURL = targetURL.String
		}
		if domain.Valid {
			ev.Domain = domain.String
		}
		if status.Valid {
			ev.Status = status.String
		}
		if reason.Valid {
			ev.Reason = reason.String
		}
		if resolutionPath.Valid {
			ev.ResolutionPath = resolutionPath.String
		}
		if callerRole.Valid {
			ev.CallerRole = callerRole.String
		}
		if workspaceID.Valid {
			ev.WorkspaceID = workspaceID.String
		}
		if projectID.Valid {
			ev.ProjectID = projectID.String
		}
		if tokenID.Valid {
			ev.TokenID = tokenID.String
		}

		_ = json.Unmarshal([]byte(secretKeysJSON), &ev.SecretKeys)
		if ev.SecretKeys == nil {
			ev.SecretKeys = []string{}
		}

		_ = json.Unmarshal([]byte(authStylesJSON), &ev.AuthStyles)
		if ev.AuthStyles == nil {
			ev.AuthStyles = []string{}
		}

		results = append(results, ev)
	}
	return results, nil
}

// QueryLocalForensic fetches forensic audit events from the local SQLite database.
func (s *Service) QueryLocalForensic(f Filter) ([]proxy.ForensicAuditEvent, error) {
	query := `SELECT id, version, created_at, workspace_id, project_id, environment, agent_id, token_id, domain, method, status_code, outcome, latency_ms, chain_hash, event_json, snapshot_json, enforcement_json, resolution_json FROM forensic_audit_events WHERE 1=1`
	args := []interface{}{}

	if f.Agent != "" {
		if f.Agent == "anonymous" || f.Agent == "(anon)" || f.Agent == "(anonymous)" {
			query += " AND (agent_id = ? OR agent_id = '' OR agent_id IS NULL)"
			args = append(args, f.Agent)
		} else {
			query += " AND agent_id = ?"
			args = append(args, f.Agent)
		}
	}
	if f.Token != "" {
		query += " AND token_id = ?"
		args = append(args, f.Token)
	}
	if f.Identity != "" {
		if f.Identity == "anonymous" {
			query += " AND (json_extract(event_json, '$.agent_identity.identity_level') = ? OR json_extract(event_json, '$.agent_identity.identity_level') IS NULL)"
			args = append(args, f.Identity)
		} else {
			query += " AND json_extract(event_json, '$.agent_identity.identity_level') = ?"
			args = append(args, f.Identity)
		}
	}
	if f.Credential != "" {
		query += " AND json_extract(event_json, '$.key_name') LIKE ?"
		args = append(args, "%"+f.Credential+"%")
	}
	if f.Domain != "" {
		query += " AND domain = ?"
		args = append(args, f.Domain)
	}
	if f.Method != "" {
		query += " AND method = ?"
		args = append(args, f.Method)
	}
	if f.Status != 0 {
		query += " AND status_code = ?"
		args = append(args, f.Status)
	}
	if f.StatusClass != "" {
		switch f.StatusClass {
		case "2xx":
			query += " AND status_code >= 200 AND status_code < 300"
		case "3xx":
			query += " AND status_code >= 300 AND status_code < 400"
		case "4xx":
			query += " AND status_code >= 400 AND status_code < 500"
		case "5xx":
			query += " AND status_code >= 500 AND status_code < 600"
		case "error":
			query += " AND (status_code >= 400 OR outcome = 'blocked')"
		}
	}
	if f.Failed {
		query += " AND (status_code >= 400 OR outcome = 'blocked')"
	}
	if f.Blocked {
		query += " AND outcome = 'blocked'"
	}
	if f.Redacted {
		query += " AND outcome = 'redacted'"
	}
	if f.ProjectID != "" {
		query += " AND project_id = ?"
		args = append(args, f.ProjectID)
	}
	if f.Environment != "" {
		query += " AND environment = ?"
		args = append(args, f.Environment)
	}
	if !f.Since.IsZero() {
		query += " AND created_at >= ?"
		args = append(args, f.Since.UTC())
	}
	if !f.Until.IsZero() {
		query += " AND created_at <= ?"
		args = append(args, f.Until.UTC())
	}

	query += " ORDER BY created_at DESC"

	if f.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, f.Limit)
	} else {
		query += " LIMIT 50"
	}

	if f.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, f.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		if err.Error() == "no such table: forensic_audit_events" {
			return nil, nil
		}
		return nil, fmt.Errorf("local forensic db query failed: %w", err)
	}
	defer rows.Close()

	var results []proxy.ForensicAuditEvent
	for rows.Next() {
		var ev proxy.ForensicAuditEvent
		var eventJSON, snapshotJSON, enforcementJSON, resolutionJSON string
		var workspaceID, projectID, environment, agentID, tokenID, domain, method, outcome, chainHash sql.NullString

		err := rows.Scan(
			&ev.ID,
			&ev.Version,
			&ev.CreatedAt,
			&workspaceID,
			&projectID,
			&environment,
			&agentID,
			&tokenID,
			&domain,
			&method,
			&ev.Event.StatusCode,
			&outcome,
			&ev.Event.LatencyMs,
			&chainHash,
			&eventJSON,
			&snapshotJSON,
			&enforcementJSON,
			&resolutionJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("scan forensic error: %w", err)
		}

		if workspaceID.Valid {
			ev.WorkspaceID = workspaceID.String
		}
		if projectID.Valid {
			ev.ProjectID = projectID.String
		}
		if chainHash.Valid {
			ev.ChainHash = chainHash.String
		}

		_ = json.Unmarshal([]byte(eventJSON), &ev.Event)
		_ = json.Unmarshal([]byte(snapshotJSON), &ev.Snapshot)
		_ = json.Unmarshal([]byte(enforcementJSON), &ev.Enforcement)
		_ = json.Unmarshal([]byte(resolutionJSON), &ev.Resolution)

		results = append(results, ev)
	}
	return results, nil
}

// GetLog returns a single log entry by ID.
func (s *Service) GetLog(id string) (*proxy.AuditEvent, error) {
	// First try to fetch from forensic table
	fe, err := s.GetForensicLog(id)
	if err == nil {
		legacy := mapForensicToLegacy(*fe)
		return &legacy, nil
	}

	// Fallback to legacy audit_events table
	query := "SELECT id, timestamp, COALESCE(environment, '') as environment, agent_id, identity_level, method, target_url, domain, status_code, duration_ms, status, reason, redacted, resolution_path, caller_role, workspace_id, project_id, token_id, secret_keys, auth_styles FROM audit_events WHERE id = ?"
	rows, err := s.db.Query(query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		var ev proxy.AuditEvent
		var secretKeysJSON, authStylesJSON string
		var environment, agentID, identityLevel, method, targetURL, domain, status, reason, resolutionPath, callerRole, workspaceID, projectID, tokenID sql.NullString

		err := rows.Scan(
			&ev.ID,
			&ev.Timestamp,
			&environment,
			&agentID,
			&identityLevel,
			&method,
			&targetURL,
			&domain,
			&ev.StatusCode,
			&ev.DurationMs,
			&status,
			&reason,
			&ev.Redacted,
			&resolutionPath,
			&callerRole,
			&workspaceID,
			&projectID,
			&tokenID,
			&secretKeysJSON,
			&authStylesJSON,
		)
		if err != nil {
			return nil, err
		}

		if environment.Valid {
			ev.Environment = environment.String
		}
		if agentID.Valid {
			ev.AgentID = agentID.String
		}
		if identityLevel.Valid {
			ev.IdentityLevel = identityLevel.String
		}
		if method.Valid {
			ev.Method = method.String
		}
		if targetURL.Valid {
			ev.TargetURL = targetURL.String
		}
		if domain.Valid {
			ev.Domain = domain.String
		}
		if status.Valid {
			ev.Status = status.String
		}
		if reason.Valid {
			ev.Reason = reason.String
		}
		if resolutionPath.Valid {
			ev.ResolutionPath = resolutionPath.String
		}
		if callerRole.Valid {
			ev.CallerRole = callerRole.String
		}
		if workspaceID.Valid {
			ev.WorkspaceID = workspaceID.String
		}
		if projectID.Valid {
			ev.ProjectID = projectID.String
		}
		if tokenID.Valid {
			ev.TokenID = tokenID.String
		}

		_ = json.Unmarshal([]byte(secretKeysJSON), &ev.SecretKeys)
		_ = json.Unmarshal([]byte(authStylesJSON), &ev.AuthStyles)

		return &ev, nil
	}

	return nil, fmt.Errorf("log entry not found locally: %s", id)
}

// GetForensicLog returns a single forensic audit event by ID.
func (s *Service) GetForensicLog(id string) (*proxy.ForensicAuditEvent, error) {
	query := `SELECT id, version, created_at, workspace_id, project_id, environment, agent_id, token_id, domain, method, status_code, outcome, latency_ms, chain_hash, event_json, snapshot_json, enforcement_json, resolution_json FROM forensic_audit_events WHERE id = ?`
	rows, err := s.db.Query(query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		var ev proxy.ForensicAuditEvent
		var eventJSON, snapshotJSON, enforcementJSON, resolutionJSON string
		var workspaceID, projectID, environment, agentID, tokenID, domain, method, outcome, chainHash sql.NullString

		err := rows.Scan(
			&ev.ID,
			&ev.Version,
			&ev.CreatedAt,
			&workspaceID,
			&projectID,
			&environment,
			&agentID,
			&tokenID,
			&domain,
			&method,
			&ev.Event.StatusCode,
			&outcome,
			&ev.Event.LatencyMs,
			&chainHash,
			&eventJSON,
			&snapshotJSON,
			&enforcementJSON,
			&resolutionJSON,
		)
		if err != nil {
			return nil, err
		}

		if workspaceID.Valid {
			ev.WorkspaceID = workspaceID.String
		}
		if projectID.Valid {
			ev.ProjectID = projectID.String
		}
		if chainHash.Valid {
			ev.ChainHash = chainHash.String
		}

		_ = json.Unmarshal([]byte(eventJSON), &ev.Event)
		_ = json.Unmarshal([]byte(snapshotJSON), &ev.Snapshot)
		_ = json.Unmarshal([]byte(enforcementJSON), &ev.Enforcement)
		_ = json.Unmarshal([]byte(resolutionJSON), &ev.Resolution)

		return &ev, nil
	}

	return nil, fmt.Errorf("forensic log entry not found locally: %s", id)
}

// QueryChronologicalForensic fetches all forensic audit events in chronological order (oldest first).
func (s *Service) QueryChronologicalForensic() ([]proxy.ForensicAuditEvent, error) {
	query := `SELECT id, version, created_at, workspace_id, project_id, environment, agent_id, token_id, domain, method, status_code, outcome, latency_ms, chain_hash, event_json, snapshot_json, enforcement_json, resolution_json FROM forensic_audit_events ORDER BY created_at ASC, id ASC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query chronological forensic events: %w", err)
	}
	defer rows.Close()

	var results []proxy.ForensicAuditEvent
	for rows.Next() {
		var ev proxy.ForensicAuditEvent
		var eventJSON, snapshotJSON, enforcementJSON, resolutionJSON string
		var workspaceID, projectID, environment, agentID, tokenID, domain, method, outcome, chainHash sql.NullString

		err := rows.Scan(
			&ev.ID,
			&ev.Version,
			&ev.CreatedAt,
			&workspaceID,
			&projectID,
			&environment,
			&agentID,
			&tokenID,
			&domain,
			&method,
			&ev.Event.StatusCode,
			&outcome,
			&ev.Event.LatencyMs,
			&chainHash,
			&eventJSON,
			&snapshotJSON,
			&enforcementJSON,
			&resolutionJSON,
		)
		if err != nil {
			return nil, err
		}

		if workspaceID.Valid {
			ev.WorkspaceID = workspaceID.String
		}
		if projectID.Valid {
			ev.ProjectID = projectID.String
		}
		if chainHash.Valid {
			ev.ChainHash = chainHash.String
		}

		_ = json.Unmarshal([]byte(eventJSON), &ev.Event)
		_ = json.Unmarshal([]byte(snapshotJSON), &ev.Snapshot)
		_ = json.Unmarshal([]byte(enforcementJSON), &ev.Enforcement)
		_ = json.Unmarshal([]byte(resolutionJSON), &ev.Resolution)

		results = append(results, ev)
	}
	return results, nil
}

// VerifyChain checks the cryptographic integrity of the forensic log chain.
// Returns nil if integrity is OK, or an error detailing where the corruption occurred.
func (s *Service) VerifyChain() error {
	logs, err := s.QueryChronologicalForensic()
	if err != nil {
		return err
	}

	if len(logs) == 0 {
		return nil
	}

	prevID := "genesis_block"
	for i, entry := range logs {
		tsStr := entry.CreatedAt.Format(time.RFC3339Nano)
		h := sha256.New()
		h.Write([]byte(prevID + entry.ID + tsStr))
		expectedHash := fmt.Sprintf("%x", h.Sum(nil))

		if entry.ChainHash != expectedHash {
			return fmt.Errorf("chain integrity failure at index %d (ID: %s, Recorded: %s, Expected: %s)", i, entry.ID, entry.ChainHash, expectedHash)
		}
		prevID = entry.ID
	}
	return nil
}
