// Package projects handles project creation, selection, updates, deletion, and team invites within workspaces.
package projects

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"strings"
)

// Project represents a project in a workspace
type Project struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	WorkspaceID string `json:"workspace_id"`
}

// Service handles project orchestration
type Service struct {
	API *api.Client
}

// NewService creates a new project service
func NewService(client *api.Client) *Service {
	return &Service{API: client}
}

// List returns all projects for the currently selected workspace
func (s *Service) List() ([]Project, error) {
	return api.CallJSON[[]Project](s.API, "projects.list", "GET", nil, nil, nil)
}

// Create creates a new project in the active workspace and binds it locally
func (s *Service) Create(name, description string) (*Project, error) {
	workspaceID := config.GetSelectedWorkspaceID()
	if workspaceID == "" {
		global, _ := config.LoadGlobalConfig()
		if global != nil {
			for id, ws := range global.Workspaces {
				if workspaceID == "" || ws.Type == "personal" {
					workspaceID = id
				}
				if ws.Type == "personal" {
					break
				}
			}
		}
	}

	if workspaceID == "" {
		return nil, fmt.Errorf("no workspace selected; run 'agentsecrets workspace switch' first")
	}

	data := map[string]interface{}{
		"name":         name,
		"workspace_id": workspaceID,
	}
	if description != "" {
		data["description"] = description
	}

	resp, err := api.CallJSON[Project](s.API, "projects.create", "POST", data, nil, nil, http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("create project: %w", err)
	}

	// Bind locally
	if err := s.bindLocally(&resp); err != nil {
		return nil, fmt.Errorf("create project: bind: %w", err)
	}

	return &resp, nil
}

// Use selects a project by name and updates the local .agentsecrets/project.json
func (s *Service) Use(name string) (*Project, error) {
	workspaceID := config.GetSelectedWorkspaceID()
	if workspaceID == "" {
		return nil, fmt.Errorf("no workspace selected; run 'agentsecrets workspace switch' first")
	}

	params := map[string]string{
		"workspace_id": workspaceID,
		"project_name": name,
	}

	resp, err := api.CallJSON[Project](s.API, "projects.get", "GET", nil, params, nil)
	if err != nil {
		return nil, fmt.Errorf("use project: %w", err)
	}

	// Update local config
	if err := s.bindLocally(&resp); err != nil {
		return nil, fmt.Errorf("use project: bind: %w", err)
	}

	return &resp, nil
}

// bindLocally updates the fields in the existing .agentsecrets/project.json
func (s *Service) bindLocally(project *Project) error {
	root, _ := config.GetProjectRoot()
	if root == "" {
		root = "."
	}
	projectDir := filepath.Join(root, ".agentsecrets")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		return fmt.Errorf("failed to create projects directory: %w", err)
	}

	local, _ := config.LoadProjectConfig()
	if local == nil {
		local = &config.ProjectConfig{Environment: "development"}
	}

	local.ProjectID = project.ID
	local.ProjectName = project.Name
	local.Description = project.Description
	local.WorkspaceID = project.WorkspaceID

	// Get workspace name from global cache if available
	global, _ := config.LoadGlobalConfig()
	if global != nil {
		if ws, ok := global.Workspaces[project.WorkspaceID]; ok {
			local.WorkspaceName = ws.Name
		}
	}

	// Save globally so exec provider can find it regardless of working directory
	_ = config.SetSelectedProjectID(project.ID)

	return config.SaveProjectConfig(local)
}

// Update modifies an existing project's name or description
func (s *Service) Update(oldName, newName, desc string) error {
	workspaceID := config.GetSelectedWorkspaceID()
	if workspaceID == "" {
		return fmt.Errorf("no workspace selected; run 'agentsecrets workspace switch' first")
	}

	data := make(map[string]interface{})
	if newName != "" {
		data["name"] = newName
	}
	if desc != "" {
		data["description"] = desc
	}

	params := map[string]string{
		"workspace_id": workspaceID,
		"project_name": oldName,
	}

	if err := s.API.CallNoContent("projects.update", "PATCH", data, params, nil); err != nil {
		return fmt.Errorf("update project: %w", err)
	}

	// Update local project config if the updated project is the currently active one
	local, err := config.LoadProjectConfig()
	if err == nil && local != nil && local.ProjectName == oldName && local.WorkspaceID == workspaceID {
		if newName != "" {
			local.ProjectName = newName
		}
		if desc != "" {
			local.Description = desc
		}
		if err := config.SaveProjectConfig(local); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: rename succeeded on cloud but failed to update local project config: %v\n", err)
		}
	}

	return nil
}

// Delete permanently removes a project from the workspace
func (s *Service) Delete(name string) error {
	workspaceID := config.GetSelectedWorkspaceID()
	if workspaceID == "" {
		return fmt.Errorf("no workspace selected; run 'agentsecrets workspace switch' first")
	}

	params := map[string]string{
		"workspace_id": workspaceID,
		"project_name": name,
	}

	if err := s.API.CallNoContent("projects.delete", "DELETE", nil, params, nil); err != nil {
		return fmt.Errorf("delete project: %w", err)
	}

	// Unbind local project info if we just deleted the active one
	local, err := config.LoadProjectConfig()
	if err == nil && local != nil && local.ProjectName == name && local.WorkspaceID == workspaceID {
		root, _ := config.GetProjectRoot()
		if root != "" {
			os.Remove(filepath.Join(root, ".agentsecrets", "project.json"))
		}
	}

	return nil
}

// Invite invites a user to the current project by email, potentially migrating a personal workspace to a shared one.
func (s *Service) Invite(email, role string) error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured; run 'agentsecrets project use' first")
	}

	workspaceID := project.WorkspaceID
	if workspaceID == "" {
		return fmt.Errorf("no workspace found for this project")
	}

	// 1. Fetch Invitee's Public Key
	pubResp, err := s.API.Call("users.public_key", "GET", nil, map[string]string{"email": email}, nil)
	if err != nil {
		return fmt.Errorf("failed to fetch public key for %s: %w", email, err)
	}
	defer pubResp.Body.Close()

	if pubResp.StatusCode != http.StatusOK {
		return fmt.Errorf("user %s not found or has no public key", email)
	}

	var pubRes struct {
		Data struct {
			PublicKey string `json:"public_key"`
		} `json:"data"`
	}
	if err := json.NewDecoder(pubResp.Body).Decode(&pubRes); err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	inviteePubKey, err := base64.StdEncoding.DecodeString(pubRes.Data.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key format: %w", err)
	}

	// 2. Determine Workspace Type
	global, err := config.LoadGlobalConfig()
	if err != nil {
		return fmt.Errorf("failed to load global config: %w", err)
	}

	ws, ok := global.Workspaces[workspaceID]
	if !ok {
		return fmt.Errorf("workspace %s not found in local cache", workspaceID)
	}

	myEmail := config.GetEmail()
	myPubKey, err := keyring.GetPublicKey(myEmail)
	if err != nil {
		return fmt.Errorf("failed to load your public key from keyring: %w", err)
	}

	data := map[string]interface{}{
		"email": email,
		"role":  role,
	}

	var newWorkspaceKey []byte
	isMigrating := strings.EqualFold(ws.Type, "personal") || ws.Type == ""

	if isMigrating {
		// Needs migration: Generate a new key and re-encrypt all secrets
		newWorkspaceKey, err = crypto.GenerateWorkspaceKey()
		if err != nil {
			return fmt.Errorf("failed to generate new workspace key: %w", err)
		}

		// Encrypt the new workspace key for both the owner and the invitee
		encForOwner, err := crypto.EncryptForUser(myPubKey, newWorkspaceKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt workspace key for owner: %w", err)
		}
		encForInvitee, err := crypto.EncryptForUser(inviteePubKey, newWorkspaceKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt workspace key for invitee: %w", err)
		}

		data["encrypted_workspace_key_owner"] = base64.StdEncoding.EncodeToString(encForOwner)
		data["encrypted_workspace_key_invitee"] = base64.StdEncoding.EncodeToString(encForInvitee)

		oldWsKeyRaw, err := config.GetWorkspaceKey(workspaceID)
		if err != nil {
			return fmt.Errorf("failed to load old workspace key: %w", err)
		}

		apiSecrets := []map[string]string{}
		environments := config.ValidEnvironments

		for _, env := range environments {
			scrtResp, err := s.API.Call("secrets.list", "GET", nil, map[string]string{"project_id": project.ProjectID}, map[string]string{"environment": env})
			if err != nil {
				continue // Skip environments that fail or don't exist
			}

			var scrtRes struct {
				Data struct {
					Secrets []struct {
						Key   string `json:"key"`
						Value string `json:"value"`
					} `json:"secrets"`
				} `json:"data"`
			}

			if err := json.NewDecoder(scrtResp.Body).Decode(&scrtRes); err != nil {
				scrtResp.Body.Close()
				continue
			}
			scrtResp.Body.Close()

			for _, secret := range scrtRes.Data.Secrets {
				plaintext, err := crypto.DecryptSecret(secret.Value, oldWsKeyRaw)
				if err != nil {
					return fmt.Errorf("failed to decrypt secret %q in %s: %w", secret.Key, env, err)
				}
				newEncrypted, err := crypto.EncryptSecret(plaintext, newWorkspaceKey)
				if err != nil {
					return fmt.Errorf("failed to re-encrypt secret %q in %s: %w", secret.Key, env, err)
				}

				apiSecrets = append(apiSecrets, map[string]string{
					"key":         secret.Key,
					"value":       newEncrypted,
					"environment": env,
				})
			}
		}

		data["secrets"] = apiSecrets

	} else {
		// Existing shared workspace: Just encrypt current workspace key for invitee
		wsKeyRaw, err := base64.StdEncoding.DecodeString(ws.Key)
		if err != nil {
			return fmt.Errorf("failed to decode current workspace key: %w", err)
		}

		encForInvitee, err := crypto.EncryptForUser(inviteePubKey, wsKeyRaw)
		if err != nil {
			return fmt.Errorf("failed to encrypt workspace key for invitee: %w", err)
		}
		data["encrypted_workspace_key_invitee"] = base64.StdEncoding.EncodeToString(encForInvitee)
	}

	// 3. Send Invite to API
	invResp, err := s.API.Call("projects.invite", "POST", data, map[string]string{
		"workspace_id": workspaceID,
		"project_name": project.ProjectName,
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to send invite: %w", err)
	}
	defer invResp.Body.Close()

	if invResp.StatusCode != http.StatusOK && invResp.StatusCode != http.StatusCreated {
		return s.API.DecodeError(invResp)
	}

	var result struct {
		Data struct {
			WorkspaceID          string `json:"workspace_id"`
			WorkspaceName        string `json:"workspace_name"`
			MigratedFromPersonal bool   `json:"migrated_from_personal"`
		} `json:"data"`
	}
	if err := json.NewDecoder(invResp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode invite response: %w", err)
	}

	// 4. Update local config if migrated
	if result.Data.MigratedFromPersonal && result.Data.WorkspaceID != "" {
		global.Workspaces[result.Data.WorkspaceID] = config.WorkspaceCacheEntry{
			Name: result.Data.WorkspaceName,
			Key:  base64.StdEncoding.EncodeToString(newWorkspaceKey),
			Role: "owner",
			Type: "shared",
		}
		config.SetSelectedWorkspaceID(result.Data.WorkspaceID)
		config.SaveGlobalConfig(global)

		project.WorkspaceID = result.Data.WorkspaceID
		project.WorkspaceName = result.Data.WorkspaceName
		config.SaveProjectConfig(project)
	}

	return nil
}
