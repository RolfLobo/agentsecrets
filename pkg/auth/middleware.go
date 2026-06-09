package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/ui"
)

// EnsureAuth is a Cobra PersistentPreRunE middleware that checks session validity.
// It automatically refreshes the access token if it is expired or close to expiring,
// assuming a valid refresh token exists.
func (s *Service) EnsureAuth(cmd *cobra.Command, args []string) error {
	if !config.IsAuthenticated() {
		return fmt.Errorf("you must be logged in to perform this action. Run 'agentsecrets login'")
	}

	if config.IsTokenExpired() {
		tokens, err := config.LoadTokens()
		if err != nil || tokens == nil || tokens.RefreshToken == "" {
			return fmt.Errorf("session expired, please run 'agentsecrets login' again")
		}
		if err := ui.Spinner("Refreshing expired session token...", func() error {
			return s.RefreshSession(tokens.RefreshToken)
		}); err != nil {
			return fmt.Errorf("session refresh failed, you may need to log in again: %w", err)
		}
	}

	return nil
}

// refreshResponse represents token refresh API response
type refreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    string `json:"expires_at"`
	Data         struct {
		Access    string `json:"access"`
		Refresh   string `json:"refresh"`
		ExpiresAt string `json:"expires_at"`
	} `json:"data"`
}

// RefreshSession uses the refresh token to get a new access token.
func (s *Service) RefreshSession(refreshToken string) error {
	if refreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	data := map[string]string{
		"refresh": refreshToken,
	}

	resp, err := s.API.Call("auth.refresh", "POST", data, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return s.API.DecodeError(resp)
	}

	var res refreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("failed to parse refresh response: %w", err)
	}

	access := coalesce(res.AccessToken, res.Data.Access)
	if access == "" {
		return fmt.Errorf("no access token in refresh response")
	}

	newRefresh := coalesce(res.RefreshToken, res.Data.Refresh)
	if newRefresh == "" {
		newRefresh = refreshToken // Keep old one if not rotated
	}

	expiresAt := coalesce(res.ExpiresAt, res.Data.ExpiresAt)
	if expiresAt == "" {
		// Fallback: estimate
		expiresAt = time.Now().Add(10 * time.Minute).Format(time.RFC3339)
	}

	return config.StoreTokens(access, newRefresh, expiresAt)
}
