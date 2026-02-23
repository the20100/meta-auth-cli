package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// TokenType describes how the access token was obtained.
type TokenType string

const (
	TokenTypeOAuth     TokenType = "oauth"       // browser OAuth flow
	TokenTypeManual    TokenType = "manual"       // pasted manually
	TokenTypeLongLived TokenType = "long-lived"   // explicitly extended
	TokenTypeSystem    TokenType = "system-user"  // never-expiring system user token
)

// Config holds the persisted Meta auth configuration.
// Stored at: ~/.config/meta-auth/config.json
type Config struct {
	AccessToken    string    `json:"access_token"`
	TokenType      TokenType `json:"token_type,omitempty"`
	UserID         string    `json:"user_id,omitempty"`
	UserName       string    `json:"user_name,omitempty"`
	// TokenExpiresAt is a Unix timestamp (seconds). Zero means unknown/never-expires.
	TokenExpiresAt int64     `json:"token_expires_at,omitempty"`
	// App credentials — env vars META_APP_ID / META_APP_SECRET always take priority.
	AppID          string    `json:"app_id,omitempty"`
	AppSecret      string    `json:"app_secret,omitempty"`
}

// ExpiresAt returns the expiry time, or zero time if unknown.
func (c *Config) ExpiresAt() time.Time {
	if c.TokenExpiresAt == 0 {
		return time.Time{}
	}
	return time.Unix(c.TokenExpiresAt, 0)
}

// DaysUntilExpiry returns the number of full days until expiry.
// Returns -1 if the expiry is unknown (TokenExpiresAt == 0).
func (c *Config) DaysUntilExpiry() int {
	if c.TokenExpiresAt == 0 {
		return -1
	}
	d := time.Until(time.Unix(c.TokenExpiresAt, 0))
	if d < 0 {
		return 0
	}
	return int(d.Hours() / 24)
}

// IsExpired returns true if the token has a known expiry that has passed.
func (c *Config) IsExpired() bool {
	if c.TokenExpiresAt == 0 {
		return false
	}
	return time.Now().After(time.Unix(c.TokenExpiresAt, 0))
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "meta-auth", "config.json"), nil
}

// Load reads the config file. Returns an empty Config (not an error) if the file doesn't exist.
func Load() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save writes the config file with 0600 permissions.
func Save(cfg *Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// Clear removes the config file (logout).
func Clear() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Path returns the config file path for display purposes.
func Path() string {
	p, _ := configPath()
	return p
}
