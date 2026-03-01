package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "meta-auth",
	Short: "Meta authentication manager for all Meta API tools",
	Long: `meta-auth manages a single Meta access token shared by all Meta CLI tools.

It stores credentials in the OS config directory and provides
token lifecycle management: login, refresh, extend, and status.

Other Meta CLI tools read from this shared store automatically:
  meta-ads, meta-adlib, and any future Meta API tool

Quick start:
  # Browser OAuth (recommended)
  export META_APP_ID=<your_app_id>
  export META_APP_SECRET=<your_app_secret>
  meta-auth login

  # Or paste a token directly
  meta-auth set-token EAABsbCS...

  # Print the current token (for use in scripts or env vars)
  meta-auth token

  # Refresh before it expires (run monthly via cron)
  meta-auth refresh

  # Check status
  meta-auth status`,
	SilenceUsage: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show tool info: config path, token status, and environment",
	Run: func(cmd *cobra.Command, args []string) {
		printInfo()
	},
}

func init() {
	rootCmd.AddCommand(infoCmd)
}

func printInfo() {
	configDir, _ := os.UserConfigDir()
	configPath := filepath.Join(configDir, "meta-auth", "config.json")

	fmt.Println("meta-auth — Meta authentication manager")
	fmt.Println()

	// Binary location
	exe, _ := os.Executable()
	fmt.Printf("  binary:     %s\n", exe)
	fmt.Printf("  os/arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()

	// Config paths
	fmt.Println("  config paths by OS:")
	fmt.Println("    macOS:    ~/Library/Application Support/meta-auth/config.json")
	fmt.Println("    Linux:    ~/.config/meta-auth/config.json")
	fmt.Println("    Windows:  %AppData%\\meta-auth\\config.json")
	fmt.Printf("  config now: %s\n", configPath)
	fmt.Println()

	// Token status
	data, err := os.ReadFile(configPath)
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(data) == 0) {
		fmt.Println("  token:      not set — run: meta-auth login")
	} else if err == nil {
		var cfg struct {
			AccessToken    string `json:"access_token"`
			UserName       string `json:"user_name"`
			TokenType      string `json:"token_type"`
			TokenExpiresAt int64  `json:"token_expires_at"`
		}
		if json.Unmarshal(data, &cfg) == nil && cfg.AccessToken != "" {
			fmt.Printf("  token:      set (user: %s, type: %s)\n", cfg.UserName, cfg.TokenType)
			if cfg.TokenExpiresAt == 0 {
				fmt.Println("  expires:    unknown (system user token or not tracked)")
			} else {
				exp := time.Unix(cfg.TokenExpiresAt, 0)
				days := int(time.Until(exp).Hours() / 24)
				if days < 0 {
					fmt.Printf("  expires:    EXPIRED on %s\n", exp.Format("2006-01-02"))
				} else {
					fmt.Printf("  expires:    %s (%d days left)\n", exp.Format("2006-01-02"), days)
				}
			}
		}
	}

	fmt.Println()
	fmt.Println("  env vars:")
	fmt.Printf("    META_APP_ID     = %s\n", maskOrEmpty(os.Getenv("META_APP_ID")))
	fmt.Printf("    META_APP_SECRET = %s\n", maskOrEmpty(os.Getenv("META_APP_SECRET")))
	fmt.Printf("    META_TOKEN      = %s\n", maskOrEmpty(os.Getenv("META_TOKEN")))
	fmt.Println("  (+ aliases accepted, see docs)")
	fmt.Println()
	fmt.Println("  token resolution order (all Meta CLIs):")
	fmt.Println("    1. META_TOKEN env var")
	fmt.Println("    2. tool's own config (e.g. ~/.config/meta-ads/config.json)")
	fmt.Println("    3. meta-auth shared config (this tool)")
}

func maskOrEmpty(v string) string {
	if v == "" {
		return "(not set)"
	}
	if len(v) <= 8 {
		return "***"
	}
	return v[:4] + "..." + v[len(v)-4:]
}

// resolveEnv returns the value of the first non-empty environment variable from the given names.
func resolveEnv(names ...string) string {
	for _, name := range names {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}
