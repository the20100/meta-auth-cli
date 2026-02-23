package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "meta-auth",
	Short: "Meta authentication manager for all Meta API tools",
	Long: `meta-auth manages a single Meta access token shared by all Meta CLI tools.

It stores credentials at ~/.config/meta-auth/config.json and provides
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
