package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/the20100/meta-auth-cli/internal/config"
)

const (
	apiVersion    = "v23.0"
	metaDialogURL = "https://www.facebook.com/" + apiVersion + "/dialog/oauth"
	metaTokenURL  = "https://graph.facebook.com/" + apiVersion + "/oauth/access_token"
	metaMeURL     = "https://graph.facebook.com/" + apiVersion + "/me"
)

// ── flag vars ─────────────────────────────────────────────────────────────────

var (
	loginScope         string
	setTokenNoExtend   bool
	extendTokenSave    bool
)

// ── commands ──────────────────────────────────────────────────────────────────

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate via browser OAuth flow",
	Long: `Opens your browser for Meta OAuth and saves a long-lived token (~60 days).

Requires META_APP_ID and META_APP_SECRET environment variables
(or values stored from a previous login).

The default scope covers Meta Ads API usage. Use --scope to customise.

Examples:
  meta-auth login
  meta-auth login --scope "ads_read,public_profile"`,
	RunE: runLogin,
}

var setTokenCmd = &cobra.Command{
	Use:   "set-token <token>",
	Short: "Save a Meta access token directly",
	Long: `Saves a Meta access token to the shared config file.

The token is validated via GET /me. If META_APP_ID and META_APP_SECRET
are available (env vars or stored config), it is automatically upgraded
to a long-lived token (~60 days) unless --no-extend is passed.

Examples:
  meta-auth set-token EAABsbCS...
  meta-auth set-token EAABsbCS... --no-extend
  META_APP_ID=123 META_APP_SECRET=abc meta-auth set-token EAABsbCS...`,
	Args: cobra.ExactArgs(1),
	RunE: runSetToken,
}

var extendTokenCmd = &cobra.Command{
	Use:   "extend-token <short_lived_token>",
	Short: "Exchange a short-lived token for a long-lived one (~60 days)",
	Long: `Upgrades a short-lived user access token to a long-lived one (~60 days).

Requires META_APP_ID and META_APP_SECRET (env vars or stored config).

Examples:
  meta-auth extend-token EAABsbCS...
  meta-auth extend-token EAABsbCS... --save`,
	Args: cobra.ExactArgs(1),
	RunE: runExtendToken,
}

var refreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Refresh the stored token before it expires",
	Long: `Re-exchanges the currently stored token for a fresh long-lived token (~60 days).

This resets the 60-day window from today. Run it once a month to keep the
token alive indefinitely without ever logging in again.

Requires META_APP_ID and META_APP_SECRET (env vars or stored config).

Cron example (1st of each month at 09:00):
  0 9 1 * * META_APP_ID=... META_APP_SECRET=... meta-auth refresh

Examples:
  meta-auth refresh
  META_APP_ID=123 META_APP_SECRET=abc meta-auth refresh`,
	RunE: runRefresh,
}

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Print the current access token to stdout",
	Long: `Prints the stored access token to stdout (no trailing newline).

Use this to inject the token into other tools or scripts:

  export META_TOKEN=$(meta-auth token)
  meta-ads campaigns list
  meta-adlib search --query "shoes" --country FR

  # Or inline
  META_TOKEN=$(meta-auth token) meta-ads accounts list`,
	RunE: runToken,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current authentication status",
	RunE:  runStatus,
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove saved credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.Clear(); err != nil {
			return fmt.Errorf("failed to clear config: %w", err)
		}
		fmt.Println("logged out")
		return nil
	},
}

func init() {
	loginCmd.Flags().StringVar(&loginScope, "scope", "ads_management,ads_read,business_management,public_profile", "OAuth scopes to request")
	setTokenCmd.Flags().BoolVar(&setTokenNoExtend, "no-extend", false, "Skip long-lived token upgrade even if app credentials are available")
	extendTokenCmd.Flags().BoolVar(&extendTokenSave, "save", false, "Save the long-lived token to config")

	rootCmd.AddCommand(loginCmd, setTokenCmd, extendTokenCmd, refreshCmd, tokenCmd, statusCmd, logoutCmd)
}

// ── handlers ──────────────────────────────────────────────────────────────────

func runLogin(cmd *cobra.Command, args []string) error {
	appID, appSecret := resolveAppCredentials()
	if appID == "" {
		return fmt.Errorf("META_APP_ID not set — export META_APP_ID=<your_app_id>")
	}
	if appSecret == "" {
		return fmt.Errorf("META_APP_SECRET not set — export META_APP_SECRET=<your_app_secret>")
	}

	// Pick a random free port for the callback server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to find free port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if errMsg := q.Get("error"); errMsg != "" {
			errCh <- fmt.Errorf("OAuth error: %s — %s", errMsg, q.Get("error_description"))
			http.Error(w, "Authentication failed. You may close this tab.", http.StatusBadRequest)
			return
		}
		code := q.Get("code")
		if code == "" {
			errCh <- fmt.Errorf("no code returned in callback")
			http.Error(w, "No code received. You may close this tab.", http.StatusBadRequest)
			return
		}
		codeCh <- code
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:40px">
<h2>✓ Authentication successful!</h2>
<p>You may close this tab and return to the terminal.</p>
</body></html>`)
	})

	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			select {
			case errCh <- fmt.Errorf("callback server error: %w", err):
			default:
			}
		}
	}()

	authURL := buildAuthURL(appID, redirectURI, loginScope)
	fmt.Printf("\nopening browser for Meta authentication...\n")
	fmt.Printf("if the browser does not open, visit:\n  %s\n\n", authURL)
	openBrowser(authURL)
	fmt.Printf("waiting for callback on http://127.0.0.1:%d/callback ...\n", port)

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		shutdownServer(srv)
		return err
	case <-time.After(5 * time.Minute):
		shutdownServer(srv)
		return fmt.Errorf("timed out waiting for OAuth callback (5 minutes)")
	}
	shutdownServer(srv)

	fmt.Println("exchanging code for token...")
	shortToken, err := exchangeCode(code, appID, appSecret, redirectURI)
	if err != nil {
		return fmt.Errorf("failed to exchange code: %w", err)
	}

	fmt.Println("upgrading to long-lived token...")
	longToken, expiresAt, err := exchangeToLongLived(shortToken, appID, appSecret)
	if err != nil {
		return fmt.Errorf("failed to upgrade token: %w", err)
	}

	fmt.Println("fetching user info...")
	userID, userName, err := fetchMe(longToken)
	if err != nil {
		return fmt.Errorf("failed to fetch user info: %w", err)
	}

	existingCfg, _ := config.Load()
	newCfg := &config.Config{
		AccessToken:    longToken,
		TokenType:      config.TokenTypeOAuth,
		UserID:         userID,
		UserName:       userName,
		TokenExpiresAt: expiresAt,
		AppID:          appID,
		AppSecret:      appSecret,
	}
	// Preserve app credentials from existing config if not re-provided
	if existingCfg != nil {
		if newCfg.AppID == "" {
			newCfg.AppID = existingCfg.AppID
		}
		if newCfg.AppSecret == "" {
			newCfg.AppSecret = existingCfg.AppSecret
		}
	}

	if err := config.Save(newCfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("\nauthenticated as %s (ID: %s)\n", userName, userID)
	printExpiry(newCfg)
	fmt.Printf("  config: %s\n", config.Path())
	return nil
}

func runSetToken(cmd *cobra.Command, args []string) error {
	token := args[0]
	appID, appSecret := resolveAppCredentials()

	finalToken := token
	tokenType := config.TokenTypeManual
	var expiresAt int64

	if !setTokenNoExtend && appID != "" && appSecret != "" {
		fmt.Println("app credentials found — upgrading to long-lived token (~60 days)...")
		lt, exp, err := exchangeToLongLived(token, appID, appSecret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not upgrade token: %v\n", err)
			fmt.Fprintf(os.Stderr, "         saving original token. Use --no-extend to suppress.\n")
		} else {
			finalToken = lt
			expiresAt = exp
			tokenType = config.TokenTypeLongLived
			fmt.Println("token upgraded to long-lived")
		}
	} else if !setTokenNoExtend && (appID == "" || appSecret == "") {
		fmt.Fprintln(os.Stderr, "note: META_APP_ID / META_APP_SECRET not available — saving token as-is")
		fmt.Fprintln(os.Stderr, "      to extend later: meta-auth extend-token <token> --save")
	}

	fmt.Println("validating token...")
	userID, userName, err := fetchMe(finalToken)
	if err != nil {
		return fmt.Errorf("token validation failed: %w", err)
	}

	existingCfg, _ := config.Load()
	newCfg := &config.Config{
		AccessToken:    finalToken,
		TokenType:      tokenType,
		UserID:         userID,
		UserName:       userName,
		TokenExpiresAt: expiresAt,
		AppID:          appID,
		AppSecret:      appSecret,
	}
	if existingCfg != nil {
		if newCfg.AppID == "" {
			newCfg.AppID = existingCfg.AppID
		}
		if newCfg.AppSecret == "" {
			newCfg.AppSecret = existingCfg.AppSecret
		}
	}

	if err := config.Save(newCfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("token saved — authenticated as %s (ID: %s)\n", userName, userID)
	printExpiry(newCfg)
	fmt.Printf("  config: %s\n", config.Path())
	return nil
}

func runExtendToken(cmd *cobra.Command, args []string) error {
	shortToken := args[0]
	appID, appSecret := resolveAppCredentials()
	if appID == "" {
		return fmt.Errorf("META_APP_ID not available — set env var or run: meta-auth login")
	}
	if appSecret == "" {
		return fmt.Errorf("META_APP_SECRET not available — set env var or run: meta-auth login")
	}

	fmt.Println("exchanging for long-lived token...")
	longToken, expiresAt, err := exchangeToLongLived(shortToken, appID, appSecret)
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}

	if extendTokenSave {
		fmt.Println("validating token...")
		userID, userName, err := fetchMe(longToken)
		if err != nil {
			return fmt.Errorf("token validation failed: %w", err)
		}

		existingCfg, _ := config.Load()
		newCfg := &config.Config{
			AccessToken:    longToken,
			TokenType:      config.TokenTypeLongLived,
			UserID:         userID,
			UserName:       userName,
			TokenExpiresAt: expiresAt,
			AppID:          appID,
			AppSecret:      appSecret,
		}
		if existingCfg != nil {
			if newCfg.AppID == "" {
				newCfg.AppID = existingCfg.AppID
			}
			if newCfg.AppSecret == "" {
				newCfg.AppSecret = existingCfg.AppSecret
			}
		}
		if err := config.Save(newCfg); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
		fmt.Printf("long-lived token saved — authenticated as %s (ID: %s)\n", userName, userID)
		printExpiry(newCfg)
		fmt.Printf("  config: %s\n", config.Path())
	} else {
		fmt.Printf("\nlong-lived token:\n%s\n", longToken)
		if expiresAt != 0 {
			fmt.Printf("expires: %s\n", time.Unix(expiresAt, 0).Format("2006-01-02"))
		}
		fmt.Println("\nto save it, run:")
		fmt.Println("  meta-auth extend-token <token> --save")
		fmt.Println("  or: meta-auth set-token <token>")
	}
	return nil
}

func runRefresh(cmd *cobra.Command, args []string) error {
	appID, appSecret := resolveAppCredentials()
	if appID == "" {
		return fmt.Errorf("META_APP_ID not available — set env var or run: meta-auth login")
	}
	if appSecret == "" {
		return fmt.Errorf("META_APP_SECRET not available — set env var or run: meta-auth login")
	}

	c, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if c.AccessToken == "" {
		return fmt.Errorf("not authenticated — run: meta-auth login or meta-auth set-token <token>")
	}

	days := c.DaysUntilExpiry()
	switch {
	case days == -1:
		fmt.Println("refreshing token (expiry unknown)...")
	case c.IsExpired():
		fmt.Println("token has expired — attempting refresh...")
	default:
		fmt.Printf("current token expires in %d day(s) — refreshing now...\n", days)
	}

	newToken, expiresAt, err := exchangeToLongLived(c.AccessToken, appID, appSecret)
	if err != nil {
		return fmt.Errorf("token refresh failed: %w", err)
	}

	newCfg := &config.Config{
		AccessToken:    newToken,
		TokenType:      config.TokenTypeLongLived,
		UserID:         c.UserID,
		UserName:       c.UserName,
		TokenExpiresAt: expiresAt,
		AppID:          appID,
		AppSecret:      appSecret,
	}
	if newCfg.AppID == "" {
		newCfg.AppID = c.AppID
	}
	if newCfg.AppSecret == "" {
		newCfg.AppSecret = c.AppSecret
	}
	if err := config.Save(newCfg); err != nil {
		return fmt.Errorf("failed to save refreshed token: %w", err)
	}

	fmt.Printf("token refreshed — authenticated as %s\n", c.UserName)
	printExpiry(newCfg)
	return nil
}

func runToken(cmd *cobra.Command, args []string) error {
	c, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if c.AccessToken == "" {
		return fmt.Errorf("not authenticated — run: meta-auth login or meta-auth set-token <token>")
	}
	if c.IsExpired() {
		fmt.Fprintf(os.Stderr, "warning: token has expired — run: meta-auth refresh\n")
	}
	// Print with no trailing newline so $(meta-auth token) works cleanly in shells
	fmt.Print(c.AccessToken)
	return nil
}

func runStatus(cmd *cobra.Command, args []string) error {
	c, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if c.AccessToken == "" {
		fmt.Println("not authenticated")
		fmt.Println("  → meta-auth login            (browser OAuth)")
		fmt.Println("  → meta-auth set-token <tok>  (paste token directly)")
		return nil
	}

	fmt.Printf("authenticated as %s (ID: %s)\n", c.UserName, c.UserID)
	if c.TokenType != "" {
		fmt.Printf("  type:    %s\n", c.TokenType)
	}

	days := c.DaysUntilExpiry()
	switch {
	case days == -1:
		fmt.Println("  expires: unknown (system user token or expiry not tracked)")
	case c.IsExpired():
		fmt.Printf("  expires: EXPIRED on %s — run: meta-auth refresh\n",
			c.ExpiresAt().Format("2006-01-02"))
	case days <= 7:
		fmt.Printf("  expires: %s (%d day(s) left) ⚠️  — run: meta-auth refresh\n",
			c.ExpiresAt().Format("2006-01-02"), days)
	default:
		fmt.Printf("  expires: %s (%d days left)\n",
			c.ExpiresAt().Format("2006-01-02"), days)
	}

	fmt.Printf("  config:  %s\n", config.Path())
	fmt.Println("\nother tools using this token:")
	fmt.Println("  export META_TOKEN=$(meta-auth token)")
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func resolveAppCredentials() (appID, appSecret string) {
	appID = os.Getenv("META_APP_ID")
	appSecret = os.Getenv("META_APP_SECRET")

	if appID == "" || appSecret == "" {
		if c, err := config.Load(); err == nil && c != nil {
			if appID == "" {
				appID = c.AppID
			}
			if appSecret == "" {
				appSecret = c.AppSecret
			}
		}
	}
	return
}

func buildAuthURL(appID, redirectURI, scope string) string {
	params := url.Values{}
	params.Set("client_id", appID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", scope)
	params.Set("response_type", "code")
	return metaDialogURL + "?" + params.Encode()
}

func openBrowser(u string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("open", u)
	case "windows":
		c = exec.Command("cmd", "/c", "start", u)
	default:
		c = exec.Command("xdg-open", u)
	}
	_ = c.Start()
}

func exchangeCode(code, appID, appSecret, redirectURI string) (string, error) {
	params := url.Values{}
	params.Set("client_id", appID)
	params.Set("client_secret", appSecret)
	params.Set("redirect_uri", redirectURI)
	params.Set("code", code)

	tok, _, err := metaTokenFetch(metaTokenURL + "?" + params.Encode())
	return tok, err
}

func exchangeToLongLived(shortToken, appID, appSecret string) (string, int64, error) {
	params := url.Values{}
	params.Set("grant_type", "fb_exchange_token")
	params.Set("client_id", appID)
	params.Set("client_secret", appSecret)
	params.Set("fb_exchange_token", shortToken)

	return metaTokenFetch(metaTokenURL + "?" + params.Encode())
}

// metaTokenFetch performs a GET to a Meta token endpoint and returns
// (accessToken, expiresAtUnix, error). expiresAtUnix is 0 if not provided.
func metaTokenFetch(reqURL string) (string, int64, error) {
	resp, err := http.Get(reqURL) //nolint:noctx
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", 0, fmt.Errorf("parsing token response: %w", err)
	}
	if result.Error != nil {
		return "", 0, fmt.Errorf("meta api error: %s", result.Error.Message)
	}
	if result.AccessToken == "" {
		return "", 0, fmt.Errorf("no access_token in response: %s", string(body))
	}

	var expiresAt int64
	if result.ExpiresIn > 0 {
		expiresAt = time.Now().Unix() + result.ExpiresIn
	}
	return result.AccessToken, expiresAt, nil
}

func fetchMe(token string) (string, string, error) {
	params := url.Values{}
	params.Set("access_token", token)
	params.Set("fields", "id,name")

	resp, err := http.Get(metaMeURL + "?" + params.Encode()) //nolint:noctx
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	var result struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("parsing /me response: %w", err)
	}
	if result.Error != nil {
		return "", "", fmt.Errorf("meta api error: %s", result.Error.Message)
	}
	return result.ID, result.Name, nil
}

func shutdownServer(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func printExpiry(c *config.Config) {
	days := c.DaysUntilExpiry()
	if days == -1 {
		return
	}
	fmt.Printf("  expires: %s (%d days)\n", c.ExpiresAt().Format("2006-01-02"), days)
}
