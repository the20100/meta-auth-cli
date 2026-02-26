# meta-auth

Shared Meta authentication manager for all Meta API CLI tools.

`meta-auth` stores a single Meta access token at `~/.config/meta-auth/config.json` and handles the full token lifecycle: login, refresh, extension, and status. All other Meta CLIs (`meta-ads`, `meta-adlib`, etc.) read from this shared store automatically.

---

## Quick start

```bash
# 1. Set your Meta app credentials (once)
export META_APP_ID=<your_app_id>
export META_APP_SECRET=<your_app_secret>

# 2. Authenticate (browser OAuth — recommended)
meta-auth login

# 3. Check status
meta-auth status

# 4. All other Meta CLI tools now work without any auth setup
meta-ads accounts list
meta-adlib search --query "shoes" --country FR
```

---

## Installation

```bash
git clone https://github.com/the20100/meta-auth-cli
cd meta-auth-cli
go build -o meta-auth .
# Move to your PATH
mv meta-auth /usr/local/bin/
```

---

## Token resolution (all Meta CLIs)

Every Meta CLI resolves the token in this order:

| Priority | Source | How to set |
|----------|--------|------------|
| 1 | `META_TOKEN` env var | `export META_TOKEN=EAABsb...` |
| 2 | Tool's own config | `meta-ads auth login` / `meta-adlib auth set-token` |
| 3 | **meta-auth shared config** | `meta-auth login` ← recommended |

---

## Commands

### `meta-auth login`
Browser OAuth flow. Opens your default browser, waits for the callback, and saves a long-lived token (~60 days).

Requires `META_APP_ID` and `META_APP_SECRET` (env vars or stored from a previous login).

```bash
meta-auth login
meta-auth login --scope "ads_read,public_profile"
```

**Options:**
- `--scope` — OAuth scopes to request (default: `ads_management,ads_read,business_management,public_profile`)

---

### `meta-auth set-token <token>`
Save a token directly — no browser needed. Validates via `GET /me`. Auto-upgrades to long-lived if `META_APP_ID` / `META_APP_SECRET` are available.

```bash
meta-auth set-token EAABsbCS...
meta-auth set-token EAABsbCS... --no-extend
META_APP_ID=123 META_APP_SECRET=abc meta-auth set-token EAABsbCS...
```

**Options:**
- `--no-extend` — skip long-lived upgrade even if app credentials are present

---

### `meta-auth extend-token <short_lived_token>`
Exchange a short-lived token for a long-lived one (~60 days). Prints the result unless `--save` is passed.

```bash
meta-auth extend-token EAABsbCS...
meta-auth extend-token EAABsbCS... --save
```

**Options:**
- `--save` — save the long-lived token to config

---

### `meta-auth refresh`
Re-exchange the **currently stored token** for a fresh long-lived token, resetting the 60-day window from today. No arguments needed — run this once a month to keep the token alive indefinitely.

Requires `META_APP_ID` and `META_APP_SECRET` (env vars or stored in config).

```bash
meta-auth refresh
META_APP_ID=123 META_APP_SECRET=abc meta-auth refresh
```

**Cron example — refresh on the 1st of every month at 09:00:**
```
0 9 1 * * META_APP_ID=... META_APP_SECRET=... meta-auth refresh
```

---

### `meta-auth token`
Print the stored access token to stdout (no trailing newline). Use this to inject the token into other tools or scripts.

```bash
# Export for a session
export META_TOKEN=$(meta-auth token)
meta-ads accounts list
meta-adlib search --query "election" --country US

# Inline
META_TOKEN=$(meta-auth token) meta-ads campaigns list --account act_123
```

---

### `meta-auth status`
Show the current authentication state, token type, expiry, and days remaining.

```bash
meta-auth status
# authenticated as John Doe (ID: 123456789)
#   type:    long-lived
#   expires: 2026-04-15 (51 days left)
#   config:  /Users/you/Library/Application Support/meta-auth/config.json
```

---

### `meta-auth logout`
Remove saved credentials.

```bash
meta-auth logout
```

---

### `meta-auth update` — Self-update

Pull the latest source from GitHub, rebuild, and replace the current binary.

```bash
meta-auth update
```

Requires `git` and `go` to be installed.

---

## Token types

| Type | Expires | How obtained |
|------|---------|--------------|
| `oauth` | ~60 days | `meta-auth login` |
| `long-lived` | ~60 days | `meta-auth extend-token` / `meta-auth set-token` (auto-extended) |
| `manual` | short (1–2h) | `meta-auth set-token --no-extend` |
| `system-user` | never | Pasted from Meta Business Manager System User |

For a truly never-expiring token, create a **System User** in [Meta Business Manager](https://business.facebook.com/) → Business Settings → Users → System Users, generate a token with "Never" expiry, then paste it with `meta-auth set-token`.

---

## Config file

```
macOS:   ~/Library/Application Support/meta-auth/config.json
Linux:   ~/.config/meta-auth/config.json
Windows: %AppData%\meta-auth\config.json
```

```json
{
  "access_token": "EAABsb...",
  "token_type": "long-lived",
  "user_id": "123456789",
  "user_name": "John Doe",
  "token_expires_at": 1744758000,
  "app_id": "your_app_id",
  "app_secret": "your_app_secret"
}
```

Permissions: `0600` (readable only by you).
