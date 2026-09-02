# Home Assistant Add-on: Google Family Link Auth

## About

This add-on performs the interactive Google login for the [Google Family Link integration](https://github.com/noiwid/HAFamilyLink). It launches a real Chromium window (Playwright) inside the container and streams it to your web browser through noVNC, so you sign in and complete 2FA exactly as you would on a desktop. Home Assistant's own container cannot run a browser, which is why this step lives in a separate add-on.

After a successful login, the add-on extracts the Google session cookies Family Link needs, encrypts them, and stores them under `/share/familylink/`. The integration then retrieves them automatically through the add-on's API (see [How the integration gets the cookies](#how-the-integration-gets-the-cookies)). One Google account at a time is supported.

> **Warning**: this project relies on unofficial, reverse-engineered Google endpoints and an automated login. There is no official API: Google can break it at any time, and usage may conflict with Google's Terms of Service. Use at your own risk.

> **Read [SECURITY.md](https://github.com/noiwid/HAFamilyLink/blob/main/SECURITY.md) before you use this.** The session this add-on stores is a Google *account* session belonging to a Family Link parent. Use a dedicated Google parent account for it.

## Installation

1. Go to **Settings > Add-ons > Add-on Store**, open the three-dot menu, choose **Repositories**, and add `https://github.com/noiwid/HAFamilyLink`.
2. Install **Google Family Link Auth**. The prebuilt image is downloaded from GHCR, so the install only takes a moment.
3. Optionally adjust the options in the **Configuration** tab (see [Configuration](#configuration)).
4. Start the add-on. Enabling **Start on boot** and **Watchdog** is recommended.

## How to use

The add-on is reached through **Home Assistant ingress**: no host port is published, and Home Assistant has already authenticated you before the request arrives. There is nothing to open in a firewall and no password to type.

1. Open the add-on and click **Open Web UI** (or use the **Family Link Auth** sidebar panel).
2. Click **Start Authentication**. Chromium starts inside the container, never on your computer.
3. Click the **Open noVNC** link on that page. It opens in the same authenticated session — there is no VNC password.
4. Sign in to Google in the noVNC window and complete 2FA. Wait for the success message showing how many cookies were saved, then close the noVNC tab.
5. Set up the integration in Home Assistant, following [INSTALL.md](https://github.com/noiwid/HAFamilyLink/blob/main/INSTALL.md). On Home Assistant OS the integration discovers the add-on and its token automatically.

To re-authenticate later (expired session), repeat steps 1 to 4. The integration picks up the new cookies automatically.

The browser and its display only exist while you are authenticating: they are started when you click **Start Authentication** and shut down when the session finishes or times out. Between logins there is no browser view to connect to, which is intentional.

### If Home Assistant runs on another machine

Only then do you need a host port. See [Temporarily exposing a host port](https://github.com/noiwid/HAFamilyLink/blob/main/SECURITY.md#temporarily-exposing-a-host-port) — in short: map `8099/tcp` in **Configuration > Network**, restart, unlock the web UI once with the service token, authenticate, then clear the mapping again.

## Configuration

Example add-on configuration:

```yaml
log_level: info
auth_timeout: 300
session_duration: 86400
language: ""
timezone: ""
cookie_allowlist_mode: strict
```

| Option | Type | Default | Description |
|---|---|---|---|
| `log_level` | list: `trace`, `debug`, `info`, `warning`, `error` | `info` | Logging level of the web service and startup scripts. |
| `auth_timeout` | int, 60 to 600 | `300` | Seconds you have to finish the Google login before the session times out. |
| `session_duration` | int, 3600 to 604800 | `86400` | How long a captured Google session may be used before re-authentication is required. **Enforced** since add-on 2.0.0: an expired session is deleted, not merely reported. Note this is a local limit — Google can invalidate a session sooner. See [Cookie expiry](https://github.com/noiwid/HAFamilyLink/blob/main/SECURITY.md#cookie-expiry-and-deletion). |
| `language` | string | `""` | Browser locale and web UI language. Empty: auto-detected from Home Assistant, fallback `en-US`. The web UI itself is translated in English and French; other locales fall back to English. |
| `timezone` | string | `""` | Browser timezone. Empty: auto-detected from Home Assistant, fallback `Europe/Paris`. |
| `cookie_allowlist_mode` | list: `strict`, `legacy` | `strict` | `strict` stores only the Google cookies Family Link needs. `legacy` stores every `google.com` cookie, as versions before 2.0.0 did. See [Cookie minimisation](#cookie-minimisation). |
| `vnc_password` | password | — | **Deprecated and ignored.** Kept only so an existing configuration still validates; the add-on logs a warning if it is set. You can delete it. See [The browser view](#the-browser-view). |

### Ports

| Port | Published by default | Purpose |
|---|---|---|
| 8099 | **no** | Web UI, REST API and the browser view, all behind the same authentication. Reached through ingress. Map a host port only if Home Assistant runs on another machine, and **never expose it to the internet**: `/api/cookies` returns Google session cookies. |
| 5900 | no | VNC server, bound to loopback inside the container. Never published. |

Port **6080** no longer exists. In earlier versions it served noVNC with no authentication at all.

### The browser view

Earlier versions published port 6080 unauthenticated, with a VNC server whose documented default password was `familylink`. That is gone:

- noVNC and its WebSocket bridge are served by the add-on itself at `/vnc`, so they are covered by the add-on's own authentication (ingress, or the service token).
- The VNC server listens on loopback only and has no RFB authentication. There is no password to configure — which also removes VNC's 8-character DES password limit that silently truncated longer values.
- The display stack runs only during a login.
- Only one observer is admitted at a time, so nobody can quietly watch a login in progress.

### Cookie minimisation

A Google login sets cookies for far more than Family Link — Search preferences, YouTube, ads personalisation, consent state. Versions before 2.0.0 encrypted and stored all of them.

In `strict` mode (the default) only these cookie names are stored, and only on `google.com`, `accounts.google.com`, `families.google.com` and `familylink.google.com`:

`SID`, `HSID`, `SSID`, `APISID`, `SAPISID`, `SIDCC`, `__Secure-1PSID`, `__Secure-3PSID`, `__Secure-1PAPISID`, `__Secure-3PAPISID`, `__Secure-1PSIDTS`, `__Secure-3PSIDTS`, `__Secure-1PSIDCC`, `__Secure-3PSIDCC`

`SAPISID` (or its `__Secure-*PAPISID` equivalents) is what the `SAPISIDHASH` authorisation header is derived from; the rest are the session identifiers Google's cookie authentication validates. Security metadata (`secure`, `httpOnly`, `sameSite`, `expires`) is preserved, so a cookie is never replayed with weaker protection than Google set it with.

> **This allowlist has not been verified against every Google region or account type.** It was derived from the cookies the Family Link web client sends, and it needs testing with a dedicated Google test account on regional Google deployments. If authentication stops working after upgrading and the log warns about missing core cookies, set `cookie_allowlist_mode: legacy`, re-authenticate, and please [open an issue](https://github.com/noiwid/HAFamilyLink/issues) saying which region you are in. `legacy` restores the previous behaviour and still keeps the domain allowlist.

Cookie values are never written to the log, and cookie responses are sent with `Cache-Control: no-store`.

## How the integration gets the cookies

- Cookies are stored Fernet-encrypted in `/share/familylink/cookies.enc`, with the key in `/share/familylink/.key` (both mode 0600, in a 0700 directory owned by the add-on's unprivileged user).
- On first start a service token is generated and saved to `/share/familylink/api_key` (0600). The integration reads that file automatically and calls `GET /api/cookies` with it in an `X-API-Key` header: nothing to configure.
- If the API is unreachable, the integration falls back to reading the encrypted file directly from `/share` — and enforces the same expiry.
- The token is never logged and is never accepted in a URL.

> The key and the ciphertext live in the same directory. Anyone who can read all of `/share/familylink` — another add-on with `share` access, or an unencrypted Home Assistant backup — has both halves. The encryption protects a leak of the cookie file alone, not read access to the directory. See [SECURITY.md](https://github.com/noiwid/HAFamilyLink/blob/main/SECURITY.md#what-is-stored-where-and-for-how-long).

### API endpoints (port 8099)

Authentication is one mechanism in two forms: the service token in an `X-API-Key` header, or the httpOnly session cookie the web UI obtains by posting that token once to `POST /api/session`. Under ingress, Home Assistant's own authentication stands in for both.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/health` | **none** | Health check. The only unauthenticated endpoint. |
| `GET /` | none to view | Web UI. Shows a token prompt until the session is unlocked; shows nothing sensitive before that. |
| `POST /api/session` | token in body | Exchange the service token for a short-lived httpOnly session cookie. Rate-limited. |
| `DELETE /api/session` | session | Revoke the caller's UI session. |
| `POST /api/auth/start` | required | Start a login session (one at a time). |
| `GET /api/auth/status/{session_id}` | required | Poll a session: `authenticating`, `completed`, `timeout`, or `error`. |
| `GET /api/cookies/check` | required | Session metadata: whether cookies exist, whether they have expired, when they expire. Never returns a cookie value. |
| `GET /api/cookies` | required | Return the decrypted cookies. `410 Gone` when the stored session has expired or is corrupted — it is deleted at that point. |
| `DELETE /api/cookies` | required | Delete the stored cookies. |
| `GET /vnc/...`, `WS /vnc/websockify` | required | The noVNC client and the framebuffer bridge. |

A token supplied in a query string is refused with `400`, even if the value is correct.

## Troubleshooting

### Where the logs are

- Add-on: **Settings > Add-ons > Google Family Link Auth > Log**. From the CLI: `ha addons logs <repository-hash>_familylink-playwright` (installed add-ons carry a repository hash prefix in their slug).
- Standalone container: `docker logs`; display-stack output is forwarded into the same log.

Set `log_level: debug` for more detail. A successful run logs, among others: `Starting authentication session: <id>`, `display-stack start: Display stack ready`, `Chromium launched with its sandbox enabled`, `Captured N Family Link cookies`, `Saved N cookies to shared storage`.

Credentials, cookie values, coordinates and child identifiers are redacted from the log, so a debug log is reasonably safe to attach to an issue — but read it before you post it.

### No browser window appears on your computer

Expected: Chromium runs inside the container. Use the **Open noVNC** link in the add-on's web UI to see and control it.

### noVNC does not connect

- Start the authentication first. The display stack does not exist until you do, so a `/vnc` page opened beforehand has nothing to connect to.
- Reload the add-on's web UI and use its **Open noVNC** link rather than a bookmarked URL: under ingress the link carries a session-specific path.
- If the page loads but stays disconnected, check the log for `display-stack` lines.
- Only one viewer is allowed at a time. Close other noVNC tabs and reload.

### Black screen in noVNC

Right after starting authentication the display shows a welcome banner, then Chromium replaces it. If it stays black, check the log for display-stack errors.

### Authentication timeout

The login was not finished within `auth_timeout` seconds. Raise the option (up to 600) and have your 2FA device ready before starting.

### `Chromium refused to start with its sandbox enabled`

Your kernel or container runtime does not allow unprivileged user namespaces, and the SUID sandbox helper was not usable either. The add-on continues with the sandbox disabled and says so; the browser still runs as an unprivileged user and only during a login. On standalone Docker, `security_opt: [seccomp=unconfined]` in the compose file usually resolves it.

### Integration cannot find cookies

1. Make sure the add-on is running and authentication completed (success message with the cookie count).
2. Check that `/share/familylink/cookies.enc` exists.
3. A corrupted or expired cookie file is deleted automatically and reported as missing: re-authenticate.
4. On a `403`, the token is wrong. For add-on installs it is read automatically from `/share/familylink/api_key`; make sure you are not overriding it with a stale value in the integration's options.

### `Your Google Family Link session has expired`

Either `session_duration` elapsed, or Google invalidated the session. Re-authenticate through the add-on; the integration resumes automatically. Home Assistant also shows a re-authentication prompt for the integration.

## Support

- Bugs and questions: [GitHub issues](https://github.com/noiwid/HAFamilyLink/issues)
- Security reports: see [SECURITY.md](https://github.com/noiwid/HAFamilyLink/blob/main/SECURITY.md#reporting-a-vulnerability)
- Version history: the add-on's **Changelog** tab, or [CHANGELOG.md](https://github.com/noiwid/HAFamilyLink/blob/main/familylink-playwright/CHANGELOG.md) and [GitHub releases](https://github.com/noiwid/HAFamilyLink/releases)
