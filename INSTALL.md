# Installation Guide

Complete setup guide for the Google Family Link integration for Home Assistant.

> **Warning**: this project relies on unofficial, reverse-engineered Google endpoints. There is no official API: Google can change or break it at any time, and usage may conflict with Google's Terms of Service. Use at your own risk.

## How it works

The integration relies on a separate **auth service** (a Home Assistant add-on, or a standalone Docker container) that performs the interactive Google login and hands the session cookies over; the full architecture is described in the [README](README.md#how-it-works).

Pick the route that matches your Home Assistant installation:

| Your Home Assistant | Auth service | Follow |
|---|---|---|
| Home Assistant OS or Supervised | The add-on from this repository | [Route A](#route-a-home-assistant-os-or-supervised) |
| Home Assistant Container or Core | Standalone Docker container | [Route B](#route-b-home-assistant-container-or-core) |

Both routes then continue with the same [integration install](#install-the-integration) and [configuration flow](#configuration-flow).

## Prerequisites

- A Google account with Family Link configured and at least one supervised child.
- Route A: a Home Assistant installation with the add-on store (OS or Supervised).
- Route B: Docker (ideally with Docker Compose) on any machine Home Assistant can reach.
- HACS (optional but recommended) for easy install and updates of the integration.

## Route A: Home Assistant OS or Supervised

[![Open your Home Assistant instance and show the add add-on repository dialog with a specific repository URL pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fnoiwid%2FHAFamilyLink)

1. Go to **Settings > Add-ons > Add-on Store**, open the three-dot menu, choose **Repositories**, and add `https://github.com/noiwid/HAFamilyLink`.
2. Install **Google Family Link Auth**. The image is built locally, so the install takes several minutes.
3. Start the add-on. Enabling **Start on boot** and **Watchdog** is recommended.
4. Log in to Google through the add-on: click **Open Web UI** (this opens through Home Assistant ingress, so no port has to be reachable and there is no password to type), click **Start Authentication**, then use the **Open noVNC** link on that page to finish the Google login and 2FA in the browser window it shows. The full walkthrough, the options reference, and add-on troubleshooting are in the [add-on documentation](familylink-playwright/DOCS.md).
5. That is all on the auth side: the integration auto-detects the add-on and reads its service token automatically. Continue with [Install the integration](#install-the-integration).

> Read [SECURITY.md](SECURITY.md) before you rely on this. In particular, use a **dedicated Google parent account**: the session the add-on stores is a Google account session, not a Family Link-scoped one.

## Route B: Home Assistant Container or Core

1. Run the standalone auth container: [DOCKER_STANDALONE.md](DOCKER_STANDALONE.md) covers the Docker Compose file, environment variables, volumes, the single port, and the service token.
2. Read the service token: `cat ./data/api_key`.
3. Authenticate through its web UI (`http://<docker-host>:8099`): paste the token to unlock the page, click **Start Authentication**, then use the **Open noVNC** link to finish the Google login. Everything is on port 8099 now.
4. Note two values for the integration: the URL `http://<docker-host>:8099` and the token. **Do not append the token to the URL** - it goes in its own field.
5. Continue with [Install the integration](#install-the-integration). In the configuration flow, choose **Manual URL configuration (Docker standalone)**.

> Read [SECURITY.md](SECURITY.md) before you rely on this, and use a **dedicated Google parent account**.

## Install the integration

### Via HACS (recommended)

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=noiwid&repository=HAFamilyLink&category=integration)

1. In HACS, open the three-dot menu and choose **Custom repositories**.
2. Add repository `https://github.com/noiwid/HAFamilyLink` with category **Integration**.
3. Search for **Google Family Link** and download the latest version.
4. Restart Home Assistant.

### Manual

1. Download `familylink.zip` from the [latest release](https://github.com/noiwid/HAFamilyLink/releases), or copy the `custom_components/familylink` folder from the repository.
2. Extract or copy it into your Home Assistant `config/custom_components/` directory, so that `config/custom_components/familylink/manifest.json` exists. Copy the folder in full: it contains subpackages (`auth/`, `client/`, `translations/`, `utils/`) and non-Python files (`services.yaml`, `strings.json`) that the integration needs; a partial copy will not load.
3. Restart Home Assistant.

## Upgrading from a version before 2.0.0

Existing installations keep working; the migration is automatic. What changes:

- **The auth-service key moves out of the URL.** A config entry of the form `http://host:8099?api_key=...` is rewritten on upgrade so the key lives in its own secret field and is sent as an `X-API-Key` header. Nothing to do by hand.
- **The add-on is reached through ingress**, and no host port is published any more. Port 6080 is gone entirely - noVNC is served on 8099 behind the same authentication. If Home Assistant runs on a different machine than the add-on, see [temporarily exposing a host port](SECURITY.md#temporarily-exposing-a-host-port).
- **`vnc_password` is ignored.** You can delete it from the add-on configuration.
- **`session_duration` is now enforced.** A stored session older than that setting is deleted on first read, so you may be asked to sign in once after upgrading. That is the intended behaviour: before 2.0.0 the option did nothing.
- **Only the Google cookies Family Link needs are stored.** See [cookie minimisation](familylink-playwright/DOCS.md#cookie-minimisation), including the `legacy` escape hatch if strict mode fails in your Google region.

For standalone Docker there are compose-file changes as well: see [Migrating from 1.x](DOCKER_STANDALONE.md#migrating-from-1x).

## Configuration flow

Go to **Settings > Devices & Services > Add Integration** and search for **Google Family Link**.

### Step 1: connection method

The first screen is a menu with two options:

| Option | When to use it |
|---|---|
| **Auto-detect (add-on or local file)** | Route A. The integration finds the auth service on its own, trying in order: the add-on resolved through the Supervisor, then `http://localhost:8099`, then the encrypted cookie file `/share/familylink/cookies.enc`. |
| **Manual URL configuration (Docker standalone)** | Route B. You enter the container URL yourself. |

If auto-detect finds nothing, the flow falls back to the manual URL form.

### Step 2 (manual URL only): authentication server URL

Two fields:

| Field | Notes |
|---|---|
| **Authentication Server URL** | For example `http://192.168.1.100:8099`. No query string. |
| **Auth service API token** | The value from the container's `data/api_key` file, or its `API_TOKEN` environment variable. Sent as an `X-API-Key` header. |

The token has its own field because a credential in a URL leaks through browser history, proxy logs and `Referer` headers - the auth service refuses one in a query string with HTTP 400, even if the value is correct. If you paste a legacy `http://host:8099?api_key=...` URL anyway, the flow splits it for you and moves the key into the token field.

The flow verifies the URL with `GET /api/health`, checks the token against `GET /api/cookies/check`, and then fetches the cookies. If an error appears, see [Troubleshooting (setup)](#troubleshooting-setup) below.

### Step 3: settings

| Field | Default | Range | Notes |
|---|---|---|---|
| Integration Name | `Google Family Link` | | Display name of the config entry. |
| Update Interval (seconds) | `60` | 30 to 3600 | How often data is fetched from Google. |
| Request Timeout (seconds) | `30` | 10 to 120 | Timeout of each API request. |
| Enable GPS location tracking | off | | Adds a device tracker and a battery sensor per child. Each location poll may send a notification to the child's device, so it is disabled by default for privacy. Coordinates and addresses are never written to the Home Assistant log. |

The first data fetch runs during setup, so entities appear as soon as the flow completes. Entities are created per child (for example `sensor.<child>_daily_screen_time`) and per device (for example `switch.<device>`); the full entity and service catalog is in the [README](README.md).

### Changing settings later

**Settings > Devices & Services > Google Family Link > Configure** exposes the same update interval, timeout, and GPS options, plus the **Auth service API token**. Leave the token field empty to keep the stored one - it is never pre-filled, so a secret is not sent back out to the browser just to be displayed. Saving reloads the integration.

## Re-authentication

Sessions expire for two independent reasons, and both land you in the same place:

- **The local lifetime elapsed.** The auth service enforces its `session_duration` option (default 24 hours). At that point the stored session is *deleted*, not just flagged, so it cannot be replayed.
- **Google invalidated it.** Google can end a session sooner - after a password change, a security review, or a sign-out elsewhere. `session_duration` does not extend Google's own decision.

What happens then:

1. The integration fetches fresh cookies from the auth service and retries once.
2. If that also fails, it clears its cached cookies and HTTP session, puts the config entry into Home Assistant's **re-authentication** state, and creates a persistent notification (one notification, not one per failed poll).
3. Open the auth web UI (add-on **Open Web UI**, or `http://<docker-host>:8099`), click **Start Authentication**, and finish the Google login through noVNC again.
4. Nothing to reload on the integration side: fresh cookies are picked up automatically on the next poll, and the notification resets after the next successful fetch. If Home Assistant is showing a re-authentication prompt, submit it once you have signed in again (the token field can stay empty unless the token itself changed).

## Troubleshooting (setup)

Auth-service issues (noVNC not connecting, black screen, login timeout) are covered in the [add-on documentation](familylink-playwright/DOCS.md#troubleshooting) and, for the container, in [DOCKER_STANDALONE.md](DOCKER_STANDALONE.md#troubleshooting).

### "Google Family Link" not found when adding the integration

- Check that `config/custom_components/familylink/manifest.json` exists at exactly that path.
- Restart Home Assistant after installing (required for new custom components), then clear the browser cache.
- Check **Settings > System > Logs** for import errors at startup.

### "Cannot connect" in the configuration flow

- Verify the auth service is running and healthy: `curl http://<host>:8099/api/health`.
- Verify Home Assistant can reach that host and port (Docker network, VLANs, firewall).

### "The auth service rejected the token" (HTTP 401 or 403)

- Route B: put the token in the **Auth service API token** field, copied from the container's `data/api_key` file or its `API_TOKEN` variable. Not in the URL.
- Route A: the token is read automatically from `/share/familylink/api_key`; a rejection usually means a stale value is set in the integration's options. Clear the token field (empty means "use the discovered one") or prefer auto-detect.
- Repeated wrong tokens are rate-limited; the service answers HTTP 429 for a minute after ten failures from the same address.

### "API tokens must not be passed in the URL" (HTTP 400)

The configured URL still contains `?api_key=...`. Upgrading the integration migrates existing entries automatically, so this only appears if you typed one in by hand: remove the query string and use the token field.

### "The stored Google session has expired" (HTTP 410)

The session outlived `session_duration` (or was corrupted) and has been deleted. Sign in again through the auth web UI; see [Re-authentication](#re-authentication).

### "No cookies found"

- Complete the Google login through the auth web UI first, and wait for the success message showing how many cookies were saved.
- Route A: check that `/share/familylink/cookies.enc` exists.

### Integration loads but shows no or partial data

- You need at least one supervised child, and the child needs at least one device.
- The first fetch runs during setup and data then refreshes every 60 seconds by default; check the logs (filter `familylink`) for API errors.
- Top-app sensors stay unavailable until the child has used apps today.

## Uninstalling

1. **Settings > Devices & Services > Google Family Link**, three-dot menu, **Delete**.
2. Remove the integration files: via HACS (**Remove**) or by deleting `config/custom_components/familylink/`, then restart Home Assistant.
3. Route A: uninstall the add-on and optionally remove the repository from the add-on store. Route B: stop and remove the container (`docker compose down`).
4. Optionally delete the stored cookies: `/share/familylink/` (Route A) or the container's `./data` directory (Route B).

## Getting help

Search the [existing issues](https://github.com/noiwid/HAFamilyLink/issues) or open a new one. Include your Home Assistant version, the integration and auth container versions, and the relevant log lines (**Settings > System > Logs**, filter `familylink`).
