# Docker Standalone Guide

How to run the Family Link auth service as a standalone Docker container, for **Home Assistant Container** or **Home Assistant Core** (no Supervisor, so no add-on store). The integration side of the setup (install, configuration flow) is covered in [INSTALL.md](INSTALL.md), Route B.

> **Warning**: this project relies on unofficial, reverse-engineered Google endpoints. There is no official API: Google can change or break it at any time. Use at your own risk.

> **Read [SECURITY.md](SECURITY.md) first.** This container stores a Google *account* session belonging to a Family Link parent. Use a dedicated Google parent account, and keep the container off the internet.

## Upgrading from a version before 2.0.0?

Jump to [Migrating from 1.x](#migrating-from-1x) — the ports and the API key handling both changed.

## Prerequisites

- Docker (and ideally Docker Compose) on a machine your Home Assistant can reach.
- A Google account with Family Link configured. Preferably a dedicated parent account.

## Quick start

### Option 1: Docker Compose (recommended)

Create a directory for the service, and inside it a `docker-compose.yml`:

```yaml
services:
  familylink-auth:
    # Pin an explicit version. There is deliberately no mutable ":standalone"
    # tag any more: a moving production tag means an unreviewed image rolls out
    # on the next `docker compose pull`.
    image: ghcr.io/noiwid/familylink-auth:2.0.0-standalone
    container_name: familylink-auth
    # Reap the display stack's X processes, which are re-parented to PID 1.
    init: true
    ports:
      # Web UI, REST API and the browser view, all behind the service token.
      # Bound to loopback: only the Docker host can reach it. If Home Assistant
      # runs on another machine, change this to "8099:8099" and keep it inside
      # a trusted LAN.
      - "127.0.0.1:8099:8099"
    volumes:
      - ./data:/share/familylink:rw
    shm_size: '2gb'  # Chromium needs more than Docker's 64MB default
    security_opt:
      # Lets Chromium create the user namespaces its sandbox needs. Without it
      # the service still works but logs a warning and runs the browser
      # unsandboxed.
      - seccomp=unconfined
    environment:
      - LOG_LEVEL=info
      - AUTH_TIMEOUT=300
      - SESSION_DURATION=86400
      - LANGUAGE=en-US
      - TIMEZONE=Europe/Paris
      - COOKIE_ALLOWLIST_MODE=strict
      # A token is generated on first start and written to ./data/api_key
      # (mode 0600). Set this only if you want to supply your own (>= 16 chars).
      # - API_TOKEN=change-me-to-at-least-16-characters
    dns:
      - 8.8.8.8
      - 8.8.4.4
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8099/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
```

Then start it:

```bash
docker compose up -d
```

### Option 2: Docker Run

```bash
docker run -d \
  --name familylink-auth \
  --init \
  --shm-size=2gb \
  --security-opt seccomp=unconfined \
  -p 127.0.0.1:8099:8099 \
  -v $(pwd)/data:/share/familylink:rw \
  -e LOG_LEVEL=info \
  -e AUTH_TIMEOUT=300 \
  -e SESSION_DURATION=86400 \
  -e LANGUAGE=en-US \
  -e TIMEZONE=Europe/Paris \
  -e COOKIE_ALLOWLIST_MODE=strict \
  --dns 8.8.8.8 \
  --dns 8.8.4.4 \
  --restart unless-stopped \
  ghcr.io/noiwid/familylink-auth:2.0.0-standalone
```

Both `linux/amd64` and `linux/arm64` are supported; Docker pulls the right image automatically.

The service runs as a dedicated unprivileged user (`familylink`, uid 1000) inside the container, and starts as root only long enough to prepare the data directory and the D-Bus socket.

## Configuration

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `LOG_LEVEL` | `info` | Logging level (`debug`, `info`, `warning`, `error`) |
| `AUTH_TIMEOUT` | `300` | Seconds you have to finish the Google login before the session times out. Clamped to 60–600 |
| `SESSION_DURATION` | `86400` | How long a captured Google session may be used before re-authentication is required. **Enforced** since 2.0.0. Clamped to 3600–604800. A local limit only — Google can invalidate a session sooner; see [Cookie expiry](SECURITY.md#cookie-expiry-and-deletion) |
| `LANGUAGE` | `en-US` | Browser locale for the Google login pages |
| `TIMEZONE` | `Europe/Paris` | Container and browser timezone |
| `COOKIE_ALLOWLIST_MODE` | `strict` | `strict` stores only the Google cookies Family Link needs; `legacy` stores every `google.com` cookie, as 1.x did. See [cookie minimisation](familylink-playwright/DOCS.md#cookie-minimisation) |
| `API_TOKEN` | generated | The service token guarding every endpoint except `/api/health`. Generated on first start and persisted to `./data/api_key` (0600) if unset. Must be at least 16 characters if you set it — a shorter one is refused and the service will not start |
| `API_KEY` | — | Deprecated alias for `API_TOKEN`, still honoured |
| `VNC_PASSWORD` | — | **Deprecated and ignored.** The container logs a warning if it is set. There is no VNC password any more; see [The browser view](#the-browser-view) |
| `FAMILYLINK_VNC_BACKEND` | `auto` | Display backend: `auto` (TigerVNC, with automatic fallback to Xvfb + x11vnc), `tigervnc`, or `x11vnc` |

### Volumes

| Host path | Container path | Contents |
|---|---|---|
| `./data` | `/share/familylink` | `cookies.enc` (Fernet-encrypted Google session cookies), `.key` (the encryption key), `api_key` (the service token) |

Keep this volume across container recreations so you do not have to log in to Google again after every update.

Treat the directory as containing a live Google session: the key sits next to the ciphertext, so anyone who can read the whole directory can decrypt it. The encryption protects a leak of `cookies.enc` alone. See [SECURITY.md](SECURITY.md#what-is-stored-where-and-for-how-long).

### Ports

| Port | Published | Purpose |
|---|---|---|
| `8099` | yes, loopback by default | Web UI, REST API and the browser view. **Never expose it to the internet**: `/api/cookies` returns Google session cookies |
| `5900` | no | VNC server, bound to loopback inside the container |

Port **6080** is gone. In 1.x it served noVNC with no authentication whatsoever.

### The browser view

noVNC is served by the service itself at `/vnc`, behind the same authentication as the API, and the VNC server it bridges to listens on loopback inside the container with no RFB authentication. There is no VNC password to set — which also removes VNC's 8-character DES limit that silently truncated longer values, and the publicly known `familylink` default that 1.x shipped with.

The X server, window manager and browser are started when you begin authenticating and stopped when the session ends, so between logins there is no framebuffer to observe. Only one viewer is admitted at a time.

### DNS

The `dns` entries (`8.8.8.8`, `8.8.4.4`) make the container resolve Google domains directly. This matters if you run Pi-hole, AdGuard, or another local DNS that might interfere with Google services.

## Authentication

Everything happens on **one port** now:

1. Read the service token:
   ```bash
   cat ./data/api_key
   ```
2. Open the web UI: `http://<docker-host>:8099`. Paste the token once and click **Unlock**. It is exchanged for a short-lived httpOnly cookie; the token itself is never put in a URL and never stored by the page.
3. Click **Start Authentication**. Chromium launches inside the container.
4. Click **Open noVNC** on the same page — no password.
5. Complete the Google login and 2FA in the Chromium window shown through noVNC.
6. Wait for the success message showing how many cookies were saved, then close the noVNC tab.

To re-authenticate after the session expires, repeat the same steps; the integration picks up the new cookies automatically (see [Re-authentication](INSTALL.md#re-authentication)).

## The service token

Every endpoint except `GET /api/health` requires it. It is generated on first start (32 random bytes) and stored in `./data/api_key` with mode 0600, and it is never written to the log.

- Give it to the integration in the **Auth service API token** field of the configuration flow — see [INSTALL.md](INSTALL.md#configuration-flow).
- **Do not append it to the URL.** A token in a query string is refused with HTTP 400, even if the value is correct, because a credential in a URL leaks through history, proxy logs and `Referer` headers. An existing `?api_key=…` configuration is migrated automatically when you upgrade the integration.
- If the token cannot be generated, written or read, the service refuses to start rather than coming up unprotected.
- Failed attempts are rate-limited, and the comparison is constant-time.
- To rotate it: delete `./data/api_key`, restart the container, and paste the new value into the integration's options. See [rotation](SECURITY.md#rotating-credentials-after-a-suspected-compromise).

Token or not, keep port 8099 inside your trusted network.

## Connecting to Home Assistant

Install the integration and run the configuration flow as described in [INSTALL.md, Route B](INSTALL.md#route-b-home-assistant-container-or-core): enter `http://<docker-host>:8099` as the URL and the token in the separate token field.

## Migrating from 1.x

Nothing needs to be re-authenticated, but three things change:

1. **Port 6080 is gone.** Remove the `- "6080:6080"` mapping from your compose file. noVNC is now at `http://<docker-host>:8099/vnc/` and reachable through the web UI's **Open noVNC** link.
2. **`VNC_PASSWORD` is ignored.** Remove it. The container logs a deprecation warning if it is still set.
3. **The API key is now mandatory and is generated for you.** If you were running without `API_KEY`, a token is generated on first start into `./data/api_key`; take it from there and put it in the integration's token field. If you were running *with* `API_KEY`, it keeps working (also under its new name `API_TOKEN`), but the integration must now send it as a header — the `?api_key=` URL form is refused. The integration migrates an existing entry automatically on upgrade; nothing to do by hand.
4. **The image tag changed.** Replace `:standalone` with an explicit version such as `:2.0.0-standalone`.
5. **Recommended:** bind the port to loopback (`127.0.0.1:8099:8099`) unless Home Assistant runs on another machine, and add `init: true` and `security_opt: [seccomp=unconfined]`.

Your existing `cookies.enc` keeps working. On first read its expiry is derived from its stored timestamp and your `SESSION_DURATION`, so a session older than that is deleted and you are asked to sign in again — which is the intended behaviour, since 1.x never enforced the setting at all.

## Updating

### Docker Compose

```bash
# Edit the image tag to the new version first
docker compose pull
docker compose up -d
```

### Docker Run

```bash
docker pull ghcr.io/noiwid/familylink-auth:<new-version>-standalone
docker stop familylink-auth
docker rm familylink-auth
# Re-run the docker run command above with the new tag
```

Your Google login survives updates as long as the `./data` volume is kept. Version history is in the [auth service changelog](familylink-playwright/CHANGELOG.md).

## Troubleshooting

### Container won't start

- Make sure `shm_size` is at least `2gb` (Chromium needs the shared memory).
- Check the logs: `docker logs familylink-auth`.
- `The configured API token is too short`: `API_TOKEN` must be at least 16 characters. Unset it to have one generated instead.
- `Could not prepare the secret directory`: the `./data` volume is not writable by uid 1000. Fix with `sudo chown -R 1000:1000 ./data`.

### Cannot access noVNC

- Start the authentication first: the display stack does not exist until you do.
- Use the **Open noVNC** link in the web UI rather than a bookmarked URL.
- Only one viewer is allowed at a time; close other noVNC tabs and reload.
- For display failures, check `docker logs familylink-auth` — the display-stack output is forwarded there.

### `Chromium refused to start with its sandbox enabled`

Add `security_opt: [seccomp=unconfined]` (compose) or `--security-opt seccomp=unconfined` (docker run). Without it the service still authenticates, but the browser runs unsandboxed and says so in the log.

### Integration cannot connect

- Ensure the container is running: `docker ps | grep familylink`.
- Check the health endpoint: `curl http://<docker-host>:8099/api/health`.
- **HTTP 401 or 403** on the cookies endpoint: the token is missing or wrong. Copy it from `./data/api_key` into the integration's **Auth service API token** field.
- **HTTP 400** with "API tokens must not be passed in the URL": you still have `?api_key=…` in the configured URL. Remove the query string and use the token field.
- **HTTP 410**: the stored session expired and was deleted. Re-authenticate.
- If the port is bound to `127.0.0.1` and Home Assistant runs elsewhere, change the mapping to `8099:8099`.

### DNS issues (Pi-hole, AdGuard, etc.)

- The `dns` entries in the compose file bypass local DNS for the container.
- If problems persist, try `network_mode: host` (you lose port mapping, and the service then listens on every host interface — only do this on a trusted network).

## Image tags

| Tag | Description |
|---|---|
| `<version>-standalone` | Standalone image as of repository release `v<version>`, e.g. `2.0.0-standalone`. **Use this.** |
| `<version>` | Add-on image as of repository release `v<version>` (for HA OS/Supervised only) |
| `latest` | Latest add-on image (for HA OS/Supervised only) |

The mutable `standalone` tag is no longer published: pinning a version is what keeps an unreviewed image from rolling out on your next `pull`. Versioned tags follow the repository's release tag (the integration version), not the add-on version shown in the add-on store.
