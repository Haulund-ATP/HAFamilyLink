# Changelog

All notable changes to the Google Family Link Auth Add-on will be documented in this file.

## [2.0.0] - 2026-09-02

Security-hardening release. Read [Migrating from 1.x](https://github.com/noiwid/HAFamilyLink/blob/main/DOCKER_STANDALONE.md#migrating-from-1x) for standalone Docker, and the [upgrade notes](https://github.com/noiwid/HAFamilyLink/blob/main/INSTALL.md#upgrading-from-a-version-before-200) for the add-on. Existing logins are not invalidated by the upgrade itself, but a session older than `session_duration` now has to be redone - see below.

### Security

- **Every endpoint except `GET /api/health` now requires authentication.** `POST /api/auth/start`, `GET /api/auth/status/{id}`, `GET /api/cookies`, `DELETE /api/cookies` and `GET /api/cookies/check` were previously reachable without credentials in at least some configurations - `/api/cookies/check` in all of them, and `/api/cookies` itself in standalone mode unless `API_KEY` happened to be set. `/api/cookies` returns a live Google session, so on a home network the supervised child could read it and lift their own restrictions.
- **One authentication mechanism, and it fails closed.** A 256-bit service token is generated on first start and persisted to `/share/familylink/api_key` (mode 0600, atomic write, symlinks refused). If it cannot be generated, written or read, the service refuses to start instead of coming up unprotected. Standalone installs get the same treatment - no more "open by default with a warning in the log".
- **Tokens are no longer accepted in a query string.** A credential in a URL leaks through browser history, proxy logs and `Referer` headers. `?api_key=` is now refused with HTTP 400 even when the value is correct; the browser UI trades the token once for an httpOnly, SameSite=Strict session cookie via `POST /api/session`. Existing integration configurations of the form `http://host:8099?api_key=...` are migrated automatically.
- **Token comparison is constant-time, and attempts are rate-limited** (ten failures per minute per client address, answered with HTTP 429 and `Retry-After`).
- **The unauthenticated noVNC port 6080 is gone.** It served a live view of - and control over - a browser holding a Google session to anyone who could reach it. noVNC and its WebSocket bridge are now served by the service itself at `/vnc`, behind the same authentication, and only one observer is admitted at a time.
- **The VNC password is gone, including the publicly known default `familylink`.** The VNC server binds to loopback with no RFB authentication and is reachable only through the authenticated bridge. This also removes VNC's 8-character DES password limit, which silently truncated anything longer. The `vnc_password` option still validates so existing configurations do not break, but it is ignored and logs a deprecation warning.
- **Home Assistant ingress is used, and no host port is published by default.** Ingress authenticates the Home Assistant user before the request arrives. Ingress is trusted only while the host port is unpublished; map one and the add-on stops trusting the ingress header, because at that point anyone reaching the port could forge it.
- **The display stack only exists during a login.** The X server, window manager and browser are started when authentication begins and torn down when it ends or times out, so there is no framebuffer to observe between logins.
- **Chromium runs sandboxed, as an unprivileged user.** The service, the X server and the browser all run as a dedicated non-root account, which is what allowed `--no-sandbox` and `--disable-setuid-sandbox` to be removed. Cross-site process isolation is restored - `IsolateOrigins` and `site-per-process` are no longer disabled. The image also ships the SUID sandbox helper for kernels that refuse unprivileged user namespaces; if neither mechanism works the service logs a clear warning and continues unsandboxed rather than failing to authenticate.
- **Only the Google cookies Family Link needs are stored.** A login sets cookies for Search, YouTube, ads personalisation and consent state; all of them used to be encrypted and handed to the integration. An explicit name and domain allowlist now applies, with `cookie_allowlist_mode: legacy` as a documented escape hatch for regional Google variations. Security metadata (`secure`, `httpOnly`, `sameSite`) is preserved. See [Cookie minimisation](https://github.com/noiwid/HAFamilyLink/blob/main/familylink-playwright/DOCS.md#cookie-minimisation) - the allowlist still needs testing against a real Google test account in other regions.
- **`session_duration` is now enforced.** It previously did nothing. The stored envelope records creation and expiry; an expired session is deleted rather than merely reported, and so is one that cannot be decrypted or parsed, or that has no usable timestamp. Cookie responses are sent with `Cache-Control: no-store`.
- **Log redaction.** Cookie values, `Cookie`/`Authorization` headers, `SAPISID` and `SAPISIDHASH` values, the service token and credential-bearing URLs are scrubbed centrally, including from exception tracebacks.
- **Storage hardening.** The secret directory stays 0700 and secret files 0600; writes are atomic (`O_EXCL` temporary file in the same directory, then `os.replace`, with `fsync`); secrets are opened `O_NOFOLLOW` and a symlink found where a secret belongs is refused. Note that the encryption key lives beside the ciphertext, so read access to the whole directory still yields the session - documented rather than glossed over.
- **Security headers** on every response: `Cache-Control: no-store`, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `X-Frame-Options: SAMEORIGIN`, and a Content-Security-Policy with a per-response nonce for the UI's inline script. The permissive CORS policy was removed - the UI is same-origin and the integration is a server-side client.

### Changed

- Dependencies updated to current supported versions (FastAPI 0.141.1, Starlette 1.6.0, Uvicorn 0.52.4, Pydantic 2.13.5, cryptography 50.0.1) and locked with hashes in `requirements.txt`, installed with `pip --require-hashes`. Playwright is pinned (1.58.0) instead of installed unversioned.
- `aiofiles`, `jinja2` and `python-multipart` removed: unused.
- Base images pinned by digest as well as tag; GitHub Actions pinned by commit SHA; Dependabot added for pip, Docker and Actions.
- The mutable `:standalone` image tag is no longer published. Pin an explicit version, e.g. `2.0.0-standalone`.
- The standalone compose file binds port 8099 to loopback, sets `init: true` (to reap the display stack's re-parented X processes) and `security_opt: [seccomp=unconfined]` (so Chromium can create the user namespaces its sandbox needs).
- Startup and shutdown moved to a FastAPI lifespan handler, since Starlette 1.x removed `@app.on_event`.
- Interactive API docs (`/docs`, `/redoc`, `/openapi.json`) are disabled: nothing consumed them, and they enumerated the protected endpoints.

### Fixed

- **The display stack could report a spurious failure and abort a login.** Its control script was run with a pipe for stdout, and the backgrounded X server and window manager inherit that pipe - so waiting for end-of-file blocked for the full timeout on every *successful* start. The timeout handler then called `kill()` on the already-exited script, raising a `ProcessLookupError` whose string form is empty, which surfaced as `Failed to start auth:` with no reason at all. Completion is now detected by waiting for the process to exit, with its output captured to a file, and the kill path tolerates the race.
- **The log-redaction filter could break logging.** Redacting a `%`-style format string such as `"token=%s"` removed the placeholder while the argument was still present, so the record raised `TypeError` when a handler formatted it. The message is now interpolated first and the arguments dropped.
- **Exception tracebacks were not redacted.** At filter time a traceback still lives in `exc_info`, not `exc_text`, so a secret in an exception message reached the log. It is now rendered, redacted and cached before any handler can print the original.
- Dead X processes were reported as "did not stop" and needlessly signalled, because `kill -0` succeeds for an unreaped process. The liveness check now looks at process state.

## [1.8.1] - 2026-08-21

### Changed
- **Add-on installs now pull the prebuilt multi-arch image from GHCR instead of compiling locally.** Installing previously built the whole image (Chromium and Playwright included) on the Home Assistant machine, which took a long time on low-power hardware. The add-on now declares `image: ghcr.io/noiwid/familylink-auth`, and CI publishes that image tagged with the add-on version on every push, so the Supervisor downloads it in seconds. Local builds keep working as a fallback (`build.json` is unchanged).

## [1.8.0] - 2026-07-24

### Fixed
- **noVNC no longer hangs on "Connecting..." forever (#136).** The display stack (Xvfb, fluxbox, x11vnc, websockify) used to start with all output discarded and no liveness check, so any failure was invisible: the container looked healthy while noVNC never rendered. Each display process now logs to `/var/log/familylink/<proc>.log` (journald in add-on mode), is re-checked after launch, and dumps its last log lines on failure.
- **Stale X99 state is cleaned on start.** A non-graceful stop left `/tmp/.X11-unix/X99` and `/tmp/.X99-lock` behind, which silently prevented the display server from binding on the next start. Both are removed before startup.
- **VNC password length.** VNC authentication only uses the first 8 characters of the password. The password is now truncated explicitly with a warning, and the web UI auto-connect URL embeds the same 8-character value so client and server agree.

### Changed
- **TigerVNC is now the default display backend**, with automatic fallback to the legacy Xvfb + x11vnc stack. TigerVNC's Xvnc serves VNC natively, removing the x11vnc screen scraper that crashed the moment a client connected. Force a backend with `FAMILYLINK_VNC_BACKEND=tigervnc|x11vnc`.

## [1.7.1] - 2026-06-15

### Fixed
- **Standalone: `/api/cookies` no longer requires a key by default (#125).** The 1.7.0 always-on key broke existing Docker standalone setups: the auth container and the HA integration don't share a volume, so the auto-generated key could never reach the integration and every cookie fetch returned 403 ("cookies not available"). The endpoint is now key-protected only when it can be consumed without manual steps — i.e. when `API_KEY` is set explicitly, or when running as a Supervisor add-on (HA OS/Supervised), where the key is shared via `/share/familylink/api_key`. In standalone without `API_KEY` the endpoint stays open (pre-1.7.0 behavior) and logs a warning recommending `API_KEY`.

## [1.7.0] - 2026-06-12

### Security
- **`/api/cookies` now always requires an API key** — previously the endpoint served the parent's full Google session cookies to anyone on the LAN (including the supervised child's devices), allowing a complete Family Link bypass. A key is auto-generated on first start and persisted in `/share/familylink/api_key` (`./data/api_key` in standalone mode); the `API_KEY` environment variable can override it. The auth-flow endpoints (`/api/auth/*`) remain usable from the web UI without a key unless `API_KEY` is explicitly set.
- API key comparison now uses a constant-time check
- The noVNC link no longer embeds a custom `vnc_password` in the unauthenticated web page (only the documented default is auto-filled)

### Changed
- **HA OS / Supervised**: no action needed — the integration reads the key automatically from the shared directory
- **Docker standalone**: the HA integration URL must now include the key: `http://<host>:8099?api_key=<key>` (update the integration to its matching version first)

### Fixed
- Status polling no longer returns HTTP 500 after a completed session is cleaned up (web UI could previously stay stuck on "waiting")
- Encryption key generation no longer crashes on first start when `/share/familylink` does not exist yet
- Web UI now forwards `?api_key=` to protected endpoints, so setting `API_KEY` no longer breaks the authentication flow

## [1.6.1] - 2026-05-12

### Fixed
- **noVNC welcome banner** — Display a clear welcome message on the Xvfb desktop via `xterm` so users connecting to noVNC before starting the auth flow no longer see a black screen (#108)

### Changed
- Added `xterm` to the base Dockerfile dependencies (both add-on and standalone images)

## [1.6.0] - 2025-03

### Added
- **noVNC web-based access** — Replace external VNC client requirement with browser-based access via noVNC on port 6080
- **Auto-detection of language and timezone** — Reads HA settings via Supervisor API when add-on options are left empty
- **Bilingual web UI (FR/EN)** — New `translations.py` module with French and English support, auto-switching based on language setting
- **DNS configuration** — Added Google DNS (8.8.8.8, 8.8.4.4) to docker-compose for Pi-hole compatibility

### Changed
- x11vnc now restricted to localhost only (no external raw VNC access)
- websockify bridges localhost VNC to noVNC on port 6080
- Exposed port changed from 5900 (VNC) to 6080 (noVNC)
- Default language/timezone options changed to empty strings for auto-detection
- Web UI HTML fully templated with i18n support (no more hardcoded French strings)

### Credits
- noVNC migration inspired by [@jnctech's fork](https://github.com/jnctech/HAFamilyLink)

---

## [1.3.0] - 2025-01-25

### Added
- HTTP API endpoint for cookie retrieval (`/api/cookies`)
- Support for Docker standalone installations without shared volumes
- Automatic detection of authentication source (API, local URL, or file fallback)

### Changed
- Integration now tries HTTP API first, then falls back to file storage
- Improved config flow with manual URL input option

### Fixed
- Docker standalone users can now configure the auth server URL manually

---

## [1.0.0] - 2025-01-07

### Added
- Initial release of the add-on
- Browser-based authentication with Playwright
- FastAPI web server with user-friendly interface
- Encrypted cookie storage using Fernet (AES-128)
- Automatic session monitoring and cleanup
- Health check endpoint
- French language interface
- Comprehensive documentation
- Support for amd64 and aarch64 architectures

### Security
- Encrypted cookie storage at rest
- Restrictive file permissions (0o600)
- Isolated browser sessions
- Automatic cleanup of sensitive data

### Technical
- Based on hassio-addons/base:14.0.2
- Python 3.11 with FastAPI and Playwright
- System Chromium browser integration
- Shared storage communication with integration

---

## Future Releases

### Planned for v1.1.0
- [ ] Automatic cookie refresh
- [ ] Multi-account support
- [x] English language toggle *(done in v1.6.0)*
- [ ] Persistent notification integration
- [ ] Advanced logging options

### Planned for v1.2.0
- [ ] Custom browser user agent
- [ ] Proxy support
- [ ] Session backup/restore
- [ ] Integration status monitoring

---

[1.3.0]: https://github.com/noiwid/HAFamilyLink/releases/tag/v1.3.0
[1.0.0]: https://github.com/noiwid/HAFamilyLink/releases/tag/v1.0.0
