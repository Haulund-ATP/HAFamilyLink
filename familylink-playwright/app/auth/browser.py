"""Browser-based authentication manager using Playwright."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Dict

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    TimeoutError as PlaywrightTimeoutError,
    async_playwright,
)

from app import cookies as cookie_rules
from app import redaction

_LOGGER = logging.getLogger(__name__)


# Chromium flags that keep the browser alive in the virtualised, GPU-less
# environments this add-on runs in (HA OS under a hypervisor, Raspberry Pi).
# None of these weaken the sandbox or the renderer's process isolation.
_STABILITY_ARGS: tuple[str, ...] = (
    # Shared memory: the container's default /dev/shm is too small for Chromium.
    "--disable-dev-shm-usage",
    # GPU and rendering - critical for VMs without GPU passthrough.
    "--disable-gpu",
    "--disable-gpu-compositing",
    "--disable-software-rasterizer",
    "--disable-accelerated-2d-canvas",
    "--disable-accelerated-video-decode",
    "--disable-accelerated-video-encode",
    # Skia and rendering - addresses SEGV crashes in VMs.
    "--disable-skia-runtime-opts",
    "--disable-partial-raster",
    "--disable-zero-copy",
    "--disable-lcd-text",
    "--disable-font-subpixel-positioning",
    # Features that misbehave without a compositor or a system D-Bus.
    # Note: IsolateOrigins/site-per-process are deliberately NOT disabled here
    # - turning them off removed Chromium's cross-site process isolation on a
    # browser that logs into a Google account.
    "--disable-features=VizDisplayCompositor,dbus,UseSkiaRenderer,TranslateUI",
    # System services.
    "--disable-breakpad",
    "--disable-component-update",
    # Keep Google's login flow from treating the automation as a bot.
    "--disable-blink-features=AutomationControlled",
    # Stability flags.
    "--disable-background-networking",
    "--disable-default-apps",
    "--disable-extensions",
    "--disable-sync",
    "--no-first-run",
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    "--disable-background-timer-throttling",
    # Memory optimisation.
    "--memory-pressure-off",
    "--disable-low-res-tiling",
    # ARM64 / RPi compatibility.
    "--ozone-platform=x11",
)

# Only used if a sandboxed launch fails outright. Kept as a last resort so a
# platform that cannot grant unprivileged user namespaces still authenticates,
# rather than silently shipping a sandbox-less browser to everyone.
_SANDBOX_FALLBACK_ARGS: tuple[str, ...] = (
    "--no-sandbox",
    "--disable-setuid-sandbox",
)


class BrowserAuthManager:
    """Manages browser-based authentication sessions."""

    MAX_CONCURRENT_SESSIONS = 1

    def __init__(
        self,
        auth_timeout: int = 300,
        language: str = "en-US",
        timezone: str = "Europe/Paris",
        storage=None,
        display_stack=None,
        allowlist_mode: str = "strict",
    ):
        """Initialize browser auth manager."""
        self._sessions: Dict[str, Dict] = {}
        self._monitor_tasks: Dict[str, asyncio.Task] = {}
        self._playwright = None
        self._auth_timeout = auth_timeout
        self._language = language
        self._timezone = timezone
        self._storage = storage  # Injected SharedStorage instance
        self._display_stack = display_stack
        self._allowlist_mode = allowlist_mode
        self._sandbox_disabled = False

    async def initialize(self):
        """Initialize Playwright."""
        try:
            self._playwright = await async_playwright().start()
            _LOGGER.info("Playwright initialized successfully")
        except Exception as e:
            _LOGGER.error(f"Failed to initialize Playwright: {e}")
            raise

    @property
    def sandbox_disabled(self) -> bool:
        """Whether the last launch had to fall back to an unsandboxed browser."""
        return self._sandbox_disabled

    def has_active_session(self) -> bool:
        """Whether an authentication session is currently in progress."""
        return any(
            session.get("status") == "authenticating"
            for session in self._sessions.values()
        )

    async def _launch_browser(self) -> Browser:
        """Launch Chromium with its sandbox enabled, falling back only if it fails.

        Chromium's sandbox needs an unprivileged user namespace. The service now
        runs as a dedicated non-root user, which removes the usual reason
        ``--no-sandbox`` was required in a container, but some kernels and
        seccomp profiles still refuse ``clone(CLONE_NEWUSER)``. Rather than
        disabling the sandbox for everyone, try the safe configuration first and
        record loudly when a host forces the fallback.
        """
        try:
            browser = await self._playwright.chromium.launch(
                headless=False,
                args=list(_STABILITY_ARGS),
            )
            self._sandbox_disabled = False
            _LOGGER.info("Chromium launched with its sandbox enabled")
            return browser
        except Exception as err:
            _LOGGER.warning(
                "Chromium refused to start with its sandbox enabled (%s). "
                "Retrying without the sandbox: the browser process is then "
                "isolated only by the container itself. It runs as an "
                "unprivileged user with no capabilities and is stopped as soon "
                "as authentication finishes.",
                err,
            )
        browser = await self._playwright.chromium.launch(
            headless=False,
            args=list(_STABILITY_ARGS) + list(_SANDBOX_FALLBACK_ARGS),
        )
        self._sandbox_disabled = True
        return browser

    async def start_auth_session(self) -> str:
        """Start a new authentication session."""
        # Prune old completed sessions (prevent memory leak)
        self._prune_old_sessions()

        # Prevent concurrent sessions (memory protection, especially on RPi)
        active = [s for s in self._sessions.values() if s.get('status') == 'authenticating']
        if len(active) >= self.MAX_CONCURRENT_SESSIONS:
            raise RuntimeError("An authentication session is already in progress. Please wait or cancel it first.")

        session_id = str(uuid.uuid4())
        _LOGGER.info(f"Starting authentication session: {session_id}")

        browser = None
        context = None
        page = None
        try:
            # Bring the display stack up only for the duration of the login, so
            # there is no observable framebuffer while no session is running.
            # Inside the try, so a failure here is logged like any other.
            if self._display_stack is not None:
                if not await self._display_stack.start():
                    raise RuntimeError(
                        "The browser display could not be started; check the "
                        "add-on log for the display-stack messages."
                    )

            browser = await self._launch_browser()

            # Create context with realistic user agent
            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                viewport={'width': 1280, 'height': 800},
                locale=self._language,
                timezone_id=self._timezone
            )

            # Create page
            page = await context.new_page()

            # Store session
            self._sessions[session_id] = {
                'browser': browser,
                'context': context,
                'page': page,
                'status': 'authenticating',
                'cookies': None,
                'cookie_count': 0,
                'error': None,
                'created_at': time.time(),
            }

            # Listen for new tabs/popups
            def on_page(new_page):
                _LOGGER.info("New tab detected, switching monitoring to new page")
                self._sessions[session_id]['page'] = new_page

            context.on("page", on_page)

            # Navigate to Google Family Link
            # Using 'load' instead of 'networkidle' for better reliability
            # 'networkidle' can timeout on pages with continuous background requests
            _LOGGER.info("Navigating to Google Family Link...")
            await page.goto('https://families.google.com', wait_until='load', timeout=30000)

            # Start monitoring in background with proper error handling
            task = asyncio.create_task(self._monitor_authentication(session_id))
            task.add_done_callback(lambda t: self._on_monitor_done(session_id, t))
            self._monitor_tasks[session_id] = task

            return session_id

        except Exception as e:
            # Include the type: some exceptions (ProcessLookupError,
            # asyncio.TimeoutError) have an empty string form, and a bare
            # "Failed to start auth session: " tells nobody anything.
            _LOGGER.error(
                "Failed to start auth session: %s: %s", type(e).__name__, e
            )
            # Cleanup browser resources on failure to prevent leaks
            try:
                if page:
                    await page.close()
                if context:
                    await context.close()
                if browser:
                    await browser.close()
            except Exception as cleanup_err:
                _LOGGER.warning(f"Cleanup after failed session start: {cleanup_err}")
            self._sessions.pop(session_id, None)
            await self._stop_display_if_idle()
            raise

    async def _monitor_authentication(self, session_id: str):
        """Monitor authentication progress."""
        session = self._sessions.get(session_id)
        if not session:
            return

        context: BrowserContext = session['context']

        try:
            _LOGGER.info(f"Monitoring authentication for session {session_id}")

            # Wait for URL change or specific elements that indicate success
            await asyncio.sleep(5)  # Give initial page time to load

            # Poll for authentication completion
            start_time = asyncio.get_event_loop().time()
            authenticated = False
            last_url = None
            GOOGLE_AUTH_COOKIE_NAMES = {'SID', 'HSID', 'SSID', 'APISID', 'SAPISID'}

            while (asyncio.get_event_loop().time() - start_time) < self._auth_timeout:
                # Get the current page (might have changed if new tab opened)
                page: Page = session['page']
                current_url = page.url

                # Log URL changes at INFO, repeated polls at DEBUG. The query
                # string is stripped: Google's login URLs carry continuation
                # tokens and identifiers that must not reach a log file.
                if current_url != last_url:
                    _LOGGER.info(
                        "URL changed to: %s", redaction.redact_url(current_url)
                    )
                    last_url = current_url
                else:
                    _LOGGER.debug("Polling - URL unchanged")

                # Method 1: URL-based detection
                # Check if we're past the login page
                if 'accounts.google.com' not in current_url:
                    if any(domain in current_url for domain in [
                        'families.google.com',
                        'myaccount.google.com',
                    ]):
                        _LOGGER.info("Authentication detected via URL")
                        await self._finalise_cookies(page)
                        authenticated = True
                        break

                # Method 2: Cookie-based detection (fallback)
                # Google sets auth cookies (SID, HSID, etc.) after successful
                # login even before the URL redirect completes.
                try:
                    current_cookies = await context.cookies()
                    google_auth_cookies = [
                        c for c in current_cookies
                        if c.get('name') in GOOGLE_AUTH_COOKIE_NAMES
                        and '.google.com' in c.get('domain', '')
                    ]
                    if len(google_auth_cookies) >= 3:
                        _LOGGER.info(
                            "Authentication detected via cookies (%d auth "
                            "cookies found: %s)",
                            len(google_auth_cookies),
                            ", ".join(cookie_rules.cookie_names(google_auth_cookies)),
                        )
                        await self._finalise_cookies(page)
                        authenticated = True
                        break
                except Exception as e:
                    _LOGGER.debug(f"Cookie check failed: {e}")
                finally:
                    current_cookies = None

                await asyncio.sleep(2)  # Check every 2 seconds

            if not authenticated:
                raise asyncio.TimeoutError("Authentication timeout")

            # Extract cookies
            _LOGGER.info("Authentication detected, extracting cookies...")
            captured = await context.cookies()

            # Minimise before anything else touches them: only the Family Link
            # cookies are persisted, never the rest of the Google account.
            google_cookies = cookie_rules.filter_cookies(
                captured, self._allowlist_mode
            )
            cookie_rules.scrub(captured)
            captured = None

            if not google_cookies:
                raise Exception("No valid Google cookies found")

            _LOGGER.info(
                "Captured %d Family Link cookies (%s)",
                len(google_cookies),
                ", ".join(cookie_rules.cookie_names(google_cookies)),
            )

            # Register the values so they are scrubbed from any log line that
            # might otherwise carry them (a Playwright error, a traceback).
            for cookie in google_cookies:
                redaction.register_secret(cookie.get("value"))

            # Save to shared storage (use injected instance to avoid config mismatch)
            if self._storage:
                await self._storage.save_cookies(google_cookies)
            else:
                from app.storage.file_storage import SharedStorage
                storage = SharedStorage()
                await storage.save_cookies(google_cookies)

            # Update session. The values are dropped immediately: the session
            # record only needs the count, and holding them would keep a live
            # Google session in memory for the lifetime of the process.
            session['status'] = 'completed'
            session['cookie_count'] = len(google_cookies)
            cookie_rules.scrub(google_cookies)
            google_cookies = None
            session['cookies'] = None

            _LOGGER.info(f"Authentication completed successfully for session {session_id}")

            # Close browser after a short delay
            await asyncio.sleep(2)
            await self._cleanup_session(session_id)

        except (asyncio.TimeoutError, PlaywrightTimeoutError):
            session['status'] = 'timeout'
            session['error'] = 'Authentication timeout - user did not complete login in time'
            _LOGGER.error(f"Authentication timeout for session {session_id}")
            await self._cleanup_session(session_id)

        except Exception as e:
            session['status'] = 'error'
            session['error'] = str(e)
            _LOGGER.error(f"Authentication error for session {session_id}: {e}")
            await self._cleanup_session(session_id)

    async def _finalise_cookies(self, page: Page) -> None:
        """Navigate to families.google.com so Google finalises the cookie set."""
        _LOGGER.info("Navigating to families.google.com to finalize cookie configuration...")
        try:
            await page.goto(
                'https://families.google.com/families/', wait_until='load', timeout=15000
            )
            _LOGGER.info("Successfully navigated to families.google.com")
            await asyncio.sleep(2)
        except Exception as e:
            _LOGGER.warning(f"Failed to navigate to families.google.com: {e}")

    def _on_monitor_done(self, session_id: str, task: asyncio.Task):
        """Handle monitor task completion, log unhandled errors."""
        self._monitor_tasks.pop(session_id, None)
        if task.cancelled():
            return
        exc = task.exception()
        if exc:
            _LOGGER.error(f"Monitor task for session {session_id} failed: {exc}")

    def _prune_old_sessions(self, max_age: int = 3600):
        """Remove completed/errored sessions older than max_age seconds."""
        now = time.time()
        to_delete = [
            sid for sid, session in self._sessions.items()
            if session.get('status') in ('completed', 'timeout', 'error', 'cleaned_up')
            and now - session.get('created_at', 0) > max_age
        ]
        for sid in to_delete:
            del self._sessions[sid]
        if to_delete:
            _LOGGER.debug(f"Pruned {len(to_delete)} old sessions")

    async def get_session_status(self, session_id: str) -> Dict:
        """Get status of authentication session."""
        session = self._sessions.get(session_id)
        if not session:
            return {'status': 'not_found'}

        cookie_count = session.get('cookie_count', 0)
        return {
            'status': session.get('status', 'unknown'),
            'has_cookies': cookie_count > 0,
            'error': session.get('error'),
            'cookie_count': cookie_count
        }

    async def _stop_display_if_idle(self) -> None:
        """Stop the display stack once no authentication session is running."""
        if self._display_stack is None:
            return
        if self.has_active_session():
            return
        await self._display_stack.stop()

    async def _cleanup_session(self, session_id: str):
        """Clean up session resources."""
        session = self._sessions.get(session_id)
        if session:
            try:
                if session.get('page'):
                    await session['page'].close()
                if session.get('context'):
                    await session['context'].close()
                if session.get('browser'):
                    await session['browser'].close()
                _LOGGER.info(f"Cleaned up session {session_id}")
            except Exception as e:
                _LOGGER.warning(f"Cleanup error for session {session_id}: {e}")
            finally:
                # Retain only minimal metadata, discard heavy objects
                cookie_rules.scrub(session.get('cookies'))
                self._sessions[session_id] = {
                    'status': session.get('status', 'cleaned_up'),
                    'created_at': session.get('created_at'),
                    'error': session.get('error'),
                    'cookie_count': session.get('cookie_count', 0),
                }
        await self._stop_display_if_idle()

    async def cleanup(self):
        """Cleanup all resources."""
        _LOGGER.info("Cleaning up all sessions...")
        for session_id in list(self._sessions.keys()):
            await self._cleanup_session(session_id)

        if self._display_stack is not None:
            await self._display_stack.stop()

        if self._playwright:
            await self._playwright.stop()
            _LOGGER.info("Playwright stopped")
