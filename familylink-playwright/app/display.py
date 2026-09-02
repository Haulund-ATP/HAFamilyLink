"""On-demand lifecycle for the VNC display stack.

Previously the X server, window manager and a websockify bridge ran for the
whole life of the container, so a framebuffer showing a logged-in Google
account was reachable at any moment, months after the last authentication.

Now the stack is started when an authentication session begins and stopped when
it ends, so there is nothing to observe while no login is in progress. The shell
details live in ``display-stack.sh``; this module only owns the lifecycle and
serialises start/stop against each other.
"""
from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from pathlib import Path

_LOGGER = logging.getLogger(__name__)


class DisplayStack:
    """Starts and stops the display stack through the control script."""

    def __init__(self, script: str, display: str = ":99") -> None:
        self._script = script
        self._display = display
        self._lock = asyncio.Lock()
        self._running = False

    @property
    def available(self) -> bool:
        """Whether the control script is present and executable."""
        return os.access(self._script, os.X_OK)

    @property
    def running(self) -> bool:
        """Whether this process believes the stack is up."""
        return self._running

    async def _run(self, action: str, timeout: float = 30.0) -> bool:
        """Invoke the control script, returning whether it reported success.

        The script's output goes to a temporary file rather than a pipe, and
        completion is detected by waiting for the process to exit rather than
        for its output to reach end-of-file. That distinction matters here: the
        script deliberately leaves an X server and a window manager running in
        the background, and those children inherit whatever the script's stdout
        was. With a pipe they hold it open indefinitely, so waiting for EOF
        would hang until the timeout on every successful start.
        """
        if not self.available:
            _LOGGER.warning(
                "Display control script %s is missing or not executable; "
                "the browser view will be unavailable",
                self._script,
            )
            return False

        output_file = tempfile.NamedTemporaryFile(
            prefix="display-stack-", suffix=".log", delete=False
        )
        try:
            with output_file:
                try:
                    process = await asyncio.create_subprocess_exec(
                        self._script,
                        action,
                        stdout=output_file,
                        stderr=asyncio.subprocess.STDOUT,
                        env={**os.environ, "DISPLAY": self._display},
                    )
                except OSError as err:
                    _LOGGER.error(
                        "Could not run %s %s: %s", self._script, action, err
                    )
                    return False

                try:
                    await asyncio.wait_for(process.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    _LOGGER.error(
                        "Display stack %s timed out after %.0fs", action, timeout
                    )
                    await self._terminate(process)
                    return False

            self._log_output(action, Path(output_file.name))
            if process.returncode != 0:
                _LOGGER.error(
                    "Display stack %s failed with exit code %s",
                    action,
                    process.returncode,
                )
                return False
            return True
        finally:
            try:
                os.unlink(output_file.name)
            except OSError:
                pass

    @staticmethod
    async def _terminate(process: "asyncio.subprocess.Process") -> None:
        """Kill a process that overran its timeout, tolerating a race.

        ``kill()`` on a process that has already exited raises
        ``ProcessLookupError`` - whose string form is empty, so it surfaces as a
        blank error message and hides the real cause. That is exactly what
        happened when this method did not exist.
        """
        if process.returncode is not None:
            return
        try:
            process.kill()
        except (ProcessLookupError, OSError):
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:  # pragma: no cover - unkillable process
            _LOGGER.warning("Display stack process did not exit after SIGKILL")

    @staticmethod
    def _log_output(action: str, path: Path) -> None:
        """Forward the script's output into the add-on log."""
        try:
            output = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return
        for line in output.splitlines():
            _LOGGER.info("display-stack %s: %s", action, line)

    async def start(self) -> bool:
        """Bring the display stack up, if it is not already running."""
        async with self._lock:
            if self._running:
                return True
            started = await self._run("start")
            self._running = started
            return started

    async def stop(self) -> None:
        """Tear the display stack down and make the framebuffer unreachable."""
        async with self._lock:
            # /tmp/.X11-unix is where the X protocol puts its sockets; the path
            # is fixed by X, not a temporary file this code creates, so there
            # is no predictable-name risk to mitigate here.
            socket_path = Path(
                f"/tmp/.X11-unix/X{self._display.lstrip(':')}"  # noqa: S108
            )
            if not self._running and not socket_path.exists():
                return
            await self._run("stop", timeout=15.0)
            self._running = False
