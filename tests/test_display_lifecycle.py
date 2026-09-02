"""Display-stack lifecycle and framebuffer concurrency tests.

The old design kept an X server, a window manager and an unauthenticated
websockify bridge running for the container's whole lifetime, so a framebuffer
holding a logged-in Google account was observable at any moment. These tests
pin down the replacement: the stack exists only while a login is in progress,
and only one observer is admitted.
"""
from __future__ import annotations

import asyncio
import os
import stat
import textwrap

import pytest

from app.auth.browser import (
    _SANDBOX_FALLBACK_ARGS,
    _STABILITY_ARGS,
    BrowserAuthManager,
)
from app.display import DisplayStack
from app.vnc_proxy import SingleObserverGuard

POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix", reason="requires a POSIX shell to script the stub"
)


@pytest.fixture
def recording_script(tmp_path):
    """A stub display-stack script that records the actions it was called with."""
    log = tmp_path / "actions.log"
    script = tmp_path / "display-stack.sh"
    script.write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            echo "$1" >> {log}
            echo "stub handled $1"
            exit 0
            """
        )
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return script, log


@pytest.fixture
def failing_script(tmp_path):
    """A stub that reports failure, as a real one would if X refused to start."""
    script = tmp_path / "broken-stack.sh"
    script.write_text("#!/bin/sh\necho 'could not start X'\nexit 1\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


class TestDisplayStackLifecycle:
    def test_missing_script_is_reported_not_ignored(self, tmp_path):
        stack = DisplayStack(str(tmp_path / "absent.sh"))

        assert stack.available is False
        assert asyncio.run(stack.start()) is False

    @POSIX_ONLY
    def test_start_invokes_the_script(self, recording_script):
        script, log = recording_script
        stack = DisplayStack(str(script))

        assert asyncio.run(stack.start()) is True
        assert log.read_text().split() == ["start"]

    @POSIX_ONLY
    def test_start_is_idempotent(self, recording_script):
        script, log = recording_script
        stack = DisplayStack(str(script))

        async def run():
            await stack.start()
            await stack.start()

        asyncio.run(run())

        assert log.read_text().split() == ["start"]

    @POSIX_ONLY
    def test_stop_invokes_the_script(self, recording_script):
        script, log = recording_script
        stack = DisplayStack(str(script))

        async def run():
            await stack.start()
            await stack.stop()

        asyncio.run(run())

        assert log.read_text().split() == ["start", "stop"]

    @POSIX_ONLY
    def test_a_failed_start_is_not_reported_as_running(self, failing_script):
        stack = DisplayStack(str(failing_script))

        assert asyncio.run(stack.start()) is False
        assert stack.running is False


class FakeDisplayStack:
    """Records start/stop calls without touching a real X server."""

    def __init__(self, start_result: bool = True):
        self.calls: list[str] = []
        self._start_result = start_result

    async def start(self) -> bool:
        self.calls.append("start")
        return self._start_result

    async def stop(self) -> None:
        self.calls.append("stop")


class TestDisplayIsTiedToASession:
    def test_a_failed_display_start_aborts_the_login(self):
        manager = BrowserAuthManager(display_stack=FakeDisplayStack(False))

        with pytest.raises(RuntimeError, match="display could not be started"):
            asyncio.run(manager.start_auth_session())

    def test_the_display_is_stopped_when_the_browser_fails_to_launch(self):
        stack = FakeDisplayStack(True)
        manager = BrowserAuthManager(display_stack=stack)
        # No Playwright started, so _launch_browser raises immediately.

        with pytest.raises(Exception):
            asyncio.run(manager.start_auth_session())

        assert stack.calls == ["start", "stop"]

    def test_cleanup_always_stops_the_display(self):
        stack = FakeDisplayStack(True)
        manager = BrowserAuthManager(display_stack=stack)

        asyncio.run(manager.cleanup())

        assert "stop" in stack.calls

    def test_no_session_means_no_active_session(self):
        manager = BrowserAuthManager(display_stack=FakeDisplayStack())

        assert manager.has_active_session() is False


class TestSingleObserver:
    def test_one_observer_is_admitted(self):
        guard = SingleObserverGuard()

        assert asyncio.run(guard.acquire()) is True

    def test_a_second_observer_is_refused(self):
        guard = SingleObserverGuard()

        async def run():
            first = await guard.acquire()
            second = await guard.acquire()
            return first, second

        first, second = asyncio.run(run())

        assert (first, second) == (True, False)

    def test_the_slot_is_reusable_after_release(self):
        guard = SingleObserverGuard()

        async def run():
            await guard.acquire()
            await guard.release()
            return await guard.acquire()

        assert asyncio.run(run()) is True

    def test_concurrent_acquires_admit_exactly_one(self):
        guard = SingleObserverGuard()

        async def run():
            return await asyncio.gather(*(guard.acquire() for _ in range(10)))

        results = asyncio.run(run())

        assert sum(results) == 1


class TestChromiumHardening:
    def test_the_sandbox_is_not_disabled_by_default(self):
        assert "--no-sandbox" not in _STABILITY_ARGS
        assert "--disable-setuid-sandbox" not in _STABILITY_ARGS
        assert "--disable-gpu-sandbox" not in _STABILITY_ARGS

    def test_site_isolation_is_preserved(self):
        """Disabling IsolateOrigins removed cross-site process isolation."""
        joined = " ".join(_STABILITY_ARGS)
        assert "IsolateOrigins" not in joined
        assert "site-per-process" not in joined

    def test_the_disable_features_list_is_still_present_for_stability(self):
        joined = " ".join(_STABILITY_ARGS)
        assert "VizDisplayCompositor" in joined
        assert "--disable-dev-shm-usage" in _STABILITY_ARGS

    def test_arm_and_vm_compatibility_flags_are_kept(self):
        assert "--ozone-platform=x11" in _STABILITY_ARGS
        assert "--disable-gpu" in _STABILITY_ARGS

    def test_the_unsandboxed_fallback_is_a_separate_opt_in_set(self):
        assert _SANDBOX_FALLBACK_ARGS == (
            "--no-sandbox",
            "--disable-setuid-sandbox",
        )

    def test_a_fresh_manager_does_not_claim_the_sandbox_is_disabled(self):
        assert BrowserAuthManager().sandbox_disabled is False
