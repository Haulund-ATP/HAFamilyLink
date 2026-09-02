"""Tests for the auth service's security primitives."""
from __future__ import annotations

import os
import stat
import sys

import pytest

from app.security import (
    MIN_TOKEN_LENGTH,
    RateLimiter,
    SessionStore,
    TokenError,
    load_or_create_api_token,
    read_secret_file,
    tokens_equal,
    write_secret_file,
)

POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix", reason="POSIX file modes are only meaningful on POSIX"
)


class TestTokenLifecycle:
    """Token generation, persistence and fail-closed behaviour."""

    def test_generates_and_persists_a_strong_token(self, share_dir):
        token = load_or_create_api_token(share_dir)

        assert len(token) >= MIN_TOKEN_LENGTH
        key_file = share_dir / "api_key"
        assert key_file.read_text() == token

    def test_reuses_the_persisted_token_across_restarts(self, share_dir):
        first = load_or_create_api_token(share_dir)
        second = load_or_create_api_token(share_dir)

        assert first == second

    def test_an_operator_supplied_token_wins(self, share_dir):
        token = load_or_create_api_token(share_dir, env_token="a" * 40)

        assert token == "a" * 40
        # Nothing is written when the token comes from the environment.
        assert not (share_dir / "api_key").exists()

    def test_rejects_a_short_operator_token(self, share_dir):
        with pytest.raises(TokenError, match="too short"):
            load_or_create_api_token(share_dir, env_token="short")

    def test_rejects_a_short_persisted_token(self, share_dir):
        (share_dir / "api_key").write_text("tiny")

        with pytest.raises(TokenError, match="too short"):
            load_or_create_api_token(share_dir)

    def test_fails_closed_when_the_directory_cannot_be_created(self, tmp_path):
        # A regular file where the directory should be: mkdir cannot succeed.
        blocker = tmp_path / "familylink"
        blocker.write_text("not a directory")

        with pytest.raises(TokenError):
            load_or_create_api_token(blocker / "sub")

    @POSIX_ONLY
    def test_token_file_is_not_readable_by_others(self, share_dir):
        load_or_create_api_token(share_dir)

        mode = stat.S_IMODE((share_dir / "api_key").stat().st_mode)
        assert mode == 0o600

    @POSIX_ONLY
    def test_directory_is_not_readable_by_others(self, share_dir):
        load_or_create_api_token(share_dir)

        assert stat.S_IMODE(share_dir.stat().st_mode) == 0o700

    @pytest.mark.skipif(
        not hasattr(os, "symlink") or sys.platform == "win32",
        reason="requires POSIX symlinks",
    )
    def test_refuses_to_read_a_symlinked_secret(self, tmp_path, share_dir):
        target = tmp_path / "elsewhere"
        target.write_text("a" * 40)
        (share_dir / "api_key").symlink_to(target)

        with pytest.raises(TokenError, match="symbolic link"):
            load_or_create_api_token(share_dir)

    @pytest.mark.skipif(
        not hasattr(os, "symlink") or sys.platform == "win32",
        reason="requires POSIX symlinks",
    )
    def test_refuses_to_write_through_a_symlink(self, tmp_path, share_dir):
        target = tmp_path / "victim"
        target.write_text("original")
        link = share_dir / "api_key"
        link.symlink_to(target)

        with pytest.raises(TokenError, match="symbolic link"):
            write_secret_file(link, "b" * 40)

        # The symlink target must be untouched.
        assert target.read_text() == "original"

    def test_write_then_read_roundtrip(self, share_dir):
        path = share_dir / "secret"
        write_secret_file(path, "value-with-newline\n")

        assert read_secret_file(path) == "value-with-newline"

    def test_read_of_missing_file_is_none(self, share_dir):
        assert read_secret_file(share_dir / "nope") is None

    def test_write_leaves_no_temporary_file_behind(self, share_dir):
        write_secret_file(share_dir / "secret", "x" * 40)

        leftovers = [p.name for p in share_dir.iterdir() if p.name != "secret"]
        assert leftovers == []


class TestConstantTimeComparison:
    def test_matching_tokens(self):
        assert tokens_equal("abc", "abc") is True

    def test_mismatched_tokens(self):
        assert tokens_equal("abc", "abd") is False

    def test_missing_candidate(self):
        assert tokens_equal(None, "abc") is False
        assert tokens_equal("", "abc") is False

    def test_different_lengths_do_not_raise(self):
        assert tokens_equal("a", "aaaaaaaaaa") is False


class TestRateLimiter:
    def test_allows_attempts_below_the_limit(self):
        limiter = RateLimiter(max_attempts=3, window_seconds=60)

        for _ in range(2):
            assert limiter.check("1.2.3.4", now=100.0).allowed
            limiter.record_failure("1.2.3.4", now=100.0)

        assert limiter.check("1.2.3.4", now=100.0).allowed

    def test_blocks_once_the_limit_is_reached(self):
        limiter = RateLimiter(max_attempts=3, window_seconds=60)
        for _ in range(3):
            limiter.record_failure("1.2.3.4", now=100.0)

        decision = limiter.check("1.2.3.4", now=100.0)

        assert decision.allowed is False
        assert decision.retry_after > 0

    def test_window_slides(self):
        limiter = RateLimiter(max_attempts=2, window_seconds=60)
        limiter.record_failure("1.2.3.4", now=100.0)
        limiter.record_failure("1.2.3.4", now=100.0)

        assert limiter.check("1.2.3.4", now=100.0).allowed is False
        assert limiter.check("1.2.3.4", now=161.0).allowed is True

    def test_clients_are_tracked_separately(self):
        limiter = RateLimiter(max_attempts=1, window_seconds=60)
        limiter.record_failure("1.1.1.1", now=100.0)

        assert limiter.check("1.1.1.1", now=100.0).allowed is False
        assert limiter.check("2.2.2.2", now=100.0).allowed is True

    def test_success_clears_the_history(self):
        limiter = RateLimiter(max_attempts=2, window_seconds=60)
        limiter.record_failure("1.2.3.4", now=100.0)
        limiter.record_failure("1.2.3.4", now=100.0)
        limiter.reset("1.2.3.4")

        assert limiter.check("1.2.3.4", now=100.0).allowed is True


class TestSessionStore:
    def test_created_session_is_valid(self):
        store = SessionStore(ttl_seconds=60)
        session_id = store.create(now=1000.0)

        assert store.is_valid(session_id, now=1000.0) is True

    def test_session_expires(self):
        store = SessionStore(ttl_seconds=60)
        session_id = store.create(now=1000.0)

        assert store.is_valid(session_id, now=1061.0) is False

    def test_unknown_session_is_rejected(self):
        store = SessionStore()

        assert store.is_valid("made-up") is False
        assert store.is_valid(None) is False

    def test_sessions_are_unguessable_and_unique(self):
        store = SessionStore()
        ids = {store.create() for _ in range(50)}

        assert len(ids) == 50
        assert all(len(i) >= 32 for i in ids)

    def test_revoke_and_clear(self):
        store = SessionStore()
        first = store.create()
        second = store.create()

        store.revoke(first)
        assert store.is_valid(first) is False
        assert store.is_valid(second) is True

        store.clear()
        assert store.is_valid(second) is False
