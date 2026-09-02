"""Tests over the add-on and container configuration itself.

These assert the shape of the shipped configuration rather than runtime
behaviour, because that is where the original weaknesses lived: a published
noVNC port with no authentication, and a documented default VNC password.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ADDON_DIR = REPO_ROOT / "familylink-playwright"

CONFIG = json.loads((ADDON_DIR / "config.json").read_text(encoding="utf-8"))
RUN_SH = (ADDON_DIR / "rootfs/usr/local/bin/run.sh").read_text(encoding="utf-8")
RUN_STANDALONE = (ADDON_DIR / "run-standalone.sh").read_text(encoding="utf-8")
DISPLAY_STACK = (
    ADDON_DIR / "rootfs/usr/local/bin/display-stack.sh"
).read_text(encoding="utf-8")
DOCKERFILE = (ADDON_DIR / "Dockerfile").read_text(encoding="utf-8")
DOCKERFILE_STANDALONE = (
    ADDON_DIR / "Dockerfile.standalone"
).read_text(encoding="utf-8")
COMPOSE = (ADDON_DIR / "docker-compose.standalone.yml").read_text(encoding="utf-8")
BUILD_JSON = json.loads((ADDON_DIR / "build.json").read_text(encoding="utf-8"))


def code_only(text: str) -> str:
    """Strip full-line comments.

    These assertions are about what the shipped configuration *does*, and the
    files explain at length what was removed and why - so the explanation must
    not be mistaken for the thing it describes.
    """
    return "\n".join(
        line for line in text.splitlines() if not line.strip().startswith("#")
    )


class TestAddonSchema:
    def test_required_keys_are_present(self):
        for key in ("name", "version", "slug", "arch", "schema", "options"):
            assert key in CONFIG, key

    def test_architectures_still_include_amd64_and_aarch64(self):
        assert set(CONFIG["arch"]) == {"amd64", "aarch64"}

    def test_every_option_has_a_schema_entry(self):
        for option in CONFIG["options"]:
            assert option in CONFIG["schema"], option

    def test_session_duration_bounds_are_validated(self):
        assert CONFIG["schema"]["session_duration"] == "int(3600,604800)?"

    def test_auth_timeout_bounds_are_validated(self):
        assert CONFIG["schema"]["auth_timeout"] == "int(60,600)?"

    def test_cookie_allowlist_defaults_to_strict(self):
        assert CONFIG["options"]["cookie_allowlist_mode"] == "strict"
        assert CONFIG["schema"]["cookie_allowlist_mode"] == "list(strict|legacy)?"


class TestVncPasswordIsGone:
    def test_no_default_vnc_password_is_shipped(self):
        """The publicly known default "familylink" must not be a default."""
        assert "vnc_password" not in CONFIG["options"]

    def test_the_legacy_option_is_still_accepted_but_unused(self):
        """Kept in the schema only so an existing config still validates."""
        assert CONFIG["schema"]["vnc_password"] == "password?"

    def test_the_legacy_password_appears_nowhere_as_a_value(self):
        for name, text in (
            ("config.json", json.dumps(CONFIG)),
            ("run.sh", RUN_SH),
            ("run-standalone.sh", RUN_STANDALONE),
            ("display-stack.sh", DISPLAY_STACK),
            ("Dockerfile", DOCKERFILE),
            ("Dockerfile.standalone", DOCKERFILE_STANDALONE),
            ("docker-compose", COMPOSE),
        ):
            assert not re.search(
                r'(VNC_PASSWORD|vnc_password)\s*[:=]\s*["\']?familylink', text
            ), name

    def test_the_deprecated_option_is_warned_about(self):
        assert "deprecated" in RUN_SH.lower()
        assert "deprecated" in RUN_STANDALONE.lower()

    def test_no_password_is_handed_to_the_vnc_server(self):
        code = code_only(DISPLAY_STACK)
        assert "-rfbauth" not in code
        assert "vncpasswd" not in code
        assert "-passwd" not in code
        assert "-SecurityTypes None" in code
        assert "-nopw" in code

    def test_the_vnc_server_binds_to_loopback_only(self):
        assert DISPLAY_STACK.count("-localhost") >= 2
        assert "-nolisten tcp" in DISPLAY_STACK

    def test_the_display_stack_can_be_stopped(self):
        """Nothing observable while no authentication session is running."""
        assert "do_stop()" in DISPLAY_STACK
        assert re.search(r"stop\)\s*do_stop", DISPLAY_STACK)


class TestPortExposure:
    def test_the_novnc_port_is_gone_entirely(self):
        assert "6080" not in json.dumps(CONFIG)
        for name, text in (
            ("Dockerfile", DOCKERFILE),
            ("Dockerfile.standalone", DOCKERFILE_STANDALONE),
            ("run.sh", RUN_SH),
            ("run-standalone.sh", RUN_STANDALONE),
            ("display-stack.sh", DISPLAY_STACK),
        ):
            assert "6080" not in code_only(text), name

    def test_websockify_is_no_longer_installed_or_started(self):
        for name, text in (
            ("Dockerfile", DOCKERFILE),
            ("Dockerfile.standalone", DOCKERFILE_STANDALONE),
            ("display-stack.sh", DISPLAY_STACK),
            ("run.sh", RUN_SH),
            ("run-standalone.sh", RUN_STANDALONE),
        ):
            assert "websockify" not in code_only(text), name

    def test_the_api_port_is_not_published_by_default(self):
        """Reached through ingress; a host mapping is opt-in."""
        assert CONFIG["ports"] == {"8099/tcp": None}

    def test_ingress_is_enabled(self):
        assert CONFIG["ingress"] is True
        assert CONFIG["ingress_port"] == 8099

    def test_no_webui_pointing_at_a_host_port(self):
        assert "webui" not in CONFIG

    def test_host_network_is_off(self):
        assert CONFIG["host_network"] is False

    def test_only_the_api_port_is_exposed_in_the_images(self):
        assert "EXPOSE 8099" in DOCKERFILE
        assert "EXPOSE 8099" in DOCKERFILE_STANDALONE

    def test_compose_binds_the_api_port_to_loopback(self):
        assert '"127.0.0.1:8099:8099"' in COMPOSE

    def test_compose_does_not_use_a_mutable_production_tag(self):
        assert "familylink-auth:standalone" not in COMPOSE
        assert re.search(r"familylink-auth:\d+\.\d+\.\d+-standalone", COMPOSE)


class TestIngressTrustIsFailClosed:
    def test_ingress_trust_depends_on_the_port_not_being_published(self):
        assert "bashio::addon.port 8099" in RUN_SH
        assert "INGRESS_TRUSTED=1" in RUN_SH
        assert "INGRESS_TRUSTED=0" in RUN_SH

    def test_standalone_never_claims_ingress_trust(self):
        assert "INGRESS_TRUSTED" not in RUN_STANDALONE


class TestPrivilegeReduction:
    def test_a_dedicated_unprivileged_user_is_created(self):
        for text in (DOCKERFILE, DOCKERFILE_STANDALONE):
            assert "useradd" in text
            assert "familylink" in text

    def test_privileges_are_dropped_before_the_service_starts(self):
        assert "s6-setuidgid" in RUN_SH
        assert "setpriv" in RUN_STANDALONE

    def test_the_addon_requests_no_extra_privileges(self):
        assert "privileged" not in CONFIG
        assert CONFIG["hassio_role"] == "default"

    def test_only_the_share_directory_is_mapped(self):
        assert CONFIG["map"] == ["share:rw"]

    def test_the_chromium_sandbox_helper_is_enabled(self):
        for text in (DOCKERFILE, DOCKERFILE_STANDALONE):
            assert "chrome[-_]sandbox" in text
            assert "4755" in text


class TestSupplyChain:
    def test_base_images_are_pinned_by_digest(self):
        assert re.search(r"FROM .*@sha256:[0-9a-f]{64}", DOCKERFILE_STANDALONE)
        assert re.search(r"BUILD_FROM=.*@sha256:[0-9a-f]{64}", DOCKERFILE)
        for arch, image in BUILD_JSON["build_from"].items():
            assert re.search(r"@sha256:[0-9a-f]{64}$", image), arch

    def test_dependencies_are_installed_with_verified_hashes(self):
        for text in (DOCKERFILE, DOCKERFILE_STANDALONE):
            assert "--require-hashes" in text

    def test_playwright_is_pinned(self):
        requirements_in = (ADDON_DIR / "requirements.in").read_text(encoding="utf-8")
        assert re.search(r"^playwright==\d+\.\d+\.\d+$", requirements_in, re.M)

    def test_unused_dependencies_are_gone(self):
        locked = (ADDON_DIR / "requirements.txt").read_text(encoding="utf-8")
        for unused in ("aiofiles", "jinja2", "python-multipart"):
            assert f"\n{unused}==" not in locked, unused

    def test_the_lock_file_carries_hashes(self):
        locked = (ADDON_DIR / "requirements.txt").read_text(encoding="utf-8")
        assert locked.count("--hash=sha256:") > 100

    def test_github_actions_are_pinned_to_commit_shas(self):
        workflows = list((REPO_ROOT / ".github/workflows").glob("*.yml"))
        assert workflows
        for workflow in workflows:
            for line in workflow.read_text(encoding="utf-8").splitlines():
                match = re.search(r"^\s*(?:-\s*)?uses:\s*(\S+)", line)
                if not match or match.group(1).startswith("./"):
                    continue
                assert re.search(
                    r"@[0-9a-f]{40}$", match.group(1)
                ), f"{workflow.name}: {match.group(1)}"


class TestNoSecretsCommitted:
    def test_no_api_key_or_cookie_file_is_tracked(self):
        for pattern in ("api_key", "cookies.enc", "*.key"):
            matches = [
                p
                for p in REPO_ROOT.rglob(pattern)
                if ".git" not in p.parts and ".venv" not in str(p)
            ]
            assert matches == [], (pattern, matches)

    def test_the_gitignore_covers_generated_secrets(self):
        gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        for entry in ("api_key", "cookies.enc"):
            assert entry in gitignore, entry
