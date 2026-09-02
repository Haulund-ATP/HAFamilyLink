#!/bin/bash
set -euo pipefail

# ==============================================================================
# Start Family Link Auth Service (Standalone)
#
# Differences from the Home Assistant add-on:
#   * there is no Supervisor and no ingress, so the web UI is unlocked once with
#     the service API token, which is generated and persisted on first start;
#   * only port 8099 is published. The old unauthenticated noVNC port 6080 is
#     gone: the browser view is served from the same port, behind the same
#     authentication.
# ==============================================================================

echo "=============================================="
echo "Google Family Link Auth Service (Standalone)"
echo "=============================================="
echo ""

LOG_LEVEL="${LOG_LEVEL:-info}"
AUTH_TIMEOUT="${AUTH_TIMEOUT:-300}"
SESSION_DURATION="${SESSION_DURATION:-86400}"
LANGUAGE="${LANGUAGE:-en-US}"
TIMEZONE="${TIMEZONE:-Europe/Paris}"
COOKIE_ALLOWLIST_MODE="${COOKIE_ALLOWLIST_MODE:-strict}"
RUN_USER="familylink"
RUN_HOME="/var/lib/familylink"
SHARE_DIR="${SHARE_DIR:-/share/familylink}"

echo "Configuration:"
echo "  - Log Level: ${LOG_LEVEL}"
echo "  - Auth Timeout: ${AUTH_TIMEOUT}s"
echo "  - Session Duration: ${SESSION_DURATION}s"
echo "  - Language: ${LANGUAGE}"
echo "  - Timezone: ${TIMEZONE}"
echo "  - Cookie allowlist mode: ${COOKIE_ALLOWLIST_MODE}"
echo ""

if [ -n "${VNC_PASSWORD:-}" ]; then
    echo "! VNC_PASSWORD is deprecated and ignored."
    echo "  The browser view is served over the authenticated /vnc endpoint on"
    echo "  port 8099; the VNC server itself listens on loopback with no RFB"
    echo "  authentication, so there is no password to configure. Remove the"
    echo "  variable from your compose file."
    unset VNC_PASSWORD
fi

mkdir -p "${SHARE_DIR}" "${RUN_HOME}" /tmp/familylink /tmp/.X11-unix
chmod 700 "${SHARE_DIR}" "${RUN_HOME}"
chmod 1777 /tmp/.X11-unix
chown -R "${RUN_USER}:${RUN_USER}" "${SHARE_DIR}" "${RUN_HOME}" /tmp/familylink
echo "* Shared storage ready at ${SHARE_DIR} (0700, owned by ${RUN_USER})"

if [ -n "${API_TOKEN:-}${API_KEY:-}" ]; then
    echo "* API token: taken from the environment"
else
    echo "* API token: generated on first start and stored in ${SHARE_DIR}/api_key (0600)"
    echo "  Read it with:  cat ./data/api_key"
    echo "  The Home Assistant integration asks for it as a separate field;"
    echo "  never append it to the URL."
fi
echo ""

# Start the D-Bus system bus while still root (fixes a blank screen on
# RPi4/ARM64). Non-critical: Chromium runs with D-Bus disabled.
if [ ! -S /run/dbus/system_bus_socket ]; then
    echo "Starting D-Bus system bus..."
    mkdir -p /run/dbus
    dbus-daemon --system --fork 2>/dev/null || echo "! D-Bus not available (non-critical)"
fi

# The display stack is started by the application only while an authentication
# session is running - see app/display.py and display-stack.sh.
export LOG_LEVEL AUTH_TIMEOUT SESSION_DURATION LANGUAGE TIMEZONE
export COOKIE_ALLOWLIST_MODE SHARE_DIR
export HOME="${RUN_HOME}"
export XDG_RUNTIME_DIR=/tmp/familylink
export FAMILYLINK_RUN_DIR=/tmp/familylink
export FAMILYLINK_LOG_DIR=/tmp/familylink/log
export DISPLAY=:99

echo "=============================================="
echo "Service starting"
echo "  - Web UI and browser view: http://localhost:8099"
echo "=============================================="
echo ""

cd /app

# Drop privileges for uvicorn, the X server and Chromium. Running the browser
# as root is what forced --no-sandbox; as an unprivileged user Chromium's
# sandbox can be enabled.
exec setpriv --reuid="${RUN_USER}" --regid="${RUN_USER}" --clear-groups \
    uvicorn app.main:app \
        --host 0.0.0.0 \
        --port 8099 \
        --log-level "${LOG_LEVEL}" \
        --no-access-log \
        --workers 1
