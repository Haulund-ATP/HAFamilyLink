#!/usr/bin/with-contenv bashio
# ==============================================================================
# Start Family Link Auth Service
# ==============================================================================

bashio::log.info "Starting Google Family Link Auth Service..."

# Read configuration from Home Assistant
LOG_LEVEL=$(bashio::config 'log_level' 'info')
AUTH_TIMEOUT=$(bashio::config 'auth_timeout' '300')
SESSION_DURATION=$(bashio::config 'session_duration' '86400')
LANGUAGE=$(bashio::config 'language' '')
TIMEZONE=$(bashio::config 'timezone' '')
COOKIE_ALLOWLIST_MODE=$(bashio::config 'cookie_allowlist_mode' 'strict')

# Auto-detect from Home Assistant if not manually configured
if [ -z "${LANGUAGE}" ] || [ "${LANGUAGE}" == "null" ]; then
    bashio::log.info "Language not configured, auto-detecting from Home Assistant..."
    HA_LANGUAGE=$(bashio::api.supervisor GET /core/api/config false '$.language' 2>/dev/null) || HA_LANGUAGE=""
    if [ -n "${HA_LANGUAGE}" ] && [ "${HA_LANGUAGE}" != "null" ]; then
        # Map HA short language code to full locale
        case "${HA_LANGUAGE}" in
            fr) LANGUAGE="fr-FR" ;;
            en) LANGUAGE="en-US" ;;
            de) LANGUAGE="de-DE" ;;
            es) LANGUAGE="es-ES" ;;
            it) LANGUAGE="it-IT" ;;
            nl) LANGUAGE="nl-NL" ;;
            pt) LANGUAGE="pt-PT" ;;
            *) LANGUAGE="${HA_LANGUAGE}" ;;
        esac
        bashio::log.info "Auto-detected language from HA: ${LANGUAGE}"
    else
        LANGUAGE="en-US"
        bashio::log.warning "Could not auto-detect language, defaulting to en-US"
    fi
fi

if [ -z "${TIMEZONE}" ] || [ "${TIMEZONE}" == "null" ]; then
    bashio::log.info "Timezone not configured, auto-detecting from Home Assistant..."
    HA_TIMEZONE=$(bashio::info.timezone 2>/dev/null) || HA_TIMEZONE=""
    if [ -n "${HA_TIMEZONE}" ] && [ "${HA_TIMEZONE}" != "null" ]; then
        TIMEZONE="${HA_TIMEZONE}"
        bashio::log.info "Auto-detected timezone from HA: ${TIMEZONE}"
    else
        TIMEZONE="Europe/Paris"
        bashio::log.warning "Could not auto-detect timezone, defaulting to Europe/Paris"
    fi
fi

# The vnc_password option no longer has any effect. VNC's own authentication
# used DES and silently honoured only the first 8 characters, and the add-on
# shipped with the publicly known default "familylink". The framebuffer is now
# reachable only through the add-on's authenticated bridge (Home Assistant
# ingress, or the service token), and the VNC server itself listens on loopback
# with no RFB authentication at all, so there is no password to get wrong.
LEGACY_VNC_PASSWORD=$(bashio::config 'vnc_password' '')
if [ -n "${LEGACY_VNC_PASSWORD}" ] && [ "${LEGACY_VNC_PASSWORD}" != "null" ]; then
    bashio::log.warning "The 'vnc_password' option is deprecated and ignored."
    bashio::log.warning "The browser view is now protected by Home Assistant ingress"
    bashio::log.warning "or the service API token instead of a VNC password."
    bashio::log.warning "You can remove the option from the add-on configuration."
fi
unset LEGACY_VNC_PASSWORD

# Export environment variables
export LOG_LEVEL="${LOG_LEVEL}"
export AUTH_TIMEOUT="${AUTH_TIMEOUT}"
export SESSION_DURATION="${SESSION_DURATION}"
export LANGUAGE="${LANGUAGE}"
export TIMEZONE="${TIMEZONE}"
export COOKIE_ALLOWLIST_MODE="${COOKIE_ALLOWLIST_MODE}"
# Mark this as a Supervisor-managed add-on run.
export ADDON_MODE=1

# ------------------------------------------------------------------------------
# Ingress trust
#
# When the host port is NOT published, the only route into this container is the
# Supervisor's ingress proxy, which authenticates the Home Assistant user before
# forwarding. In that configuration an ingress request counts as an
# authenticated UI session and the operator never has to handle the token.
#
# If the port IS published, the X-Ingress-Path header could simply be forged by
# anyone who can reach the port, so ingress trust is switched off and the web UI
# asks for the service token. Anything we cannot positively confirm is treated
# as published - the default has to fail closed.
# ------------------------------------------------------------------------------
HOST_PORT="$(bashio::addon.port 8099 2>/dev/null || true)"
if [ -z "${HOST_PORT}" ] || [ "${HOST_PORT}" == "null" ]; then
    export INGRESS_TRUSTED=1
    bashio::log.info "Host port 8099 is not published: reachable through Home Assistant ingress only"
else
    export INGRESS_TRUSTED=0
    bashio::log.warning "Host port 8099 is published on the host (port ${HOST_PORT})."
    bashio::log.warning "Anyone who can reach it must present the service API token."
    bashio::log.warning "Unless you need direct access, clear the port mapping in the add-on's Network section."
fi

bashio::log.info "Configuration loaded:"
bashio::log.info "  - Log Level: ${LOG_LEVEL}"
bashio::log.info "  - Auth Timeout: ${AUTH_TIMEOUT}s"
bashio::log.info "  - Session Duration: ${SESSION_DURATION}s"
bashio::log.info "  - Language: ${LANGUAGE}"
bashio::log.info "  - Timezone: ${TIMEZONE}"
bashio::log.info "  - Cookie allowlist mode: ${COOKIE_ALLOWLIST_MODE}"

# ------------------------------------------------------------------------------
# Unprivileged runtime
#
# Everything below runs as the dedicated 'familylink' user created in the image:
# uvicorn, the X server and Chromium. Running the browser as root was the reason
# --no-sandbox was needed at all, so dropping privileges here is what allows
# Chromium's sandbox to be switched back on.
# ------------------------------------------------------------------------------
RUN_USER="familylink"
RUN_HOME="/var/lib/familylink"

mkdir -p /share/familylink "${RUN_HOME}" /tmp/familylink /tmp/.X11-unix
chmod 700 /share/familylink
chmod 700 "${RUN_HOME}"
chmod 1777 /tmp/.X11-unix
chown -R "${RUN_USER}:${RUN_USER}" /share/familylink "${RUN_HOME}" /tmp/familylink

bashio::log.info "Shared storage ready at /share/familylink (0700, owned by ${RUN_USER})"

# Start the D-Bus system bus while we still have privileges (fixes a blank
# screen on RPi4/ARM64). Non-critical: Chromium is launched with D-Bus disabled.
if [ ! -S /run/dbus/system_bus_socket ]; then
    bashio::log.info "Starting D-Bus system bus..."
    mkdir -p /run/dbus
    dbus-daemon --system --fork 2>/dev/null || bashio::log.warning "D-Bus not available (non-critical)"
fi

# The display stack (X server + window manager) is no longer started here. The
# application brings it up when an authentication session starts and tears it
# down when the session ends, so there is no observable browser window - and no
# reachable framebuffer - while nobody is logging in.
export FAMILYLINK_RUN_DIR=/tmp/familylink
export FAMILYLINK_LOG_DIR=/tmp/familylink/log
export HOME="${RUN_HOME}"
export XDG_RUNTIME_DIR=/tmp/familylink
export DISPLAY=:99

bashio::log.info "Starting FastAPI application as ${RUN_USER}..."

cd /app || exit 1
exec s6-setuidgid "${RUN_USER}" \
    /usr/bin/env \
        HOME="${RUN_HOME}" \
        XDG_RUNTIME_DIR=/tmp/familylink \
        DISPLAY=:99 \
        FAMILYLINK_RUN_DIR=/tmp/familylink \
        FAMILYLINK_LOG_DIR=/tmp/familylink/log \
    uvicorn app.main:app \
        --host 0.0.0.0 \
        --port 8099 \
        --log-level "${LOG_LEVEL}" \
        --no-access-log \
        --workers 1
