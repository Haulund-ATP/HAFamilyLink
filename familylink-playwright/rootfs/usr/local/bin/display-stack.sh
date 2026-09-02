#!/bin/bash
# ==============================================================================
# On-demand display stack for the Family Link authentication browser.
#
# The X server, window manager and welcome banner used to run for the whole
# lifetime of the container, which left a framebuffer showing a logged-in
# Google account observable at any time. They are now started when an
# authentication session begins and stopped when it ends, driven by the
# FastAPI app (app/display.py).
#
# Two further changes matter for security:
#
#   * The VNC server binds to loopback only (-localhost) and runs with
#     -SecurityTypes None. There is no VNC password at all - the previous
#     scheme used VNC's DES authentication, which silently truncates to 8
#     characters, and shipped with the publicly known default "familylink".
#     Access control now lives one layer up: the only route to the framebuffer
#     is the authenticated WebSocket bridge in the app (/vnc/websockify), which
#     requires the service token or a Home Assistant ingress session.
#
#   * Nothing is published on the host. Port 6080 and its unauthenticated
#     websockify server are gone entirely.
#
# Usage: display-stack.sh start|stop|status
# ==============================================================================

set -uo pipefail

DISPLAY_NUM="${FAMILYLINK_DISPLAY_NUM:-99}"
export DISPLAY=":${DISPLAY_NUM}"
GEOMETRY="${FAMILYLINK_GEOMETRY:-1280x1024}"
VNC_PORT="${FAMILYLINK_VNC_PORT:-5900}"
RUN_DIR="${FAMILYLINK_RUN_DIR:-/tmp/familylink}"
LOG_DIR="${FAMILYLINK_LOG_DIR:-/tmp/familylink/log}"
BACKEND="${FAMILYLINK_VNC_BACKEND:-auto}"

mkdir -p "${RUN_DIR}" "${LOG_DIR}"

PID_XSERVER="${RUN_DIR}/xserver.pid"
PID_WM="${RUN_DIR}/fluxbox.pid"
PID_BANNER="${RUN_DIR}/banner.pid"

log() { echo "$*"; }

# A process that has exited but not yet been reaped stays visible to
# `kill -0`, so a naive liveness check reports a dead X server as running.
# These helpers look at the process state instead.
_is_zombie() {
    local pid="$1" state
    state="$(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null)" || return 1
    [ "${state}" = "Z" ]
}

_alive() {
    local pid_file="$1"
    [ -f "${pid_file}" ] || return 1
    local pid
    pid="$(cat "${pid_file}" 2>/dev/null)" || return 1
    [ -n "${pid}" ] || return 1
    kill -0 "${pid}" 2>/dev/null || return 1
    ! _is_zombie "${pid}"
}

_kill_pidfile() {
    local pid_file="$1" name="$2"
    if _alive "${pid_file}"; then
        local pid
        pid="$(cat "${pid_file}")"
        kill "${pid}" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            _alive "${pid_file}" || break
            sleep 0.3
        done
        if _alive "${pid_file}"; then
            log "  ${name} ignored SIGTERM, sending SIGKILL"
            kill -9 "${pid}" 2>/dev/null || true
        fi
        # Reap it if it is our own child, so a repeated start/stop cycle does
        # not accumulate zombie entries.
        wait "${pid}" 2>/dev/null || true
    fi
    rm -f "${pid_file}"
}

_clean_stale_x() {
    # A non-graceful stop leaves the X lock and socket behind; the X server then
    # silently refuses to bind and the whole display stack dies invisibly.
    rm -f "/tmp/.X${DISPLAY_NUM}-lock" "/tmp/.X11-unix/X${DISPLAY_NUM}" 2>/dev/null || true
}

start_tigervnc() {
    command -v Xvnc >/dev/null 2>&1 || { log "  Xvnc not installed"; return 1; }
    log "Starting display server (TigerVNC Xvnc on ${DISPLAY}, loopback only)..."
    # -localhost: refuse any connection that is not from inside the container.
    # -SecurityTypes None: see the header - authentication is enforced by the
    # app's WebSocket bridge, which is the only thing that can reach this port.
    # -NeverShared: a second RFB client cannot attach to a login in progress.
    Xvnc "${DISPLAY}" \
        -geometry "${GEOMETRY}" -depth 24 \
        -rfbport "${VNC_PORT}" -localhost \
        -SecurityTypes None -NeverShared \
        -desktop familylink \
        >"${LOG_DIR}/xvnc.log" 2>&1 &
    echo $! >"${PID_XSERVER}"
    sleep 2
    if _alive "${PID_XSERVER}"; then
        log "  TigerVNC display server started"
        return 0
    fi
    log "  TigerVNC failed to start. Last log lines:"
    tail -n 20 "${LOG_DIR}/xvnc.log" 2>/dev/null | sed 's/^/    xvnc| /'
    rm -f "${PID_XSERVER}"
    return 1
}

start_xvfb_x11vnc() {
    _clean_stale_x
    log "Starting virtual display (Xvfb)..."
    # -nolisten tcp: no X protocol over the network at all.
    # -ac (disable X host access control) is deliberately NOT used: with
    # -nolisten tcp only local clients can connect, and the browser runs as the
    # same user, so host-based access control has nothing left to relax.
    Xvfb "${DISPLAY}" -screen 0 "${GEOMETRY}x16" -nolisten tcp \
        >"${LOG_DIR}/xvfb.log" 2>&1 &
    echo $! >"${PID_XSERVER}"
    sleep 2
    if ! _alive "${PID_XSERVER}"; then
        log "  Xvfb failed to start. Last log lines:"
        tail -n 20 "${LOG_DIR}/xvfb.log" 2>/dev/null | sed 's/^/    xvfb| /'
        rm -f "${PID_XSERVER}"
        return 1
    fi

    log "Starting VNC server (x11vnc, loopback only, no RFB auth)..."
    # -nopw is explicit: the framebuffer is only reachable through the app's
    # authenticated bridge. Note the absence of -shared, so one observer at a
    # time, and of -forever, so it does not outlive the session by design.
    x11vnc -display "${DISPLAY}" -rfbport "${VNC_PORT}" -localhost -nopw \
        -noshared -forever \
        >"${LOG_DIR}/x11vnc.log" 2>&1 &
    echo $! >"${RUN_DIR}/x11vnc.pid"
    sleep 1
    if ! _alive "${RUN_DIR}/x11vnc.pid"; then
        log "  x11vnc failed to start. Last log lines:"
        tail -n 20 "${LOG_DIR}/x11vnc.log" 2>/dev/null | sed 's/^/    x11vnc| /'
        return 1
    fi
    return 0
}

do_start() {
    if _alive "${PID_XSERVER}"; then
        log "Display stack already running"
        return 0
    fi
    _clean_stale_x

    local started=""
    case "${BACKEND}" in
        x11vnc)   start_xvfb_x11vnc && started="x11vnc" ;;
        tigervnc) start_tigervnc && started="tigervnc" ;;
        *)
            if start_tigervnc; then
                started="tigervnc"
            else
                log "Falling back to the Xvfb + x11vnc display stack..."
                start_xvfb_x11vnc && started="x11vnc"
            fi
            ;;
    esac

    if [ -z "${started}" ]; then
        log "No display server could be started"
        return 1
    fi

    fluxbox >"${LOG_DIR}/fluxbox.log" 2>&1 &
    echo $! >"${PID_WM}"
    sleep 1
    if ! _alive "${PID_WM}"; then
        log "  fluxbox failed to start (non-critical)"
        rm -f "${PID_WM}"
    fi

    if [ -x /usr/local/bin/welcome-banner.sh ]; then
        /usr/local/bin/welcome-banner.sh >"${LOG_DIR}/banner.log" 2>&1 &
        echo $! >"${PID_BANNER}"
    fi

    log "Display stack ready (${started})"
    return 0
}

do_stop() {
    log "Stopping display stack..."
    _kill_pidfile "${PID_BANNER}" "welcome banner"
    # The banner runs xterm as a child; make sure nothing is left drawing.
    pkill -f "Family Link Auth" 2>/dev/null || true
    _kill_pidfile "${PID_WM}" "fluxbox"
    _kill_pidfile "${RUN_DIR}/x11vnc.pid" "x11vnc"
    _kill_pidfile "${PID_XSERVER}" "display server"
    _clean_stale_x
    log "Display stack stopped; the browser view is no longer reachable"
    return 0
}

do_status() {
    if _alive "${PID_XSERVER}"; then
        log "running"
        return 0
    fi
    log "stopped"
    return 1
}

case "${1:-}" in
    start)  do_start ;;
    stop)   do_stop ;;
    status) do_status ;;
    *)
        echo "Usage: $0 start|stop|status" >&2
        exit 2
        ;;
esac
