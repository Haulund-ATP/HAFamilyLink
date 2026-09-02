#!/bin/bash
# Display a welcome banner on the X display so a viewer sees clear instructions
# instead of a black screen before Chromium opens.

set -e

# Require DISPLAY to be set (the display stack runs on :99 by default)
DISPLAY="${DISPLAY:-:99}"
export DISPLAY

# Make sure xterm is installed; if not, exit silently (non-critical)
if ! command -v xterm >/dev/null 2>&1; then
    echo "xterm not installed, skipping welcome banner"
    exit 0
fi

# Wait briefly for X server / window manager to settle
sleep 1

# Geometry: roughly centered on a 1280x1024 display
xterm \
    -geometry 84x20+220+250 \
    -fa "Liberation Mono" -fs 13 \
    -bg "#0f172a" -fg "#22d3ee" -bd "#22d3ee" \
    -title "Family Link Auth - Welcome" \
    -e bash -c '
cat <<MSG
============================================================
   Google Family Link - Authentication Service
============================================================

   The Google login window will appear here in a moment.

   This view is only reachable through the add-on web UI
   (or the standalone container UI on port 8099) and it is
   shut down again as soon as the login finishes.

   Complete the Google sign-in and two-factor prompt here,
   then return to the web UI tab for the confirmation.

============================================================

Tip: this message stays visible until Chromium opens.
It is normal - nothing is broken.

MSG
# Keep the window open until the display stack is stopped
while true; do sleep 3600; done
' >/dev/null 2>&1 &

echo "Welcome banner launched on display ${DISPLAY}"
