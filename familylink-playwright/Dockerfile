# Base image pinned by digest as well as tag: a tag can be moved to different
# content, a digest cannot, so the build is reproducible and a compromised or
# retagged base is rejected rather than silently used.
ARG BUILD_FROM=ghcr.io/hassio-addons/debian-base:7.3.3@sha256:6984c423247ace33db70c726ff9de8d7935475cbe112f249674b2017ed05fd0e
FROM ${BUILD_FROM}

# Set shell
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install system dependencies required for Playwright and Chromium.
#
# python3-websockify is deliberately absent: the unauthenticated websockify
# server on port 6080 has been replaced by the WebSocket bridge inside the
# application, which is covered by the service's own authentication. The noVNC
# client assets are still needed and come from the `novnc` package.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-dev \
        curl \
        ca-certificates \
        fonts-liberation \
        libnss3 \
        libatk-bridge2.0-0 \
        libdrm2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxrandr2 \
        libgbm1 \
        libasound2 \
        xvfb \
        x11vnc \
        tigervnc-standalone-server \
        novnc \
        fluxbox \
        xterm \
        dbus \
        procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged account. The service, the X server and Chromium all
# run as this user: running the browser as root is what forced --no-sandbox,
# so dropping privileges here is what lets Chromium's sandbox be enabled.
RUN groupadd --system --gid 1000 familylink \
    && useradd --system --uid 1000 --gid familylink \
        --home-dir /var/lib/familylink --create-home --shell /usr/sbin/nologin \
        familylink

# Set environment variables for Playwright
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=0
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Set working directory
WORKDIR /app

# Install Python dependencies from the hashed lock file. --require-hashes makes
# pip verify every artefact against requirements.txt and refuses anything that
# does not match, so a compromised index or mirror cannot substitute a package.
COPY requirements.txt requirements.in ./
RUN pip3 install --no-cache-dir --break-system-packages \
        --require-hashes -r requirements.txt

# Install the Chromium build matching the pinned Playwright version, then make
# it readable by the unprivileged user and enable the SUID sandbox helper. The
# helper is what lets Chromium sandbox its renderers on kernels that refuse
# unprivileged user namespaces, which is the common case inside containers.
RUN playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright \
    && find /ms-playwright -name 'chrome[-_]sandbox' -type f \
        -exec chown root:root {} \; -exec chmod 4755 {} \;

# Copy application code
COPY app/ /app/app/
COPY rootfs/ /
COPY welcome-banner.sh /usr/local/bin/welcome-banner.sh

# Set permissions
RUN chmod a+x /usr/local/bin/run.sh \
    && chmod a+x /usr/local/bin/display-stack.sh \
    && chmod a+x /usr/local/bin/welcome-banner.sh \
    && chmod a+x /etc/services.d/familylink/run \
    && chmod a+x /etc/services.d/familylink/finish

# Create the shared directory with restrictive permissions. Note that the key
# and the ciphertext both live here: see the security notes in DOCS.md.
RUN mkdir -p /share/familylink \
    && chown familylink:familylink /share/familylink \
    && chmod 700 /share/familylink

# Only the web UI, REST API and browser view. Port 6080 is gone.
EXPOSE 8099

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8099/api/health || exit 1

# Labels
LABEL \
    io.hass.name="Google Family Link Auth" \
    io.hass.description="Authentication service for Google Family Link" \
    io.hass.type="addon" \
    io.hass.version="2.0.0"
