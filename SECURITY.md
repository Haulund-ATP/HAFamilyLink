# Security

This document describes what the Google Family Link integration and its
authentication add-on protect, what they do not, and what you have to do
yourself. It is deliberately specific about the remaining risks: this project
drives a Google account through an unofficial API, and no amount of hardening
changes that fact.

- [Threat model](#threat-model)
- [Use a dedicated Google parent account](#use-a-dedicated-google-parent-account)
- [How access is controlled](#how-access-is-controlled)
- [The browser view (noVNC)](#the-browser-view-novnc)
- [Temporarily exposing a host port](#temporarily-exposing-a-host-port)
- [Stopping the add-on after login](#stopping-the-add-on-after-login)
- [What is stored, where, and for how long](#what-is-stored-where-and-for-how-long)
- [Cookie expiry and deletion](#cookie-expiry-and-deletion)
- [Rotating credentials after a suspected compromise](#rotating-credentials-after-a-suspected-compromise)
- [Logging and privacy](#logging-and-privacy)
- [Remaining risks](#remaining-risks)
- [Reporting a vulnerability](#reporting-a-vulnerability)

## Threat model

**What is being protected.** A live Google session belonging to a Family Link
*parent*. Whoever holds it can lift every restriction on the supervised child's
device, read the child's location history, and reach the rest of that Google
account.

**Who we defend against, and how:**

| Adversary | Capability | Defence |
|---|---|---|
| The supervised child, on the home network | Can reach any host and port on the LAN, has a motive to unlock their own device | No host port is published by default. Every endpoint except `/api/health` requires the service token or an authenticated Home Assistant ingress session. The browser view is behind the same check. |
| Another device or user on the LAN | Can port-scan and connect | Same as above. Rate limiting bounds credential guessing; token comparison is constant-time. |
| Someone who obtains a copy of the cookie file | A backup, a snapshot, a `/share` copy taken without the key | The cookie store is encrypted with authenticated encryption (Fernet). |
| Someone who can read the whole `/share/familylink` directory | Root on the host, another add-on with `share` access, a full-directory backup | **Not defended against.** The key lives next to the ciphertext. See [What is stored](#what-is-stored-where-and-for-how-long). |
| A malicious page reached inside the auth browser | Renderer compromise during login | Chromium runs as an unprivileged user, with its sandbox enabled where the kernel allows it and cross-site process isolation intact. The browser exists only during a login. |
| The internet | — | **Out of scope, and not supported.** Nothing here is designed to be reachable from the internet. |

**Explicitly out of scope:** a compromised Home Assistant host, a compromised
Google account, and anyone with root on the machine running the add-on. Each of
those already implies access to the session.

## Use a dedicated Google parent account

Create a second Google account, add it to your family as a parent, and use
*only that account* for this integration.

This is the single most effective thing you can do, and it is worth doing even
if you trust every other control here. The session this add-on stores is a
Google session, not a Family Link session: Google's cookie authentication does
not distinguish "may adjust screen time" from "may read the mail". A dedicated
parent account limits what a stolen session reaches to Family Link
administration, instead of your primary mailbox, photos and password manager.

Give that account:

- a unique, strong password;
- two-factor authentication (it is used during the interactive login);
- no recovery relationship with your primary account.

## How access is controlled

There is **one** authentication mechanism, presented in two forms:

1. **A service token** in the `X-API-Key` header. This is what the Home
   Assistant integration uses.
2. **A short-lived, httpOnly session cookie**, obtained by posting that token
   once to `POST /api/session`. This is what the web UI uses, because a browser
   cannot attach a header to a WebSocket handshake, and because a token in a URL
   would end up in browser history, proxy logs and `Referer` headers.

The token is generated on first start (32 random bytes, URL-safe), stored at
`/share/familylink/api_key` with mode `0600`, and **never logged**. If it cannot
be generated, written or read, the service refuses to start rather than coming
up unprotected.

`GET /api/health` is the only endpoint reachable without credentials.

**A token in a query string is refused with HTTP 400**, even if the value is
correct. If you have an older configuration of the form
`http://host:8099?api_key=…`, the integration migrates it for you on upgrade —
the key moves into a separate secret field. Nothing to do by hand.

On Home Assistant OS and Supervised installations, the add-on is reached through
**Home Assistant ingress**, which authenticates your Home Assistant user before
the request ever arrives. In that configuration you never handle the token at
all. Ingress is trusted only while no host port is published; if you map one,
the add-on stops trusting the ingress header — otherwise anyone able to reach
that port could simply set it themselves.

## The browser view (noVNC)

Earlier versions published port `6080` with **no authentication of any kind**,
and the VNC server behind it used the documented default password
`familylink`. Anyone who could reach that port could watch — and drive — a
browser holding a live Google session.

Now:

- Port `6080` is gone. The noVNC client and its WebSocket bridge are served
  from the service itself, at `/vnc`, behind the same authentication as
  everything else.
- The VNC server listens on loopback inside the container only, and has no RFB
  authentication at all. There is no VNC password to configure, get wrong, or
  leak — access control lives one layer up, at the authenticated bridge. This
  also removes VNC's 8-character DES password limit, which silently truncated
  anything longer.
- **The display stack only exists during a login.** The X server, the window
  manager and the browser are started when you begin authenticating and stopped
  when the session ends. Between logins there is no framebuffer to observe.
- Only **one** observer is admitted at a time, so a second viewer cannot watch a
  login in progress.

The `vnc_password` option still validates, so an existing configuration does not
break, but it is ignored and logs a deprecation warning. You can delete it.

## Temporarily exposing a host port

Leave the port unmapped unless you have a reason not to. You need a host port
only when **Home Assistant runs on a different machine** than the auth service.

**Home Assistant OS / Supervised:** you do not need one. Use the add-on's
ingress panel.

If you do need one, treat it as temporary:

1. Add-on **Configuration → Network**, set the host port for `8099/tcp`.
2. Restart the add-on. It logs a warning, and the web UI now asks for the
   service token, because the ingress header can no longer be trusted.
3. Read the token: **Add-on → Configuration**, or from the shell,
   `cat /share/familylink/api_key`.
4. Complete the authentication.
5. **Clear the port mapping and restart the add-on again.**

**Standalone Docker:** the shipped compose file binds `127.0.0.1:8099:8099`, so
the service is reachable only from the Docker host. If Home Assistant runs
elsewhere, change it to `8099:8099` and keep it inside a trusted LAN segment.

Never place this service behind a reverse proxy, Nabu Casa remote access, a
port forward, or anything else reachable from the internet. `GET /api/cookies`
hands out a Google session; a token is not a substitute for network isolation.

## Stopping the add-on after login

The add-on only needs to run while you are authenticating and while the
integration is reading cookies from it. If you prefer the smallest possible
attack surface:

- Set the add-on to **not** start on boot, and start it only when you need to
  re-authenticate. The integration falls back to reading the encrypted cookie
  file directly from `/share/familylink`, so it keeps working while the add-on
  is stopped.
- Or leave it running and rely on ingress. The display stack is down between
  logins either way.

## What is stored, where, and for how long

Everything lives in `/share/familylink`, which is created with mode `0700` and
owned by the add-on's unprivileged user:

| File | Mode | Contents |
|---|---|---|
| `cookies.enc` | `0600` | The Google session cookies, encrypted (Fernet: AES-CBC with an HMAC), plus creation and expiry timestamps. |
| `.key` | `0600` | The Fernet key. |
| `api_key` | `0600` | The service token. |

Writes are atomic — a temporary file created `O_EXCL` with mode `0600` in the
same directory, then `os.replace` — so a crash mid-write leaves the previous
session intact rather than a truncated file. Secret files are opened with
`O_NOFOLLOW`, and a symlink found where a secret belongs is refused rather than
followed.

**Be clear about what the encryption buys you.** The key sits in the same
directory as the ciphertext, because the add-on and the Home Assistant
integration have no other shared secret channel. Anyone who can read the whole
directory therefore has both halves and can decrypt the session. The encryption
protects against a leak of the cookie file *alone* — a backup, a snapshot, a
stray copy. It is not a defence against read access to `/share/familylink`.

Consequences worth acting on:

- Anything with `share` access — another add-on, a file-editor add-on, a
  Samba share — can read the session. Review what you have installed.
- Home Assistant backups include `/share`. Encrypt your backups and treat them
  as containing a live Google session.

## Cookie expiry and deletion

The `session_duration` option (default 24 hours, range 1 hour to 7 days) is
enforced, not merely documented. The stored envelope records when the session
was created and when it expires; on every read:

- a session past its expiry is **deleted** and the read fails, so an expired
  session cannot be replayed;
- a store that cannot be decrypted or parsed is deleted too, and the integration
  is told to re-authenticate;
- a store with no usable timestamp — a corrupted or very old envelope — is
  treated as **expired**, not as valid forever.

The integration then clears its cached cookies and HTTP session, enters Home
Assistant's re-authentication state, and raises a notification.

Two different expiries are at play, and only one of them is ours:

- **Local expiry** is `session_duration`. It bounds how long *this project*
  will keep using a captured session, and it is what the checks above enforce.
- **Google's own server-side expiry** is Google's decision. Google can — and
  does — invalidate a session earlier, for example after a password change, a
  security review or a sign-out elsewhere. A session that has not reached its
  local expiry can still stop working, which surfaces as HTTP 401 and the same
  re-authentication prompt. Setting `session_duration` to seven days does not
  make Google honour a session for seven days.

To delete the stored session yourself, use the add-on API
(`DELETE /api/cookies`) or delete `/share/familylink/cookies.enc`.

Only the cookies Family Link actually needs are stored. See
[Cookie minimisation](familylink-playwright/DOCS.md#cookie-minimisation) for the
allowlist and its escape hatch.

## Rotating credentials after a suspected compromise

If you think the session or the token may have leaked, do all of the following,
in this order:

1. **Sign the Google account out everywhere.** Google Account → Security → Your
   devices → Sign out. This is the step that actually invalidates the stolen
   session; deleting local files does not.
2. **Change that account's password** and confirm two-factor authentication is
   on.
3. **Delete the local session and its key:**
   ```bash
   rm /share/familylink/cookies.enc /share/familylink/.key
   ```
   Removing `.key` makes any surviving copy of `cookies.enc` undecryptable.
4. **Rotate the service token:**
   ```bash
   rm /share/familylink/api_key
   ```
   Restart the add-on; a new token is generated. For add-on installs the
   integration picks it up automatically. For a standalone container, copy the
   new value from `./data/api_key` into the integration's token field (Settings
   → Devices & services → Google Family Link → Configure).
5. **Re-authenticate** through the add-on.
6. **Review your Home Assistant backups.** Older backups still contain the old
   session and key. Delete or re-encrypt them.

Rotating the token alone is not enough: it protects the endpoint, not the
session that already leaked. Step 1 is the one that matters.

## Logging and privacy

A redaction filter is installed on both the add-on's and the integration's
loggers, and scrubs each record before it is formatted. It removes:

- cookie values, `Cookie` and `Set-Cookie` headers, `SAPISID` and related
  values, and `SAPISIDHASH` authorisation values;
- the service token and any `api_key=`-style query parameter;
- query strings from logged URLs;
- the supervised child's coordinates, in either `(lat, lng)` or `[lat,lng]`
  form, and saved-place names and addresses;
- the child's display name and account id, once discovered;
- exception tracebacks are rendered, redacted and cached before any handler can
  print the original.

Google API response bodies are never logged in full — they are redacted and
truncated to a short prefix, because those bodies embed identifiers, device
names, coordinates and addresses.

Enabling debug logging for `custom_components.familylink` is therefore
reasonably safe to share, but read what you paste before you post it. Redaction
is a safety net, not a guarantee.

Location tracking is **off** by default, and each poll may notify the child's
device.

## Remaining risks

Stated plainly, because hardening does not remove them:

1. **The Google endpoints are unofficial.** `kidsmanagement-pa.clients6.google.com`
   is a private API reverse-engineered from the Family Link web UI, used with a
   web client's API key. It can change or disappear without notice, and using it
   may conflict with Google's Terms of Service. That is a risk you accept by
   installing this.
2. **Read access to `/share/familylink` yields the session.** The key and the
   ciphertext are co-located. See [above](#what-is-stored-where-and-for-how-long).
3. **A captured session is broadly scoped.** Cookie minimisation reduces what is
   stored, but the cookies Family Link needs are Google *account* session
   cookies. They are not scoped to Family Link, and they cannot be. This is why
   the dedicated-account recommendation matters.
4. **The Chromium sandbox depends on the host kernel.** It is enabled where the
   kernel permits unprivileged user namespaces, and the image also ships the
   SUID sandbox helper for kernels that do not. Where neither works, the service
   logs a clear warning and continues with the sandbox disabled; the browser
   still runs as an unprivileged user, with no added capabilities, only during a
   login.
5. **Anything with `share` access can read the session** — including other
   add-ons you install later.
6. **Home Assistant backups contain a live session.**
7. **The cookie allowlist has not been verified against every Google region or
   account type.** See the note in
   [DOCS.md](familylink-playwright/DOCS.md#cookie-minimisation): it needs
   testing with a real Google test account, and `cookie_allowlist_mode: legacy`
   exists as an escape hatch if strict mode fails for you.
8. **The integration trusts the auth service over plain HTTP.** Traffic between
   Home Assistant and the auth service is not encrypted. On the same host or
   through the Supervisor's internal network that is fine; across a network it
   means the token and the cookies cross that network in clear text. Keep them
   on the same host where you can.

## Reporting a vulnerability

Please report security issues privately to the maintainer through GitHub's
[private vulnerability reporting](https://github.com/noiwid/HAFamilyLink/security/advisories/new)
rather than in a public issue. Include the version of the integration and the
add-on, and how the service is reached (ingress, mapped port, standalone).

Do not include cookies, tokens, log excerpts containing credentials, or
anything identifying a child.
