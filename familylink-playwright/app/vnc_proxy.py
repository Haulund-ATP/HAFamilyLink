"""WebSocket-to-TCP bridge that replaces the separately exposed websockify.

noVNC used to be served by its own ``websockify`` process on port 6080, which
had no authentication of any kind: anyone who could reach that port watched -
and drove - a browser holding a live Google session.

Serving the same bridge from the FastAPI app means the framebuffer inherits the
service's single authentication mechanism, needs no second published port, and
works through Home Assistant ingress. Exactly one observer is admitted at a
time, so a second viewer cannot silently watch a login in progress.
"""
from __future__ import annotations

import asyncio
import logging

from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState

_LOGGER = logging.getLogger(__name__)

# noVNC offers these subprotocols; we relay raw RFB bytes, so "binary" is the
# only one we implement. Older clients that only offer "base64" are refused
# with a clear log line rather than silently mis-framed.
_BINARY_SUBPROTOCOL = "binary"

_BUFFER_SIZE = 32 * 1024


class SingleObserverGuard:
    """Admits one framebuffer observer at a time."""

    def __init__(self) -> None:
        self._taken = False
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        """Take the observer slot, or report that it is already taken."""
        async with self._lock:
            if self._taken:
                return False
            self._taken = True
            return True

    async def release(self) -> None:
        """Give the observer slot back."""
        async with self._lock:
            self._taken = False

    @property
    def taken(self) -> bool:
        """Whether an observer currently holds the slot."""
        return self._taken


def _select_subprotocol(websocket: WebSocket) -> str | None:
    """Return the subprotocol to accept, or None when none is acceptable."""
    offered = websocket.headers.get("sec-websocket-protocol", "")
    protocols = [p.strip() for p in offered.split(",") if p.strip()]
    if not protocols:
        # Some clients omit the header entirely and expect raw binary frames.
        return None
    if _BINARY_SUBPROTOCOL in protocols:
        return _BINARY_SUBPROTOCOL
    return None


async def relay(
    websocket: WebSocket,
    host: str,
    port: int,
    connect_timeout: float = 5.0,
) -> None:
    """Relay RFB traffic between an accepted WebSocket and the VNC server."""
    subprotocol = _select_subprotocol(websocket)
    offered = websocket.headers.get("sec-websocket-protocol", "")
    if offered and subprotocol is None:
        _LOGGER.warning(
            "Refusing framebuffer connection: client offered only unsupported "
            "WebSocket subprotocols (%s); this bridge relays raw binary RFB",
            offered,
        )
        await websocket.close(code=1002)
        return

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=connect_timeout
        )
    except (OSError, asyncio.TimeoutError) as err:
        _LOGGER.warning("Framebuffer is not reachable at %s:%s: %s", host, port, err)
        await websocket.close(code=1011)
        return

    await websocket.accept(subprotocol=subprotocol)
    _LOGGER.info("Framebuffer observer connected")

    async def ws_to_tcp() -> None:
        try:
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    break
                payload = message.get("bytes")
                if payload is None:
                    text = message.get("text")
                    if text is None:
                        continue
                    payload = text.encode("utf-8")
                writer.write(payload)
                await writer.drain()
        except (WebSocketDisconnect, RuntimeError):
            pass

    async def tcp_to_ws() -> None:
        try:
            while True:
                data = await reader.read(_BUFFER_SIZE)
                if not data:
                    break
                await websocket.send_bytes(data)
        except (WebSocketDisconnect, RuntimeError, ConnectionResetError):
            pass

    pump_ws = asyncio.create_task(ws_to_tcp())
    pump_tcp = asyncio.create_task(tcp_to_ws())
    try:
        done, pending = await asyncio.wait(
            {pump_ws, pump_tcp}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            exc = task.exception()
            if exc is not None and not isinstance(
                exc, (WebSocketDisconnect, ConnectionResetError, asyncio.CancelledError)
            ):
                _LOGGER.debug("Framebuffer relay ended: %s", exc)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionResetError):
            pass
        if websocket.client_state is not WebSocketState.DISCONNECTED:
            try:
                await websocket.close()
            except RuntimeError:
                pass
        _LOGGER.info("Framebuffer observer disconnected")
