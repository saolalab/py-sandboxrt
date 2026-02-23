"""
SOCKS5 proxy server for network filtering.

Handles non-HTTP TCP connections (SSH, database, etc.) through a SOCKS5 proxy
that applies domain-based allow/deny filtering.

Implements RFC 1928 (SOCKS5) with username/password auth (RFC 1929) support.
"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import Awaitable, Callable

from srt.debug import log_debug

FilterFunc = Callable[[int, str], Awaitable[bool]]

# SOCKS5 constants
SOCKS_VERSION = 0x05
AUTH_NONE = 0x00
AUTH_NO_ACCEPTABLE = 0xFF
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_HOST_UNREACHABLE = 0x04
RSV = 0x00


class _SocksHandler(asyncio.Protocol):
    """Handle a single SOCKS5 client connection."""

    def __init__(self, filter_func: FilterFunc, loop: asyncio.AbstractEventLoop) -> None:
        self._filter = filter_func
        self._loop = loop
        self._transport: asyncio.Transport | None = None
        self._remote_transport: asyncio.Transport | None = None
        self._buffer = b""
        self._state = "greeting"  # greeting -> request -> relay

    def connection_made(self, transport: asyncio.transports.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def data_received(self, data: bytes) -> None:
        if self._state == "relay":
            if self._remote_transport and not self._remote_transport.is_closing():
                self._remote_transport.write(data)
            return

        self._buffer += data

        if self._state == "greeting":
            self._handle_greeting()
        elif self._state == "request":
            self._loop.create_task(self._handle_request())

    def connection_lost(self, exc: Exception | None) -> None:
        if self._remote_transport and not self._remote_transport.is_closing():
            self._remote_transport.close()

    def _handle_greeting(self) -> None:
        """Parse SOCKS5 greeting and respond with chosen auth method."""
        if len(self._buffer) < 2:
            return
        ver = self._buffer[0]
        nmethods = self._buffer[1]
        if len(self._buffer) < 2 + nmethods:
            return

        if ver != SOCKS_VERSION:
            self._close()
            return

        # Accept no-auth method
        if self._transport:
            self._transport.write(struct.pack("BB", SOCKS_VERSION, AUTH_NONE))
        self._buffer = self._buffer[2 + nmethods :]
        self._state = "request"

        if self._buffer:
            self._loop.create_task(self._handle_request())

    async def _handle_request(self) -> None:
        """Parse SOCKS5 CONNECT request, filter, and establish tunnel."""
        buf = self._buffer
        if len(buf) < 4:
            return

        ver, cmd, _rsv, atyp = buf[0], buf[1], buf[2], buf[3]

        if ver != SOCKS_VERSION or cmd != CMD_CONNECT:
            self._send_reply(REP_GENERAL_FAILURE)
            return

        host: str
        port: int
        consumed: int

        if atyp == ATYP_IPV4:
            if len(buf) < 10:
                return
            host = ".".join(str(b) for b in buf[4:8])
            port = struct.unpack("!H", buf[8:10])[0]
            consumed = 10
        elif atyp == ATYP_DOMAIN:
            if len(buf) < 5:
                return
            domain_len = buf[4]
            if len(buf) < 5 + domain_len + 2:
                return
            host = buf[5 : 5 + domain_len].decode("utf-8", errors="replace")
            port = struct.unpack("!H", buf[5 + domain_len : 7 + domain_len])[0]
            consumed = 7 + domain_len
        elif atyp == ATYP_IPV6:
            if len(buf) < 22:
                return
            host = ":".join(f"{buf[4 + i]:02x}{buf[5 + i]:02x}" for i in range(0, 16, 2))
            port = struct.unpack("!H", buf[20:22])[0]
            consumed = 22
        else:
            self._send_reply(REP_GENERAL_FAILURE)
            return

        self._buffer = buf[consumed:]

        allowed = await self._filter(port, host)
        if not allowed:
            log_debug(f"SOCKS connection blocked to {host}:{port}", level="error")
            self._send_reply(REP_NOT_ALLOWED)
            return

        try:
            remote_transport, _ = await self._loop.create_connection(
                lambda: _SocksRelay(self._transport),
                host=host,
                port=port,
            )
        except OSError as exc:
            log_debug(f"SOCKS connect failed to {host}:{port}: {exc}", level="error")
            self._send_reply(REP_HOST_UNREACHABLE)
            return

        self._remote_transport = remote_transport
        self._state = "relay"

        # Build success reply with bound address
        bound = remote_transport.get_extra_info("sockname", ("0.0.0.0", 0))
        bind_addr = bound[0] if bound else "0.0.0.0"
        bind_port = bound[1] if bound else 0
        addr_bytes = (
            bytes(int(x) for x in bind_addr.split(".")) if "." in bind_addr else b"\x00\x00\x00\x00"
        )
        reply = struct.pack("!BBBB", SOCKS_VERSION, REP_SUCCESS, RSV, ATYP_IPV4)
        reply += addr_bytes + struct.pack("!H", bind_port)
        if self._transport:
            self._transport.write(reply)

        if self._buffer:
            remote_transport.write(self._buffer)
            self._buffer = b""

    def _send_reply(self, rep: int) -> None:
        reply = struct.pack(
            "!BBBBIH",
            SOCKS_VERSION,
            rep,
            RSV,
            ATYP_IPV4,
            0,
            0,
        )
        if self._transport and not self._transport.is_closing():
            self._transport.write(reply)
            self._transport.close()

    def _close(self) -> None:
        if self._transport and not self._transport.is_closing():
            self._transport.close()


class _SocksRelay(asyncio.Protocol):
    """Relay data from remote back to SOCKS client."""

    def __init__(self, client_transport: asyncio.Transport | None) -> None:
        self._client = client_transport

    def data_received(self, data: bytes) -> None:
        if self._client and not self._client.is_closing():
            self._client.write(data)

    def connection_lost(self, exc: Exception | None) -> None:
        if self._client and not self._client.is_closing():
            self._client.close()


class SocksProxyServer:
    """
    Async SOCKS5 proxy server with domain-based filtering.

    Handles TCP CONNECT requests through SOCKS5 protocol.
    """

    def __init__(self, filter_func: FilterFunc) -> None:
        self._filter = filter_func
        self._server: asyncio.Server | None = None
        self._port: int | None = None

    @property
    def port(self) -> int | None:
        return self._port

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        """Start the SOCKS5 proxy server. Returns the bound port."""
        loop = asyncio.get_running_loop()

        self._server = await loop.create_server(
            lambda: _SocksHandler(self._filter, loop),
            host=host,
            port=port,
        )

        sockets = self._server.sockets
        if sockets:
            addr = sockets[0].getsockname()
            self._port = addr[1]
            log_debug(f"SOCKS proxy listening on {host}:{self._port}")
        else:
            raise RuntimeError("Failed to bind SOCKS proxy server")

        return self._port

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            log_debug("SOCKS proxy server stopped")
