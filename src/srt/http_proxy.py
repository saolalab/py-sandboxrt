"""
HTTP/HTTPS proxy server for network filtering.

Intercepts HTTP requests and HTTPS CONNECT tunnels, applying domain-based
allow/deny filtering before forwarding traffic.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

from srt.debug import log_debug

FilterFunc = Callable[[int, str], Awaitable[bool]]
MitmSocketFunc = Callable[[str], str | None]


class _ProxyHandler(asyncio.Protocol):
    """Low-level async protocol handler for the HTTP proxy."""

    def __init__(
        self,
        filter_func: FilterFunc,
        get_mitm_socket_path: MitmSocketFunc | None,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self._filter = filter_func
        self._get_mitm = get_mitm_socket_path
        self._loop = loop
        self._transport: asyncio.Transport | None = None
        self._buffer = b""
        self._remote_transport: asyncio.Transport | None = None
        self._connect_mode = False

    def connection_made(self, transport: asyncio.transports.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def data_received(self, data: bytes) -> None:
        if self._connect_mode and self._remote_transport:
            self._remote_transport.write(data)
            return

        self._buffer += data
        if b"\r\n\r\n" not in self._buffer:
            return

        header_end = self._buffer.index(b"\r\n\r\n")
        header_bytes = self._buffer[:header_end]
        body_rest = self._buffer[header_end + 4 :]
        self._buffer = b""

        try:
            first_line = header_bytes.split(b"\r\n")[0].decode("utf-8", errors="replace")
        except Exception:
            self._send_error(400, "Bad Request")
            return

        parts = first_line.split()
        if len(parts) < 2:
            self._send_error(400, "Bad Request")
            return

        method = parts[0].upper()
        target = parts[1]

        if method == "CONNECT":
            self._loop.create_task(self._handle_connect(target, body_rest))
        else:
            self._loop.create_task(self._handle_request(method, target, header_bytes, body_rest))

    def connection_lost(self, exc: Exception | None) -> None:
        if self._remote_transport and not self._remote_transport.is_closing():
            self._remote_transport.close()

    async def _handle_connect(self, target: str, remaining: bytes) -> None:
        """Handle HTTPS CONNECT tunnel requests."""
        try:
            host, _, port_str = target.partition(":")
            port = int(port_str) if port_str else 443
        except (ValueError, TypeError):
            self._send_error(400, "Bad Request")
            return

        allowed = await self._filter(port, host)
        if not allowed:
            log_debug(f"Connection blocked to {host}:{port}", level="error")
            self._send_response(
                403,
                "Forbidden",
                b"Connection blocked by network allowlist",
                extra_headers={"X-Proxy-Error": "blocked-by-allowlist"},
            )
            return

        try:
            remote_transport, remote_protocol = await self._loop.create_connection(
                lambda: _TunnelRelay(self._transport),
                host=host,
                port=port,
            )
        except OSError as exc:
            log_debug(f"CONNECT tunnel failed: {exc}", level="error")
            self._send_error(502, "Bad Gateway")
            return

        self._remote_transport = remote_transport
        self._connect_mode = True
        if self._transport:
            self._transport.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        if remaining:
            remote_transport.write(remaining)

    async def _handle_request(self, method: str, url: str, raw_headers: bytes, body: bytes) -> None:
        """Handle plain HTTP proxy requests."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except Exception:
            self._send_error(400, "Bad Request")
            return

        allowed = await self._filter(port, hostname)
        if not allowed:
            log_debug(f"HTTP request blocked to {hostname}:{port}", level="error")
            self._send_response(
                403,
                "Forbidden",
                b"Connection blocked by network allowlist",
                extra_headers={"X-Proxy-Error": "blocked-by-allowlist"},
            )
            return

        try:
            reader, writer = await asyncio.open_connection(hostname, port)
        except OSError as exc:
            log_debug(f"Proxy request failed: {exc}", level="error")
            self._send_error(502, "Bad Gateway")
            return

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        header_lines = raw_headers.split(b"\r\n")
        header_lines[0] = f"{method} {path} HTTP/1.1".encode()
        request_data = b"\r\n".join(header_lines) + b"\r\n\r\n" + body
        writer.write(request_data)
        await writer.drain()

        try:
            response = await reader.read(65536)
            while response:
                if self._transport and not self._transport.is_closing():
                    self._transport.write(response)
                response = await reader.read(65536)
        except Exception:
            pass
        finally:
            writer.close()
            if self._transport and not self._transport.is_closing():
                self._transport.close()

    def _send_error(self, code: int, reason: str) -> None:
        self._send_response(code, reason, f"{code} {reason}".encode())

    def _send_response(
        self,
        code: int,
        reason: str,
        body: bytes,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        if not self._transport or self._transport.is_closing():
            return
        headers = f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
        if extra_headers:
            for k, v in extra_headers.items():
                headers += f"{k}: {v}\r\n"
        headers += "\r\n"
        self._transport.write(headers.encode() + body)
        self._transport.close()


class _TunnelRelay(asyncio.Protocol):
    """Relay data from remote server back to the client in CONNECT mode."""

    def __init__(self, client_transport: asyncio.Transport | None) -> None:
        self._client = client_transport

    def data_received(self, data: bytes) -> None:
        if self._client and not self._client.is_closing():
            self._client.write(data)

    def connection_lost(self, exc: Exception | None) -> None:
        if self._client and not self._client.is_closing():
            self._client.close()


class HttpProxyServer:
    """
    Async HTTP proxy server with domain-based filtering.

    Handles both HTTP requests (forwarding) and HTTPS CONNECT tunnels.
    """

    def __init__(
        self,
        filter_func: FilterFunc,
        get_mitm_socket_path: MitmSocketFunc | None = None,
    ) -> None:
        self._filter = filter_func
        self._get_mitm = get_mitm_socket_path
        self._server: asyncio.Server | None = None
        self._port: int | None = None

    @property
    def port(self) -> int | None:
        return self._port

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        """Start the proxy server. Returns the bound port."""
        loop = asyncio.get_running_loop()

        self._server = await loop.create_server(
            lambda: _ProxyHandler(self._filter, self._get_mitm, loop),
            host=host,
            port=port,
        )

        sockets = self._server.sockets
        if sockets:
            addr = sockets[0].getsockname()
            self._port = addr[1]
            log_debug(f"HTTP proxy listening on {host}:{self._port}")
        else:
            raise RuntimeError("Failed to bind HTTP proxy server")

        return self._port

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            log_debug("HTTP proxy server stopped")
