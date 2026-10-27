"""SOCKS5 TCP CONNECT 入口。

mitmproxy 的 upstream 模式只接受 HTTP 代理格式。这个桥接器把 SOCKS5
CONNECT 请求转换成发往本机 HTTP MITM 入口的 HTTP CONNECT。
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
from dataclasses import dataclass


SOCKS_VERSION = 5
SOCKS_AUTH_VERSION = 1
SOCKS_COMMAND_CONNECT = 1
SOCKS_ATYP_IPV4 = 1
SOCKS_ATYP_DOMAIN = 3
SOCKS_ATYP_IPV6 = 4

SOCKS_REPLY_SUCCEEDED = 0
SOCKS_REPLY_GENERAL_FAILURE = 1
SOCKS_REPLY_CONNECTION_REFUSED = 5
SOCKS_REPLY_COMMAND_NOT_SUPPORTED = 7
SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 8
DOMAIN_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


class SocksProtocolError(Exception):
    def __init__(self, reply_code: int) -> None:
        super().__init__(f"SOCKS5 请求失败，回复码 {reply_code}")
        self.reply_code = reply_code


@dataclass(frozen=True, slots=True)
class SocksTarget:
    host: str
    port: int

    @property
    def authority(self) -> str:
        if ":" in self.host:
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"


def internal_http_proxy_host(listen_host: str) -> str:
    normalized_host = listen_host.removeprefix("[").removesuffix("]")
    if normalized_host in {"", "0.0.0.0", "localhost"}:
        return "127.0.0.1"
    if normalized_host == "::":
        return "::1"
    return normalized_host


async def read_socks_target(reader: asyncio.StreamReader) -> SocksTarget:
    request_header = await reader.readexactly(4)
    version, command, _, address_type = request_header
    if version != SOCKS_VERSION:
        raise SocksProtocolError(SOCKS_REPLY_GENERAL_FAILURE)
    if command != SOCKS_COMMAND_CONNECT:
        raise SocksProtocolError(SOCKS_REPLY_COMMAND_NOT_SUPPORTED)

    if address_type == SOCKS_ATYP_IPV4:
        target_host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
    elif address_type == SOCKS_ATYP_IPV6:
        target_host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
    elif address_type == SOCKS_ATYP_DOMAIN:
        domain_length = (await reader.readexactly(1))[0]
        domain_bytes = await reader.readexactly(domain_length)
        try:
            target_host = domain_bytes.decode("ascii")
        except UnicodeDecodeError as error:
            raise SocksProtocolError(SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED) from error
        if not DOMAIN_PATTERN.fullmatch(target_host):
            raise SocksProtocolError(SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED)
    else:
        raise SocksProtocolError(SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED)

    target_port = int.from_bytes(await reader.readexactly(2), "big")
    if target_port == 0:
        raise SocksProtocolError(SOCKS_REPLY_GENERAL_FAILURE)
    return SocksTarget(host=target_host, port=target_port)


async def send_socks_reply(
    writer: asyncio.StreamWriter,
    reply_code: int = SOCKS_REPLY_SUCCEEDED,
) -> None:
    writer.write(bytes((SOCKS_VERSION, reply_code, 0, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0)))
    await writer.drain()


async def read_http_connect_status(proxy_reader: asyncio.StreamReader) -> int:
    response_header = await asyncio.wait_for(
        proxy_reader.readuntil(b"\r\n\r\n"),
        timeout=10,
    )
    status_line = response_header.split(b"\r\n", 1)[0]
    status_parts = status_line.split(b" ", 2)
    if len(status_parts) < 2:
        raise ValueError("HTTP 代理返回了无效的 CONNECT 响应")
    return int(status_parts[1])


async def copy_stream(
    source: asyncio.StreamReader,
    destination: asyncio.StreamWriter,
) -> None:
    while data := await source.read(64 * 1024):
        destination.write(data)
        await destination.drain()


class Socks5Bridge:
    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        http_proxy_host: str,
        http_proxy_port: int,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.http_proxy_host = http_proxy_host
        self.http_proxy_port = http_proxy_port
        self._server: asyncio.AbstractServer | None = None
        self._client_tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.listen_host,
            port=self.listen_port,
        )

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        client_tasks = list(self._client_tasks)
        for client_task in client_tasks:
            client_task.cancel()
        if client_tasks:
            await asyncio.gather(*client_tasks, return_exceptions=True)
        self._client_tasks.clear()

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        current_task = asyncio.current_task()
        if current_task is not None:
            self._client_tasks.add(current_task)

        proxy_writer: asyncio.StreamWriter | None = None
        try:
            greeting = await client_reader.readexactly(2)
            version, method_count = greeting
            methods = await client_reader.readexactly(method_count)
            if version != SOCKS_VERSION or 0 not in methods:
                client_writer.write(bytes((SOCKS_VERSION, 0xFF)))
                await client_writer.drain()
                return

            client_writer.write(bytes((SOCKS_VERSION, 0)))
            await client_writer.drain()
            target = await read_socks_target(client_reader)

            try:
                proxy_reader, proxy_writer = await asyncio.open_connection(
                    self.http_proxy_host,
                    self.http_proxy_port,
                )
            except OSError:
                await send_socks_reply(
                    client_writer,
                    SOCKS_REPLY_CONNECTION_REFUSED,
                )
                return

            connect_request = (
                f"CONNECT {target.authority} HTTP/1.1\r\n"
                f"Host: {target.authority}\r\n"
                "\r\n"
            ).encode("ascii")
            proxy_writer.write(connect_request)
            await proxy_writer.drain()

            try:
                status_code = await read_http_connect_status(proxy_reader)
            except (asyncio.IncompleteReadError, TimeoutError, ValueError):
                await send_socks_reply(
                    client_writer,
                    SOCKS_REPLY_GENERAL_FAILURE,
                )
                return
            if status_code != 200:
                await send_socks_reply(
                    client_writer,
                    SOCKS_REPLY_CONNECTION_REFUSED,
                )
                return

            await send_socks_reply(client_writer)
            await self._relay(
                client_reader,
                client_writer,
                proxy_reader,
                proxy_writer,
            )
        except SocksProtocolError as error:
            with contextlib.suppress(ConnectionError, OSError):
                await send_socks_reply(client_writer, error.reply_code)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            if proxy_writer is not None:
                proxy_writer.close()
                with contextlib.suppress(ConnectionError, OSError):
                    await proxy_writer.wait_closed()
            client_writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await client_writer.wait_closed()
            if current_task is not None:
                self._client_tasks.discard(current_task)

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        proxy_reader: asyncio.StreamReader,
        proxy_writer: asyncio.StreamWriter,
    ) -> None:
        client_to_proxy = asyncio.create_task(
            copy_stream(client_reader, proxy_writer)
        )
        proxy_to_client = asyncio.create_task(
            copy_stream(proxy_reader, client_writer)
        )
        completed_tasks, pending_tasks = await asyncio.wait(
            {client_to_proxy, proxy_to_client},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for pending_task in pending_tasks:
            pending_task.cancel()
        await asyncio.gather(*pending_tasks, return_exceptions=True)
        for completed_task in completed_tasks:
            with contextlib.suppress(ConnectionError, OSError):
                completed_task.result()
