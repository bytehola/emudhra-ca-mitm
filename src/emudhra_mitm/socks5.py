"""SOCKS5 TCP CONNECT 与 DNS UDP ASSOCIATE 入口。

mitmproxy 的 upstream 模式只接受 HTTP 代理格式。这个桥接器把 SOCKS5
CONNECT 请求转换成发往本机 HTTP MITM 入口的 HTTP CONNECT。
HTTP 上游无法承载 UDP，因此 UDP ASSOCIATE 仅为热点网关转发 DNS。
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
import socket
from dataclasses import dataclass


SOCKS_VERSION = 5
SOCKS_AUTH_VERSION = 1
SOCKS_COMMAND_CONNECT = 1
SOCKS_COMMAND_UDP_ASSOCIATE = 3
SOCKS_ATYP_IPV4 = 1
SOCKS_ATYP_DOMAIN = 3
SOCKS_ATYP_IPV6 = 4

SOCKS_REPLY_SUCCEEDED = 0
SOCKS_REPLY_GENERAL_FAILURE = 1
SOCKS_REPLY_CONNECTION_REFUSED = 5
SOCKS_REPLY_COMMAND_NOT_SUPPORTED = 7
SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 8
DNS_PORT = 53
DNS_RESPONSE_TIMEOUT_SECONDS = 5.0
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


@dataclass(frozen=True, slots=True)
class SocksRequest:
    command: int
    target: SocksTarget


def internal_http_proxy_host(listen_host: str) -> str:
    normalized_host = listen_host.removeprefix("[").removesuffix("]")
    if normalized_host in {"", "0.0.0.0", "localhost"}:
        return "127.0.0.1"
    if normalized_host == "::":
        return "::1"
    return normalized_host


async def read_socks_request(reader: asyncio.StreamReader) -> SocksRequest:
    request_header = await reader.readexactly(4)
    version, command, _, address_type = request_header
    if version != SOCKS_VERSION:
        raise SocksProtocolError(SOCKS_REPLY_GENERAL_FAILURE)

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
        if command != SOCKS_COMMAND_UDP_ASSOCIATE:
            raise SocksProtocolError(SOCKS_REPLY_GENERAL_FAILURE)
    return SocksRequest(
        command=command,
        target=SocksTarget(host=target_host, port=target_port),
    )


def encode_socks_address(
    host: str,
    port: int,
) -> bytes:
    if port and not 1 <= port <= 65535:
        raise ValueError("SOCKS5 地址端口无效")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded_host = host.encode("ascii")
        if not encoded_host or len(encoded_host) > 255:
            raise ValueError("SOCKS5 域名长度无效")
        return (
            bytes((SOCKS_ATYP_DOMAIN, len(encoded_host)))
            + encoded_host
            + int(port).to_bytes(2, "big")
        )

    if address.version == 4:
        return (
            bytes((SOCKS_ATYP_IPV4,))
            + address.packed
            + int(port).to_bytes(2, "big")
        )
    return (
        bytes((SOCKS_ATYP_IPV6,))
        + address.packed
        + int(port).to_bytes(2, "big")
    )


def parse_udp_datagram(data: bytes) -> tuple[SocksTarget, bytes]:
    if len(data) < 4 or data[:2] != b"\x00\x00":
        raise ValueError("SOCKS5 UDP 数据报头无效")
    if data[2] != 0:
        raise ValueError("不支持 SOCKS5 UDP 分片")

    address_type = data[3]
    offset = 4
    if address_type == SOCKS_ATYP_IPV4:
        end = offset + 4
        if len(data) < end + 2:
            raise ValueError("SOCKS5 UDP IPv4 地址不完整")
        host = str(ipaddress.IPv4Address(data[offset:end]))
        offset = end
    elif address_type == SOCKS_ATYP_IPV6:
        end = offset + 16
        if len(data) < end + 2:
            raise ValueError("SOCKS5 UDP IPv6 地址不完整")
        host = str(ipaddress.IPv6Address(data[offset:end]))
        offset = end
    elif address_type == SOCKS_ATYP_DOMAIN:
        if len(data) < offset + 1:
            raise ValueError("SOCKS5 UDP 域名长度缺失")
        domain_length = data[offset]
        offset += 1
        end = offset + domain_length
        if len(data) < end + 2:
            raise ValueError("SOCKS5 UDP 域名不完整")
        try:
            host = data[offset:end].decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("SOCKS5 UDP 域名不是 ASCII") from error
        if not DOMAIN_PATTERN.fullmatch(host):
            raise ValueError("SOCKS5 UDP 域名无效")
        offset = end
    else:
        raise ValueError("不支持 SOCKS5 UDP 地址类型")

    port = int.from_bytes(data[offset : offset + 2], "big")
    offset += 2
    if port == 0:
        raise ValueError("SOCKS5 UDP 目标端口为空")
    return SocksTarget(host=host, port=port), data[offset:]


def build_udp_datagram(
    target: SocksTarget,
    payload: bytes,
) -> bytes:
    return b"\x00\x00\x00" + encode_socks_address(
        target.host,
        target.port,
    ) + payload


async def send_socks_reply(
    writer: asyncio.StreamWriter,
    reply_code: int = SOCKS_REPLY_SUCCEEDED,
    bound_host: str = "0.0.0.0",
    bound_port: int = 0,
) -> None:
    writer.write(
        bytes((SOCKS_VERSION, reply_code, 0))
        + encode_socks_address(bound_host, bound_port)
    )
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
        allowed_udp_ports: tuple[int, ...] = (DNS_PORT,),
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.http_proxy_host = http_proxy_host
        self.http_proxy_port = http_proxy_port
        self.allowed_udp_ports = frozenset(allowed_udp_ports)
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
            request = await read_socks_request(client_reader)
            if request.command == SOCKS_COMMAND_UDP_ASSOCIATE:
                await self._handle_udp_associate(
                    client_reader,
                    client_writer,
                )
                return
            if request.command != SOCKS_COMMAND_CONNECT:
                raise SocksProtocolError(SOCKS_REPLY_COMMAND_NOT_SUPPORTED)

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
                f"CONNECT {request.target.authority} HTTP/1.1\r\n"
                f"Host: {request.target.authority}\r\n"
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

    async def _handle_udp_associate(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        peer = client_writer.get_extra_info("peername")
        if (
            not peer
            or not ipaddress.ip_address(str(peer[0])).is_loopback
        ):
            raise SocksProtocolError(SOCKS_REPLY_CONNECTION_REFUSED)

        loop = asyncio.get_running_loop()
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setblocking(False)
        try:
            udp_socket.bind(("127.0.0.1", 0))
            bound_address = udp_socket.getsockname()
            await send_socks_reply(
                client_writer,
                bound_host="127.0.0.1",
                bound_port=int(bound_address[1]),
            )

            tcp_closed = asyncio.create_task(
                self._wait_for_tcp_close(client_reader)
            )
            try:
                while True:
                    receive_task = asyncio.create_task(
                        loop.sock_recvfrom(udp_socket, 65535)
                    )
                    completed_tasks, _ = await asyncio.wait(
                        {tcp_closed, receive_task},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if tcp_closed in completed_tasks:
                        receive_task.cancel()
                        await asyncio.gather(
                            receive_task,
                            return_exceptions=True,
                        )
                        break

                    datagram, client_address = receive_task.result()
                    response = await self._resolve_udp_datagram(datagram)
                    if response is not None:
                        udp_socket.sendto(response, client_address)
            finally:
                tcp_closed.cancel()
                await asyncio.gather(tcp_closed, return_exceptions=True)
        finally:
            udp_socket.close()

    @staticmethod
    async def _wait_for_tcp_close(
        client_reader: asyncio.StreamReader,
    ) -> None:
        while await client_reader.read(64 * 1024):
            pass

    async def _resolve_udp_datagram(
        self,
        datagram: bytes,
    ) -> bytes | None:
        try:
            target, payload = parse_udp_datagram(datagram)
        except ValueError:
            return None
        if target.port not in self.allowed_udp_ports:
            return None

        try:
            address_info = await asyncio.get_running_loop().getaddrinfo(
                target.host,
                target.port,
                type=socket.SOCK_DGRAM,
            )
        except OSError:
            return None
        if not address_info:
            return None

        family, _, _, _, remote_address = address_info[0]
        loop = asyncio.get_running_loop()
        resolve_socket = socket.socket(family, socket.SOCK_DGRAM)
        resolve_socket.setblocking(False)
        try:
            await loop.sock_sendto(resolve_socket, payload, remote_address)
            response, response_address = await asyncio.wait_for(
                loop.sock_recvfrom(resolve_socket, 65535),
                timeout=DNS_RESPONSE_TIMEOUT_SECONDS,
            )
        except (OSError, TimeoutError):
            return None
        finally:
            resolve_socket.close()

        return build_udp_datagram(
            SocksTarget(
                host=str(response_address[0]),
                port=int(response_address[1]),
            ),
            response,
        )

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
