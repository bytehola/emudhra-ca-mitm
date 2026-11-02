from __future__ import annotations

import asyncio
import socket
import unittest

from emudhra_mitm.socks5 import (
    Socks5Bridge,
    SocksTarget,
    build_udp_datagram,
    internal_http_proxy_host,
    parse_udp_datagram,
)


def find_free_ports(port_count: int) -> list[int]:
    listeners: list[socket.socket] = []
    try:
        for _ in range(port_count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listeners.append(listener)
        return [listener.getsockname()[1] for listener in listeners]
    finally:
        for listener in listeners:
            listener.close()


class SocksTargetTests(unittest.TestCase):
    def test_formats_ipv4_authority(self) -> None:
        target = SocksTarget(host="127.0.0.1", port=443)
        self.assertEqual(target.authority, "127.0.0.1:443")

    def test_formats_ipv6_authority(self) -> None:
        target = SocksTarget(host="::1", port=443)
        self.assertEqual(target.authority, "[::1]:443")

    def test_selects_internal_http_host(self) -> None:
        self.assertEqual(internal_http_proxy_host("0.0.0.0"), "127.0.0.1")
        self.assertEqual(internal_http_proxy_host("::"), "::1")
        self.assertEqual(internal_http_proxy_host("[::]"), "::1")
        self.assertEqual(internal_http_proxy_host("::1"), "::1")


class Socks5BridgeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.http_proxy_port, self.socks_port = find_free_ports(2)
        self.dns_server_port = self._reserve_udp_port()
        self.http_proxy_server = await asyncio.start_server(
            self._handle_http_proxy,
            host="127.0.0.1",
            port=self.http_proxy_port,
        )
        self.dns_server_transport, _ = await self.loop.create_datagram_endpoint(
            self._create_dns_server,
            local_addr=("127.0.0.1", self.dns_server_port),
        )
        self.bridge = Socks5Bridge(
            listen_host="127.0.0.1",
            listen_port=self.socks_port,
            http_proxy_host="127.0.0.1",
            http_proxy_port=self.http_proxy_port,
            allowed_udp_ports=(self.dns_server_port,),
        )
        await self.bridge.start()

    async def asyncTearDown(self) -> None:
        await self.bridge.close()
        self.dns_server_transport.close()
        self.http_proxy_server.close()
        await self.http_proxy_server.wait_closed()

    @staticmethod
    def _reserve_udp_port() -> int:
        probe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe_socket.bind(("127.0.0.1", 0))
            return int(probe_socket.getsockname()[1])
        finally:
            probe_socket.close()

    def _create_dns_server(self) -> asyncio.DatagramProtocol:
        class EchoDnsProtocol(asyncio.DatagramProtocol):
            def connection_made(self, transport: asyncio.BaseTransport) -> None:
                self.transport = transport

            def datagram_received(
                self,
                data: bytes,
                address: tuple[str, int],
            ) -> None:
                self.transport.sendto(b"dns:" + data, address)

        return EchoDnsProtocol()

    async def _handle_http_proxy(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        request_header = await reader.readuntil(b"\r\n\r\n")
        self.last_connect_request = request_header.decode("ascii")
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        while data := await reader.read(4096):
            writer.write(data)
            await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def test_bridges_connect_and_relays_bytes(self) -> None:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            self.socks_port,
        )
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\x00")

        target = SocksTarget(host="echo.example", port=443)
        domain = target.host.encode("ascii")
        writer.write(
            b"\x05\x01\x00\x03"
            + bytes((len(domain),))
            + domain
            + target.port.to_bytes(2, "big")
        )
        await writer.drain()
        self.assertEqual(
            await reader.readexactly(10),
            b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",
        )

        writer.write(b"payload")
        await writer.drain()
        self.assertEqual(await reader.readexactly(7), b"payload")
        self.assertIn("CONNECT echo.example:443", self.last_connect_request)

        writer.close()
        await writer.wait_closed()

    async def test_rejects_non_connect_command(self) -> None:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            self.socks_port,
        )
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\x00")

        writer.write(b"\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x50")
        await writer.drain()
        reply = await reader.readexactly(10)
        self.assertEqual(reply[1], 7)

        writer.close()
        await writer.wait_closed()

    async def test_udp_associate_relays_dns_datagram(self) -> None:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            self.socks_port,
        )
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\x00")

        writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        reply = await reader.readexactly(10)
        self.assertEqual(reply[1], 0)
        self.assertEqual(reply[3], 1)
        udp_host = socket.inet_ntoa(reply[4:8])
        udp_port = int.from_bytes(reply[8:10], "big")

        udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_client.setblocking(False)
        try:
            query = b"\x12\x34\x01\x00"
            udp_client.sendto(
                build_udp_datagram(
                    SocksTarget(
                        host="127.0.0.1",
                        port=self.dns_server_port,
                    ),
                    query,
                ),
                (udp_host, udp_port),
            )
            response = await asyncio.wait_for(
                self.loop.sock_recv(udp_client, 65535),
                timeout=2,
            )
        finally:
            udp_client.close()

        target, payload = parse_udp_datagram(response)
        self.assertEqual(target.port, self.dns_server_port)
        self.assertEqual(payload, b"dns:" + query)

        writer.close()
        await writer.wait_closed()


if __name__ == "__main__":
    unittest.main()
