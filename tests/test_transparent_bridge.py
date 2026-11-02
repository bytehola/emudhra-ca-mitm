from __future__ import annotations

import asyncio
import socket
import struct
import unittest
from unittest import mock

from emudhra_mitm.transparent_bridge import (
    TransparentRelay,
    WindowsClientRedirector,
    build_probe_syn,
    linux_original_destination,
)
from emudhra_mitm.windivert_binding import (
    diverted_packet_meta,
    internet_checksum,
    TCP_FLAG_FIN,
    TCP_FLAG_RST,
)


def build_ipv4_tcp_packet(
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
    tcp_flags: int = 0x02,
) -> bytes:
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        0,
        0,
        5 << 4,
        tcp_flags,
        8192,
        0,
        0,
    )
    total_length = 20 + len(tcp_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        6,
        0,
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip),
    )
    return ip_header + tcp_header


def parse_packet_addresses_and_ports(packet: bytes) -> tuple[str, int, str, int]:
    source_address = ".".join(str(byte) for byte in packet[12:16])
    destination_address = ".".join(str(byte) for byte in packet[16:20])
    source_port, destination_port = struct.unpack_from("!HH", packet, 20)
    return source_address, source_port, destination_address, destination_port


class FakeOriginalDestinationSocket:
    family = socket.AF_INET

    def getsockopt(self, level: int, option: int, size: int) -> bytes:
        return struct.pack(
            "!HH4s8x",
            socket.AF_INET,
            443,
            socket.inet_aton("93.184.216.34"),
        )


class TransparentBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.proxy_connections: list[str] = []

        async def handle_proxy_client(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            headers = await reader.readuntil(b"\r\n\r\n")
            self.proxy_connections.append(headers.decode("ascii"))
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            while data := await reader.read(65536):
                writer.write(data.upper())
                await writer.drain()
            writer.close()
            await writer.wait_closed()

        self.proxy_server = await asyncio.start_server(
            handle_proxy_client,
            host="127.0.0.1",
            port=0,
        )
        self.proxy_port = self.proxy_server.sockets[0].getsockname()[1]

    async def asyncTearDown(self) -> None:
        self.proxy_server.close()
        await self.proxy_server.wait_closed()

    async def test_relays_through_http_connect(self) -> None:
        relay = TransparentRelay(
            listen_host="127.0.0.1",
            listen_port=0,
            proxy_host="127.0.0.1",
            proxy_port=self.proxy_port,
            destination_resolver=lambda _socket, _peer: (
                "example.com",
                443,
            ),
        )
        await relay.start()
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                relay.listen_port,
            )
            writer.write(b"hello")
            await writer.drain()
            self.assertEqual(await reader.readexactly(5), b"HELLO")
            writer.close()
            await writer.wait_closed()
        finally:
            await relay.close()

        self.assertEqual(len(self.proxy_connections), 1)
        self.assertIn("CONNECT example.com:443 HTTP/1.1", self.proxy_connections[0])

    def test_reads_linux_original_destination(self) -> None:
        destination = linux_original_destination(
            FakeOriginalDestinationSocket(),  # type: ignore[arg-type]
            ("192.168.1.20", 45678),
        )
        self.assertEqual(destination, ("93.184.216.34", 443))


class WindowsClientRedirectorTests(unittest.TestCase):
    def make_redirector(self) -> WindowsClientRedirector:
        return WindowsClientRedirector(
            listen_port=28083,
            redirect_target_host="192.168.137.1",
            client_network="192.168.137.0/24",
            hotspot_if_index=17,
        )

    def test_forwards_hotspot_flow_through_synthetic_port(self) -> None:
        redirector = self.make_redirector()
        request = build_ipv4_tcp_packet(
            "192.168.137.52",
            41000,
            "93.184.216.34",
            443,
        )

        rewritten = redirector._prepare_forward_packet(bytearray(request))

        self.assertIsNotNone(rewritten)
        assert rewritten is not None
        source_address, source_port, destination_address, destination_port = (
            parse_packet_addresses_and_ports(bytes(rewritten))
        )
        self.assertEqual(source_address, "192.168.137.52")
        self.assertTrue(20000 <= source_port <= 29999)
        self.assertNotEqual(source_port, 41000)
        self.assertEqual(destination_address, "192.168.137.1")
        self.assertEqual(destination_port, 28083)
        self.assertEqual(
            redirector.resolve_synthetic_port(source_port),
            ("93.184.216.34", 443),
        )

    def test_rewrites_return_flow_back_to_original_destination(self) -> None:
        redirector = self.make_redirector()
        request = build_ipv4_tcp_packet(
            "192.168.137.52",
            41000,
            "93.184.216.34",
            443,
        )
        rewritten = redirector._prepare_forward_packet(bytearray(request))
        assert rewritten is not None
        _, synthetic_port, _, _ = parse_packet_addresses_and_ports(
            bytes(rewritten)
        )

        response = build_ipv4_tcp_packet(
            "192.168.137.1",
            28083,
            "192.168.137.52",
            synthetic_port,
        )
        rewritten_response = redirector._prepare_return_packet(
            bytearray(response)
        )

        self.assertIsNotNone(rewritten_response)
        assert rewritten_response is not None
        source_address, source_port, destination_address, destination_port = (
            parse_packet_addresses_and_ports(bytes(rewritten_response))
        )
        self.assertEqual(source_address, "93.184.216.34")
        self.assertEqual(source_port, 443)
        self.assertEqual(destination_address, "192.168.137.52")
        self.assertEqual(destination_port, 41000)

    def test_allocates_distinct_synthetic_ports_for_same_client_port(
        self,
    ) -> None:
        redirector = self.make_redirector()
        first_request = build_ipv4_tcp_packet(
            "192.168.137.52",
            41000,
            "93.184.216.34",
            443,
        )
        second_request = build_ipv4_tcp_packet(
            "192.168.137.52",
            41000,
            "8.8.8.8",
            80,
        )

        first = redirector._prepare_forward_packet(bytearray(first_request))
        second = redirector._prepare_forward_packet(bytearray(second_request))

        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        assert first is not None and second is not None
        _, first_port, _, _ = parse_packet_addresses_and_ports(bytes(first))
        _, second_port, _, _ = parse_packet_addresses_and_ports(bytes(second))
        self.assertNotEqual(first_port, second_port)
        self.assertEqual(
            redirector.resolve_synthetic_port(first_port),
            ("93.184.216.34", 443),
        )
        self.assertEqual(
            redirector.resolve_synthetic_port(second_port),
            ("8.8.8.8", 80),
        )

    def test_ignores_traffic_outside_hotspot_network(self) -> None:
        redirector = self.make_redirector()
        packet = build_ipv4_tcp_packet(
            "192.168.8.77",
            41000,
            "93.184.216.34",
            443,
        )

        rewritten = redirector._prepare_forward_packet(bytearray(packet))

        self.assertIsNone(rewritten)

    def test_ignores_nat_rewritten_source_address(self) -> None:
        # NETWORK_FORWARD 层可能同时看到 NAT 后的副本，源地址是网关
        # 自己；不能再把它当成客户端流量改写，否则会二次代理。
        # 这一路要真正上报 forward-ignored，供界面统计“忽略”计数。
        events: list[tuple[str, dict]] = []
        redirector = self.make_redirector()
        redirector._event_observer = lambda name, payload: events.append(
            (name, payload)
        )
        packet = build_ipv4_tcp_packet(
            "192.168.137.1",
            41000,
            "93.184.216.34",
            443,
        )

        rewritten = redirector._prepare_forward_packet(bytearray(packet))

        self.assertIsNone(rewritten)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], "forward-ignored")
        self.assertEqual(
            events[0][1]["destination"],
            "93.184.216.34:443",
        )

    def test_rewrite_tcp_checksum_ignores_trailing_padding(self) -> None:
        redirector = self.make_redirector()
        request = build_ipv4_tcp_packet(
            "192.168.137.52",
            41000,
            "93.184.216.34",
            443,
        )
        padded = bytearray(request) + b"\xaa\xbb\xcc\xdd\xee\xff"
        rewritten = redirector._prepare_forward_packet(padded)
        assert rewritten is not None
        tcp_start = 20
        ip_total_length = struct.unpack_from("!H", rewritten, 2)[0]
        pseudo_header = (
            rewritten[12:16]
            + rewritten[16:20]
            + b"\x00\x06"
            + struct.pack("!H", ip_total_length - tcp_start)
        )
        self.assertEqual(
            internet_checksum(
                pseudo_header + rewritten[tcp_start:ip_total_length]
            ),
            b"\x00\x00",
        )
        padded_pseudo = (
            rewritten[12:16]
            + rewritten[16:20]
            + b"\x00\x06"
            + struct.pack("!H", len(rewritten) - tcp_start)
        )
        self.assertNotEqual(
            internet_checksum(padded_pseudo + rewritten[tcp_start:]),
            b"\x00\x00",
        )

    def test_reports_forward_and_return_flow_once(self) -> None:
        events: list[tuple[str, str, int]] = []
        redirector = WindowsClientRedirector(
            listen_port=28083,
            redirect_target_host="192.168.137.1",
            client_network="192.168.137.0/24",
            hotspot_if_index=17,
            event_observer=lambda name, payload: events.append(
                (name, payload["client"], payload["synthetic_port"])
            ),
        )
        request = build_ipv4_tcp_packet(
            "192.168.137.52",
            41000,
            "93.184.216.34",
            443,
        )

        first = redirector._prepare_forward_packet(bytearray(request))
        second = redirector._prepare_forward_packet(bytearray(request))
        assert first is not None and second is not None
        _, synthetic_port, _, _ = parse_packet_addresses_and_ports(
            bytes(first)
        )
        self.assertEqual(
            redirector.resolve_synthetic_port(synthetic_port),
            ("93.184.216.34", 443),
        )

        response = build_ipv4_tcp_packet(
            "192.168.137.1",
            28083,
            "192.168.137.52",
            synthetic_port,
        )
        redirector._prepare_return_packet(bytearray(response))
        redirector._prepare_return_packet(bytearray(response))

        self.assertEqual(
            events,
            [
                ("forward-flow", "192.168.137.52:41000", synthetic_port),
                ("return-flow", "192.168.137.52:41000", synthetic_port),
            ],
        )
        self.assertEqual(events[0][0], "forward-flow")

    def test_rst_from_client_removes_flow_mapping(self) -> None:
        redirector = self.make_redirector()
        request = build_ipv4_tcp_packet(
            "192.168.137.52",
            41000,
            "93.184.216.34",
            443,
        )
        rewritten = redirector._prepare_forward_packet(bytearray(request))
        assert rewritten is not None
        _, synthetic_port, _, _ = parse_packet_addresses_and_ports(
            bytes(rewritten)
        )

        reset = build_ipv4_tcp_packet(
            "192.168.137.52",
            41000,
            "93.184.216.34",
            443,
            tcp_flags=TCP_FLAG_RST,
        )
        reset_rewritten = redirector._prepare_forward_packet(
            bytearray(reset)
        )

        # RST 段本身仍要转发，但映射必须立刻回收。
        self.assertIsNotNone(reset_rewritten)
        self.assertIsNone(redirector.resolve_synthetic_port(synthetic_port))

    def test_server_fin_removes_flow_mapping(self) -> None:
        redirector = self.make_redirector()
        request = build_ipv4_tcp_packet(
            "192.168.137.52",
            41000,
            "93.184.216.34",
            443,
        )
        rewritten = redirector._prepare_forward_packet(bytearray(request))
        assert rewritten is not None
        _, synthetic_port, _, _ = parse_packet_addresses_and_ports(
            bytes(rewritten)
        )

        fin_response = build_ipv4_tcp_packet(
            "192.168.137.1",
            28083,
            "192.168.137.52",
            synthetic_port,
            tcp_flags=TCP_FLAG_FIN,
        )
        rewritten_fin = redirector._prepare_return_packet(
            bytearray(fin_response)
        )

        self.assertIsNotNone(rewritten_fin)
        self.assertIsNone(redirector.resolve_synthetic_port(synthetic_port))

    def test_return_to_other_client_is_not_rewritten(self) -> None:
        # 另一台客户端的真实临时端口与合成端口重合时，返回包目的
        # 地址不是该流的客户端；必须拒绝重写，杜绝跨连接串流。
        redirector = self.make_redirector()
        request = build_ipv4_tcp_packet(
            "192.168.137.52",
            41000,
            "93.184.216.34",
            443,
        )
        rewritten = redirector._prepare_forward_packet(bytearray(request))
        assert rewritten is not None
        _, synthetic_port, _, _ = parse_packet_addresses_and_ports(
            bytes(rewritten)
        )

        mismatched_response = build_ipv4_tcp_packet(
            "192.168.137.1",
            28083,
            "192.168.137.99",
            synthetic_port,
        )
        with mock.patch(
            "emudhra_mitm.transparent_bridge.append_bridge_log"
        ):
            result = redirector._prepare_return_packet(
                bytearray(mismatched_response)
            )

        self.assertIsNone(result)
        self.assertEqual(
            redirector.resolve_synthetic_port(synthetic_port),
            ("93.184.216.34", 443),
        )

    def test_unmatched_return_logs_only_once_per_port(self) -> None:
        redirector = self.make_redirector()
        for destination in ("192.168.137.60", "192.168.137.61"):
            packet = build_ipv4_tcp_packet(
                "192.168.137.1",
                28083,
                destination,
                45000,
            )
            with mock.patch(
                "emudhra_mitm.transparent_bridge.append_bridge_log"
            ) as log:
                redirector._prepare_return_packet(bytearray(packet))
                if destination == "192.168.137.60":
                    self.assertEqual(log.call_count, 1)
                else:
                    self.assertEqual(log.call_count, 0)

    def test_probe_source_packets_are_not_tracked(self) -> None:
        # 注入自检借用真实客户端 IP 发探测包；这类包不得登记流表。
        redirector = self.make_redirector()
        redirector._probe_source = "192.168.137.52"
        packet = build_ipv4_tcp_packet(
            "192.168.137.52",
            41000,
            "93.184.216.34",
            443,
        )

        self.assertIsNone(redirector._prepare_forward_packet(bytearray(packet)))
        self.assertEqual(len(redirector._flows_by_client), 0)

    def test_shifts_dns_udp_port_to_avoid_port_53(self) -> None:
        redirector = self.make_redirector()
        query = build_ipv4_udp_packet(
            "192.168.137.52",
            45000,
            "192.168.137.1",
            53,
        )

        rewritten = redirector._prepare_dns_forward_packet(bytearray(query))

        self.assertIsNotNone(rewritten)
        assert rewritten is not None
        _, _, _, destination_port = parse_packet_addresses_and_ports_udp(
            bytes(rewritten)
        )
        self.assertEqual(destination_port, 15353)

        response = build_ipv4_udp_packet(
            "192.168.137.1",
            15353,
            "192.168.137.52",
            45000,
        )
        rewritten_response = redirector._prepare_dns_return_packet(
            bytearray(response)
        )

        self.assertIsNotNone(rewritten_response)
        assert rewritten_response is not None
        source_address, source_port, _, _ = (
            parse_packet_addresses_and_ports_udp(bytes(rewritten_response))
        )
        self.assertEqual(source_address, "192.168.137.1")
        self.assertEqual(source_port, 53)

    def test_leaves_non_dns_udp_untouched(self) -> None:
        redirector = self.make_redirector()
        packet = build_ipv4_udp_packet(
            "192.168.137.52",
            45000,
            "192.168.137.1",
            123,
        )

        self.assertIsNone(
            redirector._prepare_dns_forward_packet(bytearray(packet))
        )

    def test_leaves_dns_query_to_other_resolver_untouched(self) -> None:
        # 只平移发往热点网关的查询；手机写死 8.8.8.8 时保持原样交给
        # ICS NAT，不能把目的端口改到 15353 后无人监听。
        redirector = self.make_redirector()
        packet = build_ipv4_udp_packet(
            "192.168.137.52",
            45000,
            "8.8.8.8",
            53,
        )

        self.assertIsNone(
            redirector._prepare_dns_forward_packet(bytearray(packet))
        )

    def test_client_address_detection(self) -> None:
        redirector = self.make_redirector()

        self.assertTrue(redirector._is_client_address("192.168.137.52"))
        self.assertFalse(redirector._is_client_address("192.168.137.1"))
        self.assertFalse(redirector._is_client_address("192.168.8.77"))

    def test_inject_inbound_forces_inbound_and_hotspot_interface(self) -> None:
        redirector = self.make_redirector()
        sent: list[tuple[bytes, int, bool]] = []

        class FakeHandle:
            def send(self, packet, meta) -> None:
                sent.append((packet, meta.if_index, meta.outbound))

        meta = diverted_packet_meta(if_index=3, outbound=True, ipv6=False)

        redirector._inject_inbound(
            FakeHandle(),  # type: ignore[arg-type]
            b"packet",
            meta,
        )

        self.assertEqual(sent, [(b"packet", 17, False)])

    def test_probe_syn_has_valid_checksums(self) -> None:
        packet = build_probe_syn(
            "192.168.137.222",
            40099,
            "192.168.137.1",
            28083,
        )

        self.assertEqual(internet_checksum(packet[:20]), b"\x00\x00")
        pseudo_header = (
            packet[12:16]
            + packet[16:20]
            + b"\x00\x06"
            + struct.pack("!H", len(packet) - 20)
        )
        self.assertEqual(
            internet_checksum(pseudo_header + packet[20:]),
            b"\x00\x00",
        )

    def test_probe_return_marks_self_test(self) -> None:
        redirector = self.make_redirector()
        redirector._probe_port = 40100
        response = build_ipv4_tcp_packet(
            "192.168.137.1",
            28083,
            "192.168.137.222",
            40100,
        )

        with mock.patch(
            "emudhra_mitm.transparent_bridge.append_bridge_log"
        ):
            rewritten = redirector._prepare_return_packet(
                bytearray(response)
            )

        self.assertIsNone(rewritten)
        self.assertTrue(redirector._probe_seen.is_set())


    def test_reuses_synthetic_port_for_retransmits_of_same_flow(self) -> None:
        redirector = self.make_redirector()
        request = build_ipv4_tcp_packet(
            "192.168.137.52",
            41000,
            "93.184.216.34",
            443,
        )

        first = redirector._prepare_forward_packet(bytearray(request))
        second = redirector._prepare_forward_packet(bytearray(request))

        assert first is not None and second is not None
        self.assertEqual(bytes(first), bytes(second))

def build_ipv4_udp_packet(
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
) -> bytes:
    udp_header = struct.pack("!HHHH", source_port, destination_port, 8 + 12, 0)
    payload = b"query-bytes-1234567"
    total_length = 20 + len(udp_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        17,
        0,
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip),
    )
    return ip_header + udp_header + payload


def parse_packet_addresses_and_ports_udp(
    packet: bytes,
) -> tuple[str, int, str, int]:
    source_address = ".".join(str(byte) for byte in packet[12:16])
    destination_address = ".".join(str(byte) for byte in packet[16:20])
    source_port, destination_port = struct.unpack_from("!HH", packet, 20)
    return source_address, source_port, destination_address, destination_port


if __name__ == "__main__":
    unittest.main()
