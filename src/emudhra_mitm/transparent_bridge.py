"""把透明重定向的 TCP 连接转交给现有 HTTP upstream 代理入口。

Linux 使用 nftables REDIRECT + SO_ORIGINAL_DST 还原原始目标；
Windows 使用 WinDivert 在转发层（NETWORK_FORWARD）截获热点客户端的
TCP 80/443，改写目的地址到本机透明桥（每个连接分配独立的合成源
端口），返回方向再做二次改写。热点客户端的流量由 ICS 转发，只出现
在 NETWORK_FORWARD 层，本机代理自己产生的响应仍在 NETWORK 层。
Windows 上同时在 53 端口运行 DNS 转发器，并丢弃客户端的 UDP 443
以促使 QUIC 回退到 TCP。两条路径都不依赖 ICS 的 NAT 与 HNetCfg COM。
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime
import ipaddress
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from emudhra_mitm.app_paths import CONFIG_DIRECTORY
from emudhra_mitm.windivert_binding import (
    diverted_packet_meta,
    internet_checksum,
    parse_ipv4_tcp,
    parse_ipv4_udp,
    rewrite_ipv4_tcp_addresses_and_ports,
    rewrite_ipv4_udp_ports,
    WINDIVERT_ADDRESS_SIZE,
    WINDIVERT_LAYER_NETWORK_FORWARD,
    TCP_FLAG_FIN,
    TCP_FLAG_RST,
    WindivertShutdown,
)


CONNECT_TIMEOUT_SECONDS = 10.0
COPY_BUFFER_SIZE = 64 * 1024
DNS_PORT = 53
DNS_RESPONSE_TIMEOUT_SECONDS = 3.0
# Linux 内核在 AF_INET6 套接字上同样以 SOL_IP(0) 层级暴露
# SO_ORIGINAL_DST(80)，该值就是 ip6_tables 里的 IP6T_SO_ORIGINAL_DST；
# 两个常量数值相同，IPv4/IPv6 分支沿用同一个选项号。
LINUX_ORIGINAL_DST_OPTION = 80
# 这些过滤器在 NETWORK_FORWARD 层使用：ICS 转发流量只在这一层可见。
# 不能加 inbound/outbound 限定词——转发层的方向标记以出发/到达接口
# 为准，客户端请求和 NAT 后的副本都可能匹配，方向交给源地址判断。
WINDOWS_CAPTURE_FILTER = (
    "ip and tcp and "
    "(tcp.DstPort == 80 or tcp.DstPort == 443)"
)
WINDOWS_RETURN_FILTER = (
    "outbound and ip and tcp and tcp.SrcPort == {listen_port}"
)
WINDOWS_IPV6_FILTER = "ipv6"
# 客户端 QUIC（UDP 443）在转发层直接丢弃，促使应用回退到 TCP 进入代理。
WINDOWS_QUIC_FILTER = "ip and udp and udp.DstPort == 443"
# DNS 转发器绑定 15353 而不是 53：实测在 192.168.137.1:53 上绑定会让
# ipnathlp 崩溃（热点随之消失）。客户端发往网关 :53 的查询平移到
# :15353，返回方向再改回来，53 端口始终保持空闲。
# 目的地址是热点网关本身（本机地址），属于本地入站流量，只会出现在
# NETWORK 层，不能用 NETWORK_FORWARD。
WINDOWS_DNS_FORWARD_FILTER = "inbound and ip and udp and udp.DstPort == 53"
WINDOWS_DNS_RETURN_FILTER = (
    "outbound and ip and udp and udp.SrcPort == {dns_port}"
)
WINDOWS_DNS_LISTEN_PORT = 15353
WINDOWS_SYNTHETIC_PORT_START = 20000
WINDOWS_SYNTHETIC_PORT_END = 29999
# 上限取满整个合成端口段：正常连接靠 FIN/RST 及时回收，LRU 只做兜底，
# 避免流量突发时把仍在传输的长连接驱逐掉。
WINDOWS_MAX_FLOWS = (
    WINDOWS_SYNTHETIC_PORT_END - WINDOWS_SYNTHETIC_PORT_START + 1
)
TRANSPARENT_LOG_PATH = CONFIG_DIRECTORY / "transparent.log"
TRANSPARENT_LOG_MAX_BYTES = 1024 * 1024
BRIDGE_LOG_PATH = CONFIG_DIRECTORY / "transparent-bridge.log"
BRIDGE_LOG_MAX_BYTES = 512 * 1024
INJECTION_PROBE_PORT = 40099
INJECTION_PROBE_TIMEOUT_SECONDS = 1.5
EVENT_LOCK = threading.Lock()

Destination = tuple[str, int]
DestinationResolver = Callable[
    [socket.socket, tuple[Any, ...]],
    Destination | None,
]
FlowEventObserver = Callable[[str, dict[str, Any]], None]


@dataclass(slots=True)
class WindowsForwardFlow:
    client_address: str
    client_port: int
    destination_address: str
    destination_port: int
    interface_index: int
    synthetic_port: int
    return_reported: bool = False


def format_authority(destination: Destination) -> str:
    host, port = destination
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def append_bridge_log(message: str) -> None:
    """把透明桥日志同时写入文件，便于没有控制台时排查。"""
    timestamp = datetime.datetime.now().astimezone().isoformat(
        timespec="seconds"
    )
    with EVENT_LOCK, contextlib.suppress(OSError):
        BRIDGE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if (
            BRIDGE_LOG_PATH.is_file()
            and BRIDGE_LOG_PATH.stat().st_size >= BRIDGE_LOG_MAX_BYTES
        ):
            rotated_path = Path(f"{BRIDGE_LOG_PATH}.1")
            with contextlib.suppress(OSError):
                rotated_path.unlink()
            with contextlib.suppress(OSError):
                BRIDGE_LOG_PATH.replace(rotated_path)
        with BRIDGE_LOG_PATH.open("a", encoding="utf-8") as log_file:
            log_file.write(f"{timestamp} {message}\n")


def build_udp_probe(
    source_address: str,
    source_port: int,
    destination_address: str,
    destination_port: int,
    payload: bytes,
) -> bytes:
    """构造一个 IPv4/UDP 探测包（UDP 校验和置 0，IPv4 允许）。"""
    udp_header = struct.pack(
        "!HHHH",
        source_port,
        destination_port,
        8 + len(payload),
        0,
    )
    udp_datagram = udp_header + payload
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp_datagram),
        0,
        0,
        64,
        17,
        0,
        socket.inet_aton(source_address),
        socket.inet_aton(destination_address),
    )
    packet = bytearray(ip_header + udp_datagram)
    packet[10:12] = internet_checksum(bytes(packet[:20]))
    return bytes(packet)


def build_probe_syn(
    source_address: str,
    source_port: int,
    destination_address: str,
    destination_port: int,
) -> bytes:
    """构造一个校验和正确的 TCP SYN，用于启动时的注入自检。"""
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        0,
        0,
        5 << 4,
        0x02,
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
        0x4000,
        64,
        6,
        0,
        socket.inet_aton(source_address),
        socket.inet_aton(destination_address),
    )
    packet = bytearray(ip_header + tcp_header)
    packet[10:12] = internet_checksum(bytes(packet[:20]))
    pseudo_header = (
        packet[12:16]
        + packet[16:20]
        + b"\x00\x06"
        + struct.pack("!H", len(packet) - 20)
    )
    packet[20 + 16 : 20 + 18] = internet_checksum(
        bytes(pseudo_header) + bytes(packet[20:])
    )
    return bytes(packet)


def linux_original_destination(
    client_socket: socket.socket,
    peer: tuple[Any, ...],
) -> Destination | None:
    try:
        if client_socket.family == socket.AF_INET:
            raw_address = client_socket.getsockopt(
                socket.SOL_IP,
                LINUX_ORIGINAL_DST_OPTION,
                16,
            )
            port = int.from_bytes(raw_address[2:4], "big")
            host = socket.inet_ntop(socket.AF_INET, raw_address[4:8])
        elif client_socket.family == socket.AF_INET6:
            raw_address = client_socket.getsockopt(
                socket.SOL_IPV6,
                LINUX_ORIGINAL_DST_OPTION,
                28,
            )
            port = int.from_bytes(raw_address[2:4], "big")
            host = socket.inet_ntop(socket.AF_INET6, raw_address[8:24])
        else:
            return None
    except OSError:
        return None

    if not host or not 1 <= port <= 65535:
        return None
    return host, port


class WindowsClientRedirector:
    """用 WinDivert 截获热点客户端的 TCP 80/443 与 DNS 查询。

    客户端流量由 ICS 转发，必须使用 NETWORK_FORWARD 层捕获；本机透明
    桥自己产生的响应仍用 NETWORK 层。捕获点在 ICS NAT 之前，每个流
    的四元组稳定。转发方向把目的地址改写为本机透明桥地址，同时给每
    个连接分配独立的合成源端口，再以入站方向注入 NETWORK 层交给本地
    监听端口；返回方向按 tcp.SrcPort == 透明桥端口捕获响应，把源地址
    改回原始目的、目的端口改回客户端原始端口。第三个句柄丢弃热点
    网卡的 IPv6，第四个句柄丢弃客户端 QUIC，迫使客户端回退 IPv4/TCP。
    """

    def __init__(
        self,
        listen_port: int,
        redirect_target_host: str,
        client_network: str,
        hotspot_if_index: int,
        dns_redirect_port: int = WINDOWS_DNS_LISTEN_PORT,
        event_observer: FlowEventObserver | None = None,
    ) -> None:
        if not redirect_target_host:
            raise ValueError("Windows 透明重定向缺少本机交付地址")
        self.listen_port = listen_port
        self.redirect_target_host = redirect_target_host
        try:
            self._redirect_target_address = ipaddress.ip_address(
                redirect_target_host
            )
        except ValueError:
            self._redirect_target_address = None
        self.client_network = (
            ipaddress.ip_network(client_network, strict=False)
            if client_network
            else None
        )
        self.hotspot_if_index = hotspot_if_index
        self.dns_redirect_port = dns_redirect_port
        self._event_observer = event_observer
        self._flows_by_client: dict[
            tuple[str, int, str, int],
            WindowsForwardFlow,
        ] = {}
        self._flows_by_synthetic: OrderedDict[
            int,
            WindowsForwardFlow,
        ] = OrderedDict()
        self._logged_no_flow_ports: set[int] = set()
        self._probe_port: int | None = None
        self._probe_source: str | None = None
        self._probe_seen = threading.Event()
        self._if_index_offset = 16
        self._inject_flags = 0
        self._inject_target_host = redirect_target_host
        self._inject_if_index = hotspot_if_index
        self._inject_handle: Any | None = None
        self._probe_handle: Any | None = None
        self._inbound_address_logged = False
        self._handled_address_logged = False
        self._lock = threading.RLock()
        self._next_synthetic_port = WINDOWS_SYNTHETIC_PORT_START
        self._stopping = threading.Event()
        self._forward_handle: Any | None = None
        self._return_handle: Any | None = None
        self._ipv6_handle: Any | None = None
        self._quic_handle: Any | None = None
        self._dns_forward_handle: Any | None = None
        self._dns_return_handle: Any | None = None
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        from emudhra_mitm.windivert_binding import WindivertHandle

        self._stopping.clear()
        self._forward_handle = WindivertHandle(
            WINDOWS_CAPTURE_FILTER,
            WINDIVERT_LAYER_NETWORK_FORWARD,
        )
        self._return_handle = WindivertHandle(
            WINDOWS_RETURN_FILTER.format(listen_port=self.listen_port)
        )
        self._ipv6_handle = WindivertHandle(
            WINDOWS_IPV6_FILTER,
            WINDIVERT_LAYER_NETWORK_FORWARD,
        )
        self._quic_handle = WindivertHandle(
            WINDOWS_QUIC_FILTER,
            WINDIVERT_LAYER_NETWORK_FORWARD,
        )
        self._dns_forward_handle = WindivertHandle(
            WINDOWS_DNS_FORWARD_FILTER
        )
        self._dns_return_handle = WindivertHandle(
            WINDOWS_DNS_RETURN_FILTER.format(dns_port=self.dns_redirect_port)
        )
        try:
            self._forward_handle.open()
            self._return_handle.open()
            self._ipv6_handle.open()
            self._quic_handle.open()
            self._dns_forward_handle.open()
            self._dns_return_handle.open()
            threads = [
                threading.Thread(
                    target=self._forward_loop,
                    name="emudhra-windivert-forward",
                    daemon=True,
                ),
                threading.Thread(
                    target=self._return_loop,
                    name="emudhra-windivert-return",
                    daemon=True,
                ),
                threading.Thread(
                    target=self._ipv6_loop,
                    name="emudhra-windivert-ipv6",
                    daemon=True,
                ),
                threading.Thread(
                    target=self._quic_loop,
                    name="emudhra-windivert-quic",
                    daemon=True,
                ),
                threading.Thread(
                    target=self._dns_forward_loop,
                    name="emudhra-windivert-dns-forward",
                    daemon=True,
                ),
                threading.Thread(
                    target=self._dns_return_loop,
                    name="emudhra-windivert-dns-return",
                    daemon=True,
                ),
            ]
            for thread in threads:
                thread.start()
            self._threads = threads
            self._write_log(
                "透明重定向已启用: 捕获=NETWORK_FORWARD, "
                "注入=NETWORK, "
                f"热点接口={self.hotspot_if_index or '未指定'}, "
                f"交付地址={self.redirect_target_host}:{self.listen_port}"
            )
            if self.hotspot_if_index <= 0:
                self._write_log(
                    "警告: 未提供热点接口索引，IPv6 丢弃和入站注入"
                    "可能失效"
                )
            try:
                self._run_injection_self_test()
            except Exception as error:  # noqa: BLE001
                self._write_log(f"注入自检异常（已忽略）: {error!r}")
        except Exception:
            self.stop()
            raise

    def resolve(
        self,
        client_socket: socket.socket,
        peer: tuple[Any, ...],
    ) -> Destination | None:
        if len(peer) < 2:
            return None
        return self.resolve_synthetic_port(int(peer[1]))

    def resolve_synthetic_port(self, synthetic_port: int) -> Destination | None:
        with self._lock:
            flow = self._flows_by_synthetic.get(synthetic_port)
        if flow is None:
            return None
        return flow.destination_address, flow.destination_port

    def stop(self) -> None:
        self._stopping.set()
        for handle in (
            self._forward_handle,
            self._return_handle,
            self._ipv6_handle,
            self._quic_handle,
            self._dns_forward_handle,
            self._dns_return_handle,
            self._inject_handle,
        ):
            if handle is None:
                continue
            with contextlib.suppress(Exception):
                handle.close()
        for thread in self._threads:
            if thread is threading.current_thread():
                continue
            thread.join(timeout=2)
        self._threads = []
        self._forward_handle = None
        self._return_handle = None
        self._ipv6_handle = None
        self._quic_handle = None
        self._dns_forward_handle = None
        self._dns_return_handle = None
        self._inject_handle = None

    def _send_meta(
        self,
        handle: Any,
        packet: bytes,
        meta: diverted_packet_meta,
    ) -> None:
        """按已检测到的地址布局注入；默认布局见 diverted_packet_meta。"""
        if handle is None:
            return
        if self._if_index_offset == 16 and self._inject_flags == 0:
            handle.send(packet, meta)
            return
        address = bytearray(WINDIVERT_ADDRESS_SIZE)
        flags = self._inject_flags
        if meta.outbound:
            flags |= 1 << 17
        if meta.ipv6:
            flags |= 1 << 20
        struct.pack_into("<I", address, 8, flags)
        if self._if_index_offset:
            struct.pack_into(
                "<I",
                address,
                self._if_index_offset,
                meta.if_index,
            )
        handle.send_with_address(packet, bytes(address))

    def _inject_inbound(
        self,
        handle: Any,
        packet: bytes,
        meta: diverted_packet_meta,
    ) -> None:
        """把 NETWORK_FORWARD 层截获的包以入站方向注入 NETWORK 层。

        注入必须走 NETWORK 层句柄（这里复用返回句柄），否则包会再次
        进入转发路径。目的地址落在热点网关上，因此接口索引固定为热点
        网卡，满足 Windows 的强主机接收模型。
        """
        if handle is None:
            return
        target = self._inject_handle or handle
        meta.outbound = False
        meta.if_index = self._inject_if_index
        self._send_meta(target, packet, meta)

    def _dns_forward_loop(self) -> None:
        handle = self._dns_forward_handle
        while not self._stopping.is_set():
            try:
                packet, meta = handle.recv(COPY_BUFFER_SIZE)
            except (OSError, WindivertShutdown) as error:
                if not self._stopping.is_set():
                    self._write_log(f"DNS 平移句柄读取失败: {error}")
                return

            try:
                rewritten = self._prepare_dns_forward_packet(
                    bytearray(packet)
                )
                if rewritten is None:
                    self._send_meta(handle, packet, meta)
                else:
                    self._inject_inbound(
                        self._dns_return_handle,
                        bytes(rewritten),
                        meta,
                    )
            except (OSError, RuntimeError, ValueError) as error:
                self._write_log(f"处理 DNS 查询平移失败: {error}")

    def _dns_return_loop(self) -> None:
        handle = self._dns_return_handle
        while not self._stopping.is_set():
            try:
                packet, meta = handle.recv(COPY_BUFFER_SIZE)
            except (OSError, WindivertShutdown) as error:
                if not self._stopping.is_set():
                    self._write_log(f"DNS 返回句柄读取失败: {error}")
                return

            try:
                rewritten = self._prepare_dns_return_packet(
                    bytearray(packet)
                )
                if rewritten is None:
                    self._send_meta(handle, packet, meta)
                else:
                    self._send_meta(handle, bytes(rewritten), meta)
            except (OSError, RuntimeError, ValueError) as error:
                self._write_log(f"处理 DNS 响应改写失败: {error}")

    def _prepare_dns_forward_packet(
        self,
        packet: bytearray,
    ) -> bytearray | None:
        """把热点客户端发往 :53 的 DNS 查询平移到 :15353。"""
        parsed = parse_ipv4_udp(bytes(packet))
        if parsed is None:
            return None
        (
            source_address,
            _source_port,
            destination_address,
            destination_port,
            ip_header_length,
        ) = parsed
        if destination_port != DNS_PORT:
            return None
        # 只接管客户端发给热点网关的查询；发给其他 DNS（如手机写死
        # 8.8.8.8）的查询原样放行，避免把包改到本机 15353 后丢弃。
        if (
            self._redirect_target_address is None
            or ipaddress.ip_address(destination_address)
            != self._redirect_target_address
        ):
            return None
        if not self._is_client_address(source_address):
            return None
        rewrite_ipv4_udp_ports(
            packet,
            ip_header_length,
            destination_port=self.dns_redirect_port,
        )
        return packet

    def _prepare_dns_return_packet(
        self,
        packet: bytearray,
    ) -> bytearray | None:
        """把转发器的 DNS 响应源端口从 :15353 改回 :53。"""
        parsed = parse_ipv4_udp(bytes(packet))
        if parsed is None:
            return None
        (
            source_address,
            source_port,
            _destination_address,
            _destination_port,
            ip_header_length,
        ) = parsed
        if source_port != self.dns_redirect_port:
            return None
        if self.redirect_target_host and (
            source_address != self.redirect_target_host
        ):
            return None
        rewrite_ipv4_udp_ports(
            packet,
            ip_header_length,
            source_port=DNS_PORT,
        )
        return packet

    def _forward_loop(self) -> None:
        handle = self._forward_handle
        while not self._stopping.is_set():
            try:
                packet, address, meta = handle.recv_raw(COPY_BUFFER_SIZE)
            except (OSError, WindivertShutdown) as error:
                if not self._stopping.is_set():
                    self._write_log(f"WinDivert 转发句柄读取失败: {error}")
                return

            if not self._inbound_address_logged:
                self._inbound_address_logged = True
                self._write_log(
                    "转发层首个包地址样本: "
                    f"{address[:24].hex()} "
                    f"ifidx0={struct.unpack_from('<I', address, 0)[0]} "
                    f"ifidx12={struct.unpack_from('<I', address, 12)[0]} "
                    f"ifidx16={struct.unpack_from('<I', address, 16)[0]} "
                    "flags=0x"
                    f"{struct.unpack_from('<I', address, 8)[0]:08x}"
                )

            try:
                rewritten = self._prepare_forward_packet(
                    bytearray(packet),
                )
                if rewritten is None:
                    self._send_meta(handle, packet, meta)
                else:
                    if not self._handled_address_logged:
                        self._handled_address_logged = True
                        parsed = parse_ipv4_tcp(bytes(packet))
                        self._write_log(
                            "客户端包地址样本: "
                            f"{address[:24].hex()} "
                            f"ifidx16={struct.unpack_from('<I', address, 16)[0]} "
                            "flags=0x"
                            f"{struct.unpack_from('<I', address, 8)[0]:08x} "
                            f"packet={parsed}"
                        )
                    self._inject_inbound(
                        self._return_handle,
                        bytes(rewritten),
                        meta,
                    )
            except (OSError, RuntimeError, ValueError) as error:
                self._write_log(f"处理热点转发数据包失败: {error}")

    def _return_loop(self) -> None:
        handle = self._return_handle
        while not self._stopping.is_set():
            try:
                packet, meta = handle.recv(COPY_BUFFER_SIZE)
            except (OSError, WindivertShutdown) as error:
                if not self._stopping.is_set():
                    self._write_log(f"WinDivert 返回句柄读取失败: {error}")
                return

            try:
                rewritten = self._prepare_return_packet(
                    bytearray(packet),
                )
                if rewritten is None:
                    self._send_meta(handle, packet, meta)
                else:
                    self._send_meta(handle, bytes(rewritten), meta)
            except (OSError, RuntimeError, ValueError) as error:
                self._write_log(f"处理透明桥返回数据包失败: {error}")

    def _ipv6_loop(self) -> None:
        handle = self._ipv6_handle
        while not self._stopping.is_set():
            try:
                _packet, _meta = handle.recv(COPY_BUFFER_SIZE)
            except (OSError, WindivertShutdown) as error:
                if not self._stopping.is_set():
                    self._write_log(f"WinDivert IPv6 句柄读取失败: {error}")
                return
            # 转发层的客户端包带的是上行网卡 IfIdx（实测 WLAN=13），
            # 不是热点网卡；此层只会出现被转发的流量，收到即丢弃，
            # 不重新注入，迫使客户端回退 IPv4。
            continue

    def _quic_loop(self) -> None:
        handle = self._quic_handle
        while not self._stopping.is_set():
            try:
                packet, meta = handle.recv(COPY_BUFFER_SIZE)
            except (OSError, WindivertShutdown) as error:
                if not self._stopping.is_set():
                    self._write_log(f"WinDivert QUIC 句柄读取失败: {error}")
                return

            try:
                parsed = parse_ipv4_udp(bytes(packet))
                if parsed is not None:
                    source_address = parsed[0]
                    destination_port = parsed[3]
                    if (
                        destination_port == 443
                        and self._address_in_client_network(source_address)
                    ):
                        # 热点客户端的 QUIC 在转发层丢弃，促使浏览器
                        # 回退到 TCP 443 进入透明代理。
                        continue
                self._send_meta(handle, packet, meta)
            except (OSError, RuntimeError, ValueError) as error:
                self._write_log(f"处理热点 QUIC 数据包失败: {error}")

    def _address_in_client_network(self, address: str) -> bool:
        """判断地址是否属于热点客户端网段。"""
        if self.client_network is None:
            return False
        try:
            return ipaddress.ip_address(address) in self.client_network
        except ValueError:
            return False

    def _is_client_address(self, address: str) -> bool:
        """判断源地址是否属于热点客户端（排除 NAT 后的网关自身）。"""
        if not self._address_in_client_network(address):
            return False
        return address != self.redirect_target_host

    def _log_port_once(
        self,
        logged_ports: set[int],
        port: int,
        message: str,
    ) -> None:
        """同一目的端口的异常只记录一次，避免热路径逐包刷日志。"""
        with self._lock:
            if port in logged_ports:
                return
            if len(logged_ports) >= WINDOWS_MAX_FLOWS:
                logged_ports.clear()
            logged_ports.add(port)
        self._write_log(f"{message}: {port}")

    def _report_ignored_flow(
        self,
        client_port: int,
        destination_address: str,
        destination_port: int,
    ) -> None:
        """上报被忽略的客户端流量副本（NAT 后源地址改为网关）。"""
        if self._event_observer is None:
            return
        self._event_observer(
            "forward-ignored",
            {
                "client": f":{client_port}",
                "destination": (
                    f"{destination_address}:{destination_port}"
                ),
                "reason": "nat-duplicate",
            },
        )

    def _prepare_forward_packet(
        self,
        packet: bytearray,
    ) -> bytearray | None:
        parsed = parse_ipv4_tcp(bytes(packet))
        if parsed is None:
            return None
        (
            source_address,
            source_port,
            destination_address,
            destination_port,
            ip_header_length,
            _tcp_header_length,
            tcp_flags,
        ) = parsed
        if destination_port not in {80, 443}:
            return None
        # 注入自检的探测包可能借用真实客户端 IP；这类包原样放行，
        # 不登记流表，否则统计和连接映射会被探测污染。
        if (
            self._probe_source is not None
            and source_address == self._probe_source
        ):
            return None
        if not self._address_in_client_network(source_address):
            return None
        if source_address == self.redirect_target_host:
            # NAT 后的副本仍是客户端发起的连接，原始副本已经改写；
            # 忽略并上报一次，供界面显示“忽略”计数。
            self._report_ignored_flow(
                source_port,
                destination_address,
                destination_port,
            )
            return None
        return self._forward_client_packet(
            packet,
            source_address,
            source_port,
            destination_address,
            destination_port,
            ip_header_length,
            tcp_flags,
        )

    def _forward_client_packet(
        self,
        packet: bytearray,
        source_address: str,
        source_port: int,
        destination_address: str,
        destination_port: int,
        ip_header_length: int,
        tcp_flags: int,
    ) -> bytearray | None:

        client_flow_key = (
            source_address,
            source_port,
            destination_address,
            destination_port,
        )
        new_flow: WindowsForwardFlow | None = None
        with self._lock:
            existing_flow = self._flows_by_client.get(client_flow_key)
            if existing_flow is not None:
                flow = existing_flow
                self._flows_by_synthetic.move_to_end(flow.synthetic_port)
            else:
                flow = WindowsForwardFlow(
                    client_address=source_address,
                    client_port=source_port,
                    destination_address=destination_address,
                    destination_port=destination_port,
                    interface_index=self.hotspot_if_index,
                    synthetic_port=self._allocate_synthetic_port(),
                )
                self._flows_by_client[client_flow_key] = flow
                self._flows_by_synthetic[flow.synthetic_port] = flow
                self._evict_stale_flows_locked()
                new_flow = flow
        if new_flow is not None and self._event_observer is not None:
            self._event_observer(
                "forward-flow",
                _flow_event_payload(new_flow),
            )

        rewrite_ipv4_tcp_addresses_and_ports(
            packet,
            ip_header_length,
            source_address=flow.client_address,
            source_port=flow.synthetic_port,
            destination_address=self._inject_target_host,
            destination_port=self.listen_port,
        )
        if tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST):
            # FIN/RST 段本身照常转发；映射在改写之后删除，
            # 合成端口立刻可以复用。
            with self._lock:
                self._forget_flow_locked(flow)
        return packet

    def _prepare_return_packet(
        self,
        packet: bytearray,
    ) -> bytearray | None:
        parsed = parse_ipv4_tcp(bytes(packet))
        if parsed is None:
            return None
        (
            _source_address,
            _source_port,
            destination_address,
            destination_port,
            ip_header_length,
            _tcp_header_length,
            tcp_flags,
        ) = parsed
        closed = bool(tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST))
        flow: WindowsForwardFlow | None = None
        report_return = False
        mismatched_client = False
        with self._lock:
            candidate_flow = self._flows_by_synthetic.get(destination_port)
            if candidate_flow is not None:
                if candidate_flow.client_address != destination_address:
                    # 合成端口与另一台客户端的真实临时端口重合时，
                    # 返回包会指向错误的主机；拒绝重写，杜绝跨连接串流。
                    mismatched_client = True
                else:
                    flow = candidate_flow
                    if not flow.return_reported:
                        flow.return_reported = True
                        report_return = True
                    if closed:
                        self._forget_flow_locked(flow)
        if flow is None:
            if (
                self._probe_port is not None
                and destination_port == self._probe_port
            ):
                self._probe_seen.set()
                return None
            if mismatched_client:
                self._log_port_once(
                    self._logged_no_flow_ports,
                    destination_port,
                    "透明桥返回连接与客户端地址不匹配，丢弃",
                )
            else:
                self._log_port_once(
                    self._logged_no_flow_ports,
                    destination_port,
                    "未找到透明桥返回连接映射",
                )
            return None
        if report_return and self._event_observer is not None:
            self._event_observer(
                "return-flow",
                _flow_event_payload(flow),
            )

        rewrite_ipv4_tcp_addresses_and_ports(
            packet,
            ip_header_length,
            source_address=flow.destination_address,
            source_port=flow.destination_port,
            destination_address=flow.client_address,
            destination_port=flow.client_port,
        )
        return packet

    def _evict_stale_flows_locked(self) -> None:
        while len(self._flows_by_synthetic) > WINDOWS_MAX_FLOWS:
            _, evicted_flow = self._flows_by_synthetic.popitem(last=False)
            client_flow_key = (
                evicted_flow.client_address,
                evicted_flow.client_port,
                evicted_flow.destination_address,
                evicted_flow.destination_port,
            )
            if self._flows_by_client.get(client_flow_key) is evicted_flow:
                self._flows_by_client.pop(client_flow_key, None)

    def _forget_flow_locked(self, flow: WindowsForwardFlow) -> None:
        """删除流映射；调用方必须已经持有 self._lock。"""
        if self._flows_by_synthetic.get(flow.synthetic_port) is flow:
            self._flows_by_synthetic.pop(flow.synthetic_port, None)
        client_flow_key = (
            flow.client_address,
            flow.client_port,
            flow.destination_address,
            flow.destination_port,
        )
        if self._flows_by_client.get(client_flow_key) is flow:
            self._flows_by_client.pop(client_flow_key, None)

    def _allocate_synthetic_port(self) -> int:
        port_count = (
            WINDOWS_SYNTHETIC_PORT_END
            - WINDOWS_SYNTHETIC_PORT_START
            + 1
        )
        for _ in range(port_count):
            candidate = self._next_synthetic_port
            self._next_synthetic_port += 1
            if self._next_synthetic_port > WINDOWS_SYNTHETIC_PORT_END:
                self._next_synthetic_port = WINDOWS_SYNTHETIC_PORT_START
            if candidate == self.listen_port:
                continue
            if candidate in self._flows_by_synthetic:
                continue
            return candidate
        raise RuntimeError("Windows 透明重定向没有可用的本地端口")

    @staticmethod
    def default_local_address() -> str:
        """探测本机出口地址，作为交付地址的最后兜底。"""
        probe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe_socket.connect(("1.1.1.1", 80))
            return str(probe_socket.getsockname()[0])
        except OSError as error:
            raise RuntimeError(
                "无法确定 Windows 透明重定向使用的本地地址"
            ) from error
        finally:
            probe_socket.close()

    def _run_injection_self_test(self) -> None:
        """后台探测 WinDivert 入站注入是否可达本机监听端口。

        启动后延迟 1 秒（等 webview 建好防火墙规则），依次尝试地址
        布局、Impostor/Loopback 标志、上行网卡目标、独立 NETWORK
        句柄。命中后立即采用对应配置；整个过程不阻塞桥接启动。
        """
        if self.client_network is None or not self.redirect_target_host:
            return
        if self._redirect_target_address is None:
            return
        if self.client_network.num_addresses < 8:
            return
        threading.Thread(
            target=self._injection_self_test_worker,
            name="emudhra-injection-selftest",
            daemon=True,
        ).start()

    def _injection_self_test_worker(self) -> None:
        # 等 webview 建好 28083 的入站防火墙规则后再探测。
        time.sleep(3.0)
        self._log_inbound_address_sample()
        self._log_outbound_address_sample()
        self._run_udp_injection_probe()
        probe_client = self._find_probe_client()
        probes: list[dict[str, Any]] = []
        for index, (label, offset) in enumerate(
            (
                ("ifIdx@16(生产布局)", 16),
                ("ifIdx@12", 12),
                ("ifIdx@20", 20),
                ("ifIdx=0", 0),
            )
        ):
            probes.append(
                {
                    "label": label,
                    "mode": "layout",
                    "source": probe_client,
                    "port": INJECTION_PROBE_PORT + index,
                    "destination": self.redirect_target_host,
                    "if_index": self.hotspot_if_index,
                    "offset": offset,
                    "flags": 0,
                }
            )
        for index, (label, flags) in enumerate(
            (
                ("impostor", 1 << 19),
                ("loopback", 1 << 18),
                ("impostor+loopback", (1 << 19) | (1 << 18)),
                ("flags=0x1", 1),
                ("flags=0x100", 1 << 8),
            )
        ):
            probes.append(
                {
                    "label": f"hotspot+{label}",
                    "mode": "raw",
                    "source": probe_client,
                    "port": INJECTION_PROBE_PORT + 20 + index,
                    "destination": self.redirect_target_host,
                    "if_index": self.hotspot_if_index,
                    "offset": 16,
                    "flags": flags,
                }
            )
        try:
            uplink_ip = self.default_local_address()
        except RuntimeError:
            uplink_ip = ""
        if uplink_ip:
            uplink_client = uplink_ip.rsplit(".", 1)[0] + ".222"
            probes.extend(
                (
                    {
                        "label": "上行网卡目标+热点源",
                        "mode": "raw",
                        "source": probe_client,
                        "port": INJECTION_PROBE_PORT + 30,
                        "destination": uplink_ip,
                        "if_index": 0,
                        "offset": 16,
                        "flags": 0,
                    },
                    {
                        "label": "上行网卡目标+上行源",
                        "mode": "raw",
                        "source": uplink_client,
                        "port": INJECTION_PROBE_PORT + 31,
                        "destination": uplink_ip,
                        "if_index": 0,
                        "offset": 16,
                        "flags": 0,
                    },
                    {
                        "label": "上行网卡目标+热点源+impostor",
                        "mode": "raw",
                        "source": probe_client,
                        "port": INJECTION_PROBE_PORT + 32,
                        "destination": uplink_ip,
                        "if_index": 0,
                        "offset": 16,
                        "flags": 1 << 19,
                    },
                )
            )
        probes.append(
            {
                "label": "独立NETWORK句柄",
                "mode": "fresh",
                "source": probe_client,
                "port": INJECTION_PROBE_PORT + 40,
                "destination": self.redirect_target_host,
                "if_index": self.hotspot_if_index,
                "offset": 16,
                "flags": 0,
            }
        )

        for probe in probes:
            if self._stopping.is_set():
                return
            self._execute_probe(probe)
            if probe.get("succeeded"):
                self._adopt_probe(probe)
                self._probe_port = None
                self._probe_source = None
                return
        self._probe_port = None
        self._probe_source = None
        self._if_index_offset = 16
        self._inject_flags = 0
        self._write_log(
            "注入自检失败: 所有布局/标志/目标均未到达本机监听端口"
        )

    def _log_inbound_address_sample(self) -> None:
        """触发一个本机入站连接，记录 NETWORK 层入站包的地址布局。"""
        try:
            from emudhra_mitm.windivert_binding import WindivertHandle

            handle = WindivertHandle(
                "inbound and ip and tcp and tcp.SrcPort == 443"
            )
            handle.open()
        except Exception as error:  # noqa: BLE001
            self._write_log(f"入站地址样本打开失败: {error!r}")
            return

        def connect() -> None:
            try:
                connection = socket.create_connection(
                    ("1.1.1.1", 443),
                    timeout=2,
                )
            except OSError:
                return
            connection.close()

        watchdog = threading.Timer(3.0, handle.close)
        watchdog.daemon = True
        watchdog.start()
        threading.Thread(target=connect, daemon=True).start()
        try:
            packet, address, _meta = handle.recv_raw(COPY_BUFFER_SIZE)
            parsed = parse_ipv4_tcp(bytes(packet))
            self._write_log(
                "入站地址样本(NETWORK): "
                f"{address[:24].hex()} "
                f"ifidx16={struct.unpack_from('<I', address, 16)[0]} "
                "flags=0x"
                f"{struct.unpack_from('<I', address, 8)[0]:08x} "
                f"packet={parsed}"
            )
        except Exception as error:  # noqa: BLE001
            self._write_log(f"入站地址样本失败: {error!r}")
        finally:
            watchdog.cancel()
            with contextlib.suppress(Exception):
                handle.close()

    def _log_outbound_address_sample(self) -> None:
        """触发一个本机出站 SYN，记录 WINDIVERT_ADDRESS 真实布局。

        与热点入站包样本对比即可确认方向位和 IfIdx 的偏移。
        """
        try:
            from emudhra_mitm.windivert_binding import WindivertHandle

            handle = WindivertHandle(
                "outbound and ip and tcp and tcp.DstPort == 1"
            )
            handle.open()
        except Exception as error:  # noqa: BLE001
            self._write_log(f"出站地址样本打开失败: {error!r}")
            return

        def connect() -> None:
            try:
                connection = socket.create_connection(
                    ("1.1.1.1", 1),
                    timeout=2,
                )
            except OSError:
                return
            connection.close()

        watchdog = threading.Timer(3.0, handle.close)
        watchdog.daemon = True
        watchdog.start()
        threading.Thread(target=connect, daemon=True).start()
        try:
            _packet, address, _meta = handle.recv_raw(COPY_BUFFER_SIZE)
            self._write_log(
                "出站地址样本: "
                f"{address[:24].hex()} "
                f"ifidx0={struct.unpack_from('<I', address, 0)[0]} "
                f"ifidx12={struct.unpack_from('<I', address, 12)[0]} "
                f"ifidx16={struct.unpack_from('<I', address, 16)[0]} "
                "flags=0x"
                f"{struct.unpack_from('<I', address, 8)[0]:08x}"
            )
        except Exception as error:  # noqa: BLE001
            self._write_log(f"出站地址样本失败: {error!r}")
        finally:
            watchdog.cancel()
            with contextlib.suppress(Exception):
                handle.close()

    def _run_udp_injection_probe(self) -> None:
        """用 UDP 验证注入能否到达本机套接字，区分 TCP 专属问题。"""
        probe_client = str(self.client_network.network_address + 223)
        for index, if_index in enumerate((self.hotspot_if_index, 0)):
            port = 29001 + index
            try:
                probe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                probe_socket.bind((self.redirect_target_host, port))
                probe_socket.settimeout(1.0)
            except OSError as error:
                self._write_log(
                    f"UDP 注入自检(ifidx={if_index})绑定失败: {error!r}"
                )
                continue
            packet = build_udp_probe(
                probe_client,
                45001 + index,
                self.redirect_target_host,
                port,
                b"emudhra-udp-probe",
            )
            address = bytearray(WINDIVERT_ADDRESS_SIZE)
            struct.pack_into("<I", address, 8, 0)
            struct.pack_into("<I", address, 16, if_index)
            try:
                self._return_handle.send_with_address(
                    packet,
                    bytes(address),
                )
                data, peer = probe_socket.recvfrom(1024)
                self._write_log(
                    f"UDP 注入自检(ifidx={if_index}, port={port}): "
                    f"收到 {len(data)} 字节 from {peer}"
                )
            except (OSError, socket.timeout) as error:
                self._write_log(
                    f"UDP 注入自检(ifidx={if_index}, port={port}): "
                    f"未收到 ({error!r})"
                )
            finally:
                probe_socket.close()

    def _find_probe_client(self) -> str:
        """优先用 ARP 表里真实存在的客户端 IP 作探测源。

        假地址无法完成 ARP，协议栈不会真正发出 SYN-ACK，自检会误报
        失败；真实客户端地址能同时验证注入和返回两个方向。
        """
        fallback = str(self.client_network.network_address + 222)
        try:
            completed = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=5,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                ),
            )
        except (OSError, subprocess.TimeoutExpired):
            return fallback
        gateway = self.redirect_target_host
        for line in completed.stdout.splitlines():
            fields = line.split()
            if len(fields) < 2:
                continue
            address_text = fields[0]
            mac_text = fields[1].lower()
            if mac_text in {
                "00-00-00-00-00-00",
                "ff-ff-ff-ff-ff-ff",
            }:
                continue
            if address_text == gateway or address_text.endswith(".255"):
                continue
            try:
                address = ipaddress.ip_address(address_text)
            except ValueError:
                continue
            if address in self.client_network:
                return address_text
        return fallback

    def _execute_probe(self, probe: dict[str, Any]) -> None:
        label = probe["label"]
        port = probe["port"]
        self._probe_port = port
        self._probe_source = probe["source"]
        self._probe_seen.clear()
        packet = build_probe_syn(
            probe["source"],
            port,
            probe["destination"],
            self.listen_port,
        )
        try:
            if probe["mode"] == "layout":
                self._if_index_offset = probe["offset"]
                meta = diverted_packet_meta(
                    if_index=probe["if_index"],
                    outbound=False,
                    ipv6=False,
                )
                self._inject_inbound(self._return_handle, packet, meta)
            elif probe["mode"] == "fresh":
                from emudhra_mitm.windivert_binding import (
                    WINDIVERT_LAYER_NETWORK,
                    WindivertHandle,
                )

                handle = WindivertHandle("false", WINDIVERT_LAYER_NETWORK)
                handle.open()
                self._probe_handle = handle
                handle.send_with_address(packet, self._probe_address(probe))
            else:
                self._return_handle.send_with_address(
                    packet,
                    self._probe_address(probe),
                )
        except Exception as error:  # noqa: BLE001
            self._write_log(
                f"注入自检 {label}: WinDivertSend 异常 {error!r}"
            )
            return
        syn_ack_seen = self._probe_seen.wait(
            INJECTION_PROBE_TIMEOUT_SECONDS
        )
        tcp_state = self._probe_tcp_state(port)
        probe["succeeded"] = bool(syn_ack_seen or tcp_state)
        self._write_log(
            f"注入自检 {label}: {probe['source']}:{port} -> "
            f"{probe['destination']}:{self.listen_port}, "
            f"SYN-ACK={'收到' if syn_ack_seen else '未收到'}, "
            f"TCP 状态={tcp_state or '未找到'}"
        )
        if (
            probe["mode"] == "fresh"
            and not syn_ack_seen
            and self._probe_handle is not None
        ):
            with contextlib.suppress(Exception):
                self._probe_handle.close()
            self._probe_handle = None

    @staticmethod
    def _probe_address(probe: dict[str, Any]) -> bytes:
        address = bytearray(WINDIVERT_ADDRESS_SIZE)
        struct.pack_into("<I", address, 8, probe["flags"])
        if probe["offset"]:
            struct.pack_into(
                "<I",
                address,
                probe["offset"],
                probe["if_index"],
            )
        return bytes(address)

    def _adopt_probe(self, probe: dict[str, Any]) -> None:
        self._write_log(f"注入自检通过: 采用 {probe['label']}")
        self._if_index_offset = probe["offset"]
        if probe["mode"] == "layout":
            return
        self._inject_flags = probe["flags"]
        if probe["destination"] != self.redirect_target_host:
            self._inject_target_host = probe["destination"]
            self._inject_if_index = probe["if_index"]
            self._write_log(
                "注入自检: 注入目标切换到 "
                f"{probe['destination']}:{self.listen_port}, "
                f"ifIndex={probe['if_index']}"
            )
        if probe["mode"] == "fresh" and self._probe_handle is not None:
            self._inject_handle = self._probe_handle
            self._write_log("注入自检: 使用独立 NETWORK 注入句柄")

    @staticmethod
    def _probe_tcp_state(probe_port: int) -> str:
        try:
            completed = subprocess.run(
                ["netstat", "-ano", "-p", "tcp"],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=5,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                ),
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        for line in completed.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            if fields[0] != "TCP":
                continue
            if (
                fields[1].endswith(f":{probe_port}")
                or fields[2].endswith(f":{probe_port}")
            ):
                return fields[3]
        return ""

    @staticmethod
    def _write_log(message: str) -> None:
        print(f"[windows-redirect] {message}", file=sys.stderr, flush=True)
        append_bridge_log(message)


class DnsForwarder:
    """把热点客户端的 DNS 查询转发给上游 DNS 服务器。

    监听端口是 15353：WinDivert 已把客户端发往 53 端口的查询平移
    过来（实测直接绑定 53 会让 ipnathlp 崩溃），响应由 DNS 返回
    句柄把源端口改写回 53。每个查询用一个独立上游套接字，5 秒
    超时后换下一个上游。
    """

    def __init__(
        self,
        bind_ip: str,
        upstream_servers: list[str],
        listen_port: int = WINDOWS_DNS_LISTEN_PORT,
    ) -> None:
        self.bind_ip = bind_ip
        self.listen_port = listen_port
        self.upstream_servers = [
            server for server in upstream_servers if server
        ]
        self._transport: asyncio.DatagramTransport | None = None
        self._pending_tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        if not self.bind_ip or not self.upstream_servers:
            return
        loop = asyncio.get_running_loop()
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _DnsClientProtocol(self),
            local_addr=(self.bind_ip, self.listen_port),
        )
        self._transport = transport
        asyncio.create_task(self._diagnose_upstream())

    async def _diagnose_upstream(self) -> None:
        """启动时直接查询一次上游，记录桥接进程内的真实结果。"""
        loop = asyncio.get_running_loop()
        query = (
            struct.pack("!HHHHHH", 0x5A5A, 0x0100, 1, 0, 0, 0)
            + b"\x07example\x03com\x00"
            + struct.pack("!HH", 1, 1)
        )
        for upstream_server in self.upstream_servers:
            upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream_socket.setblocking(False)
            local_address = None
            try:
                self._bind_upstream_source(
                    upstream_socket,
                    upstream_server,
                )
                await loop.sock_sendto(
                    upstream_socket,
                    query,
                    (upstream_server, DNS_PORT),
                )
                local_address = upstream_socket.getsockname()
                response, peer = await asyncio.wait_for(
                    loop.sock_recvfrom(upstream_socket, 65535),
                    timeout=DNS_RESPONSE_TIMEOUT_SECONDS,
                )
                self._write_log(
                    f"DNS 自检 {upstream_server}: 成功 "
                    f"{len(response)} 字节 本地={local_address} "
                    f"响应={peer}"
                )
            except (OSError, asyncio.TimeoutError) as error:
                self._write_log(
                    f"DNS 自检 {upstream_server}: 失败 {error!r} "
                    f"本地={local_address}"
                )
            finally:
                upstream_socket.close()

    async def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        pending_tasks = list(self._pending_tasks)
        for pending_task in pending_tasks:
            pending_task.cancel()
        if pending_tasks:
            await asyncio.gather(*pending_tasks, return_exceptions=True)
        self._pending_tasks.clear()

    def handle_query(
        self,
        query: bytes,
        client_address: tuple[str, int],
    ) -> None:
        pending_task = asyncio.create_task(
            self._resolve_query(query, client_address)
        )
        self._pending_tasks.add(pending_task)
        pending_task.add_done_callback(self._pending_tasks.discard)

    async def _resolve_query(
        self,
        query: bytes,
        client_address: tuple[str, int],
    ) -> None:
        loop = asyncio.get_running_loop()
        for upstream_server in self.upstream_servers:
            upstream_socket: socket.socket | None = None
            try:
                upstream_socket = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_DGRAM,
                )
                upstream_socket.setblocking(False)
                local_address = None
                self._bind_upstream_source(
                    upstream_socket,
                    upstream_server,
                )
                await loop.sock_sendto(
                    upstream_socket,
                    query,
                    (upstream_server, DNS_PORT),
                )
                local_address = upstream_socket.getsockname()
                response, _remote = await asyncio.wait_for(
                    loop.sock_recvfrom(upstream_socket, 65535),
                    timeout=DNS_RESPONSE_TIMEOUT_SECONDS,
                )
                if self._transport is not None:
                    self._transport.sendto(response, client_address)
                return
            except (OSError, asyncio.TimeoutError) as error:
                self._write_log(
                    f"DNS 上游 {upstream_server} 失败: {error!r} "
                    f"本地={local_address}"
                )
            finally:
                if upstream_socket is not None:
                    upstream_socket.close()
        self._write_log("所有 DNS 上游均未响应")

    @staticmethod
    def _bind_upstream_source(
        upstream_socket: socket.socket,
        upstream_server: str,
    ) -> None:
        """把上游查询显式绑定到通往该服务器的源地址。

        桥接进程同时持有热点网关监听套接字，未绑定 socket 的源地址
        选择可能落到 192.168.137.1，路由器会把它当成异常来源丢弃。
        """
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect((upstream_server, DNS_PORT))
            source_address = probe.getsockname()[0]
        except OSError:
            return
        finally:
            probe.close()
        if not source_address:
            return
        try:
            upstream_socket.bind((source_address, 0))
        except OSError:
            pass

    @staticmethod
    def _write_log(message: str) -> None:
        print(f"[dns-forwarder] {message}", file=sys.stderr, flush=True)
        append_bridge_log(f"[dns-forwarder] {message}")


class _DnsClientProtocol(asyncio.DatagramProtocol):
    """承接 53 端口的客户端查询，正文处理交给 DnsForwarder。"""

    def __init__(self, forwarder: DnsForwarder) -> None:
        self.forwarder = forwarder

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        pass

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        self.forwarder.handle_query(data, addr)


class TransparentRelay:
    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        proxy_host: str,
        proxy_port: int,
        destination_resolver: DestinationResolver,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.destination_resolver = destination_resolver
        self._servers: list[asyncio.AbstractServer] = []
        self._client_tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        ipv4_server = await asyncio.start_server(
            self._handle_client,
            host=(
                "0.0.0.0"
                if self.listen_host in {"", "0.0.0.0", "::"}
                else self.listen_host
            ),
            port=self.listen_port,
        )
        self._servers.append(ipv4_server)
        listening_socket = ipv4_server.sockets[0]
        self.listen_port = int(listening_socket.getsockname()[1])
        if self.listen_host in {"", "0.0.0.0", "::"}:
            ipv6_server = await self._start_ipv6_server(self.listen_port)
            if ipv6_server is not None:
                self._servers.append(ipv6_server)

    async def close(self) -> None:
        for server in self._servers:
            server.close()
            await server.wait_closed()
        self._servers.clear()

        client_tasks = list(self._client_tasks)
        for client_task in client_tasks:
            client_task.cancel()
        if client_tasks:
            await asyncio.gather(*client_tasks, return_exceptions=True)
        self._client_tasks.clear()

    async def _start_ipv6_server(
        self,
        listen_port: int,
    ) -> asyncio.AbstractServer | None:
        if not socket.has_ipv6:
            return None
        ipv6_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        try:
            ipv6_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            ipv6_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ipv6_socket.bind(("::", listen_port))
            ipv6_socket.listen()
            ipv6_socket.setblocking(False)
            return await asyncio.start_server(
                self._handle_client,
                sock=ipv6_socket,
            )
        except OSError:
            ipv6_socket.close()
            return None

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        current_task = asyncio.current_task()
        if current_task is not None:
            self._client_tasks.add(current_task)

        proxy_writer: asyncio.StreamWriter | None = None
        destination: Destination | None = None
        try:
            peer = client_writer.get_extra_info("peername") or ()
            raw_socket = client_writer.get_extra_info("socket")
            if raw_socket is None:
                return
            destination = self.destination_resolver(raw_socket, tuple(peer))
            if destination is None:
                print(
                    "[transparent] 无法解析透明连接的目标地址: "
                    f"{peer}",
                    file=sys.stderr,
                    flush=True,
                )
                return
            if destination[1] == self.listen_port:
                return

            proxy_reader, proxy_writer = await self._connect_proxy_tunnel(
                destination
            )
            await self._relay(
                client_reader,
                client_writer,
                proxy_reader,
                proxy_writer,
            )
        except (
            asyncio.IncompleteReadError,
            ConnectionError,
            OSError,
            ValueError,
        ) as error:
            if destination is not None:
                print(
                    "[transparent] "
                    f"{format_authority(destination)}: {error}",
                    file=sys.stderr,
                    flush=True,
                )
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

    async def _connect_proxy_tunnel(
        self,
        destination: Destination,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        proxy_reader, proxy_writer = await asyncio.wait_for(
            asyncio.open_connection(self.proxy_host, self.proxy_port),
            timeout=CONNECT_TIMEOUT_SECONDS,
        )
        authority = format_authority(destination)
        connect_request = (
            f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "\r\n"
        ).encode("ascii")

        try:
            proxy_writer.write(connect_request)
            await proxy_writer.drain()
            response_header = await asyncio.wait_for(
                proxy_reader.readuntil(b"\r\n\r\n"),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
            status_parts = response_header.split(b"\r\n", 1)[0].split(b" ", 2)
            if len(status_parts) < 2 or status_parts[1] != b"200":
                raise ConnectionError("HTTP upstream 代理拒绝 CONNECT 请求")
        except Exception:
            proxy_writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await proxy_writer.wait_closed()
            raise

        return proxy_reader, proxy_writer

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        proxy_reader: asyncio.StreamReader,
        proxy_writer: asyncio.StreamWriter,
    ) -> None:
        client_to_proxy = asyncio.create_task(
            self._copy_stream(client_reader, proxy_writer)
        )
        proxy_to_client = asyncio.create_task(
            self._copy_stream(proxy_reader, client_writer)
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

    @staticmethod
    async def _copy_stream(
        source: asyncio.StreamReader,
        destination: asyncio.StreamWriter,
    ) -> None:
        while data := await source.read(COPY_BUFFER_SIZE):
            destination.write(data)
            await destination.drain()


def emit_event(event_name: str, **payload: Any) -> None:
    event = {
        "event": event_name,
        "timestamp": datetime.datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
        **payload,
    }
    line = json.dumps(event, ensure_ascii=False)
    with EVENT_LOCK:
        print(line, flush=True)
        if event_name in {
            "forward-flow",
            "forward-ignored",
            "return-flow",
        }:
            with contextlib.suppress(OSError):
                append_event_log(line)


def append_event_log(line: str) -> None:
    TRANSPARENT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if (
        TRANSPARENT_LOG_PATH.is_file()
        and TRANSPARENT_LOG_PATH.stat().st_size
        >= TRANSPARENT_LOG_MAX_BYTES
    ):
        rotated_path = Path(f"{TRANSPARENT_LOG_PATH}.1")
        with contextlib.suppress(OSError):
            rotated_path.unlink()
        with contextlib.suppress(OSError):
            TRANSPARENT_LOG_PATH.replace(rotated_path)
    with TRANSPARENT_LOG_PATH.open(
        "a",
        encoding="utf-8",
    ) as log_file:
        log_file.write(line + "\n")


async def wait_for_control_stop(stop_event: asyncio.Event) -> None:
    event_loop = asyncio.get_running_loop()

    def read_stdin() -> None:
        for raw_line in sys.stdin:
            if raw_line.strip().lower() == "stop":
                break
        event_loop.call_soon_threadsafe(stop_event.set)

    threading.Thread(
        target=read_stdin,
        name="emudhra-transparent-control",
        daemon=True,
    ).start()
    await stop_event.wait()


def install_shutdown_handlers(stop_event: asyncio.Event) -> None:
    event_loop = asyncio.get_running_loop()

    def request_shutdown(*_: Any) -> None:
        event_loop.call_soon_threadsafe(stop_event.set)

    for signal_number in (signal.SIGINT, signal.SIGTERM):
        try:
            event_loop.add_signal_handler(signal_number, request_shutdown)
        except NotImplementedError:
            signal.signal(signal_number, request_shutdown)


def _emit_flow_event(
    event_name: str,
    event_payload: dict[str, Any],
) -> None:
    """把 WinDivert 线程里发现的流事件上报给控制器和透明日志。"""
    emit_event(event_name, **event_payload)


def _flow_event_payload(flow: WindowsForwardFlow) -> dict[str, Any]:
    return {
        "client": f"{flow.client_address}:{flow.client_port}",
        "destination": (
            f"{flow.destination_address}:{flow.destination_port}"
        ),
        "synthetic_port": flow.synthetic_port,
        "interface": [flow.interface_index, 0],
    }


async def run_bridge(arguments: argparse.Namespace) -> None:
    redirector: WindowsClientRedirector | None = None
    dns_forwarder: DnsForwarder | None = None
    if os.name == "nt":
        # 交付地址必须是热点网关自己的 IP（如 192.168.137.1）：改写后的
        # 包仍从热点网卡入站，只有该接口上属于本机的地址才会被强主机
        # 接收模型放行；用上行网卡 IP 会被静默丢弃。
        redirect_target_host = (
            arguments.redirect_target_host
            or arguments.redirect_host
            or WindowsClientRedirector.default_local_address()
        )
        try:
            redirector = WindowsClientRedirector(
                listen_port=arguments.listen_port,
                redirect_target_host=redirect_target_host,
                client_network=arguments.client_network,
                hotspot_if_index=arguments.hotspot_if_index,
                dns_redirect_port=arguments.dns_listen_port,
                event_observer=_emit_flow_event,
            )
        except Exception as error:
            raise RuntimeError(
                "无法初始化 Windows WinDivert 透明重定向组件: "
                f"{error!r}"
            ) from error
        destination_resolver: DestinationResolver = redirector.resolve
        if arguments.dns_listen_ip and arguments.dns_upstream:
            dns_forwarder = DnsForwarder(
                bind_ip=arguments.dns_listen_ip,
                upstream_servers=[
                    server.strip()
                    for server in arguments.dns_upstream.split(",")
                    if server.strip()
                ],
                listen_port=arguments.dns_listen_port,
            )
    else:
        destination_resolver = linux_original_destination

    relay = TransparentRelay(
        listen_host=arguments.listen_host,
        listen_port=arguments.listen_port,
        proxy_host=arguments.proxy_host,
        proxy_port=arguments.proxy_port,
        destination_resolver=destination_resolver,
    )
    stop_event = asyncio.Event()
    install_shutdown_handlers(stop_event)
    try:
        await relay.start()
        if redirector is not None:
            try:
                redirector.start()
            except Exception as error:
                raise RuntimeError(
                    "无法启用 Windows WinDivert 透明重定向: "
                    f"{error}（需要管理员权限）"
                ) from error
        if dns_forwarder is not None:
            try:
                await dns_forwarder.start()
            except OSError as error:
                print(
                    f"[dns-forwarder] DNS 转发器绑定失败: {error}",
                    file=sys.stderr,
                    flush=True,
                )
        emit_event(
            "ready",
            listen_endpoint=f"{arguments.listen_host}:{relay.listen_port}",
            proxy_endpoint=(
                f"{arguments.proxy_host}:{arguments.proxy_port}"
            ),
        )
        await wait_for_control_stop(stop_event)
    finally:
        if redirector is not None:
            with contextlib.suppress(Exception):
                redirector.stop()
        if dns_forwarder is not None:
            with contextlib.suppress(Exception):
                await dns_forwarder.close()
        await relay.close()
        emit_event("stopped")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="把透明重定向的 TCP 连接转交给 HTTP upstream 代理。"
    )
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=28083)
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=28081)
    parser.add_argument("--redirect-host", default="")
    parser.add_argument("--redirect-target-host", default="")
    parser.add_argument("--client-network", default="")
    parser.add_argument(
        "--hotspot-ifindex",
        dest="hotspot_if_index",
        type=int,
        default=0,
    )
    parser.add_argument("--dns-listen-ip", default="")
    parser.add_argument(
        "--dns-listen-port",
        dest="dns_listen_port",
        type=int,
        default=WINDOWS_DNS_LISTEN_PORT,
    )
    parser.add_argument("--dns-upstream", default="")
    return parser.parse_args()


def main() -> int:
    try:
        asyncio.run(run_bridge(parse_arguments()))
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, ValueError) as error:
        print(f"[!] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
