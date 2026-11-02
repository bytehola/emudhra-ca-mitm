"""WinDivert 2.2 的最小 ctypes 绑定。

驱动文件由 mitmproxy 的 Windows 依赖（mitmproxy_windows 包）自带，
不再单独 vendor。这里只封装热点拦截用到的四个函数：open、close、
recv、send，以及 IPv4/TCP 头部的字段改写与校验和计算。
"""

from __future__ import annotations

import ctypes
import struct
from pathlib import Path


WINDIVERT_LAYER_NETWORK = 0
# 热点客户端的流量由 ICS 转发而不是本机收发，只会出现在 forward 层；
# 本机代理进程自己发出的响应仍然用 NETWORK 层。
WINDIVERT_LAYER_NETWORK_FORWARD = 1
WINDIVERT_ADDRESS_SIZE = 128

# WINDIVERT_ADDRESS 布局（WinDivert 2.2）：
#   offset 0  INT64  Timestamp
#   offset 8  UINT32 位域：Layer(0-7) Event(8-15) Sniffed(16) Outbound(17)
#                     Loopback(18) Impostor(19) IPv6(20) 校验和标记(21-23)
#   offset 16 NETWORK 层数据：IfIdx(16) SubIfIdx(20)
ADDRESS_TIMESTAMP_OFFSET = 0
ADDRESS_FLAGS_OFFSET = 8
ADDRESS_IF_INDEX_OFFSET = 16
ADDRESS_OUTBOUND_BIT = 1 << 17
ADDRESS_IPV6_BIT = 1 << 20

# TCP 头部 flags 字段常用位，透明桥据此回收已结束的连接映射。
TCP_FLAG_FIN = 0x01
TCP_FLAG_RST = 0x04
TCP_FLAG_SYN = 0x02


class WindivertError(RuntimeError):
    """WinDivert 打开或收发失败。"""


class WindivertShutdown(WindivertError):
    """句柄被 close() 中断的收发失败，属正常停机路径。"""


ERROR_OPERATION_ABORTED = 995


def locate_windivert_dll() -> Path:
    """定位 mitmproxy_windows 包自带的 WinDivert.dll。"""
    try:
        import mitmproxy_windows
    except ImportError as error:
        raise WindivertError(
            "未找到 mitmproxy_windows 包，无法加载 WinDivert"
        ) from error
    dll_path = Path(mitmproxy_windows.__file__).parent / "WinDivert.dll"
    if not dll_path.is_file():
        raise WindivertError(f"WinDivert.dll 不存在: {dll_path}")
    return dll_path


class WindivertHandle:
    """单个 WinDivert 句柄：打开时绑定过滤器，recv/send 收发原始包。"""

    # WinDivertOpen 失败时返回 INVALID_HANDLE_VALUE（-1）。
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def __init__(
        self,
        filter_expression: str,
        layer: int = WINDIVERT_LAYER_NETWORK,
    ) -> None:
        self._filter_expression = filter_expression.encode("ascii")
        self._layer = layer
        self._dll = ctypes.WinDLL(str(locate_windivert_dll()))
        self._dll.WinDivertOpen.restype = ctypes.c_void_p
        self._dll.WinDivertOpen.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int16,
            ctypes.c_uint64,
        ]
        self._dll.WinDivertClose.restype = ctypes.c_bool
        self._dll.WinDivertClose.argtypes = [ctypes.c_void_p]
        self._dll.WinDivertRecv.restype = ctypes.c_bool
        self._dll.WinDivertRecv.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.c_void_p,
        ]
        self._dll.WinDivertSend.restype = ctypes.c_bool
        # 官方签名: (handle, packet, packetLen, pSendLen, pAddr)
        self._dll.WinDivertSend.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.c_void_p,
        ]
        self._handle: int | None = None
    def open(self) -> None:
        if self._handle is not None:
            raise WindivertError("WinDivert 句柄已打开")
        ctypes.windll.kernel32.SetLastError(0)
        handle = self._dll.WinDivertOpen(
            self._filter_expression,
            self._layer,
            0,
            ctypes.c_uint64(0),
        )
        if (
            not handle
            or handle == self.INVALID_HANDLE_VALUE
        ):
            error_code = ctypes.windll.kernel32.GetLastError()
            raise WindivertError(
                f"WinDivertOpen 失败（filter={self._filter_expression!r}, "
                f"错误码 {error_code}；需要管理员权限）"
            )
        self._handle = int(handle)

    def close(self) -> None:
        if self._handle is not None:
            self._dll.WinDivertClose(self._handle)
            self._handle = None

    def recv(self, buffer_size: int) -> tuple[bytes, "diverted_packet_meta"]:
        packet, _address, meta = self.recv_raw(buffer_size)
        return packet, meta

    def recv_raw(
        self,
        buffer_size: int,
    ) -> tuple[bytes, bytes, "diverted_packet_meta"]:
        """接收一个包，同时返回原始 WINDIVERT_ADDRESS，供诊断布局。"""
        if self._handle is None:
            raise WindivertError("WinDivert 句柄未打开")
        packet_buffer = ctypes.create_string_buffer(buffer_size)
        address_buffer = ctypes.create_string_buffer(WINDIVERT_ADDRESS_SIZE)
        received_length = ctypes.c_uint(0)
        ctypes.windll.kernel32.SetLastError(0)
        success = self._dll.WinDivertRecv(
            self._handle,
            packet_buffer,
            ctypes.c_uint(buffer_size),
            ctypes.byref(received_length),
            address_buffer,
        )
        if not success:
            error_code = ctypes.windll.kernel32.GetLastError()
            if error_code == ERROR_OPERATION_ABORTED:
                raise WindivertShutdown(
                    f"WinDivertRecv 被中断（错误码 {error_code}）"
                )
            raise WindivertError(
                f"WinDivertRecv 失败（错误码 {error_code}）"
            )
        meta = diverted_packet_meta.from_address_buffer(address_buffer.raw)
        return (
            packet_buffer.raw[: received_length.value],
            address_buffer.raw,
            meta,
        )

    def send(self, packet: bytes, meta: "diverted_packet_meta") -> None:
        self.send_with_address(packet, meta.to_address_buffer())

    def send_with_address(self, packet: bytes, address: bytes) -> None:
        """用原始 WINDIVERT_ADDRESS 缓冲区注入，供诊断不同布局用。"""
        if self._handle is None:
            raise WindivertError("WinDivert 句柄未打开")
        address_buffer = ctypes.create_string_buffer(
            address,
            WINDIVERT_ADDRESS_SIZE,
        )
        sent_length = ctypes.c_uint(0)
        ctypes.windll.kernel32.SetLastError(0)
        success = self._dll.WinDivertSend(
            self._handle,
            packet,
            ctypes.c_uint(len(packet)),
            ctypes.byref(sent_length),
            address_buffer,
        )
        if not success:
            raise WindivertError(
                f"WinDivertSend 失败（错误码 {ctypes.windll.kernel32.GetLastError()}）"
            )


class diverted_packet_meta:
    """WINDIVERT_ADDRESS 中热点拦截关心的字段。"""

    __slots__ = ("if_index", "outbound", "ipv6")

    def __init__(self, if_index: int, outbound: bool, ipv6: bool) -> None:
        self.if_index = if_index
        self.outbound = outbound
        self.ipv6 = ipv6

    @classmethod
    def from_address_buffer(cls, raw: bytes) -> "diverted_packet_meta":
        flags = struct.unpack_from("<I", raw, ADDRESS_FLAGS_OFFSET)[0]
        if_index = struct.unpack_from("<I", raw, ADDRESS_IF_INDEX_OFFSET)[0]
        return cls(
            if_index=if_index,
            outbound=bool(flags & ADDRESS_OUTBOUND_BIT),
            ipv6=bool(flags & ADDRESS_IPV6_BIT),
        )

    def to_address_buffer(self) -> bytes:
        buffer = bytearray(WINDIVERT_ADDRESS_SIZE)
        struct.pack_into(
            "<I",
            buffer,
            ADDRESS_FLAGS_OFFSET,
            (ADDRESS_OUTBOUND_BIT if self.outbound else 0)
            | (ADDRESS_IPV6_BIT if self.ipv6 else 0),
        )
        struct.pack_into("<I", buffer, ADDRESS_IF_INDEX_OFFSET, self.if_index)
        return bytes(buffer)


def parse_ipv4_tcp(
    packet: bytes,
) -> tuple[str, int, str, int, int, int, int] | None:
    """解析 IPv4 + TCP 包头。

    返回 (源地址, 源端口, 目的地址, 目的端口, IPv4 头长度, TCP 头长度,
    TCP flags)；
    非 IPv4/TCP 或包不完整时返回 None。
    """
    if len(packet) < 20:
        return None
    version_and_ihl = packet[0]
    if version_and_ihl >> 4 != 4:
        return None
    ip_header_length = (version_and_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(packet) < ip_header_length:
        return None
    protocol = packet[9]
    if protocol != 6:
        return None
    source_address = ".".join(str(byte) for byte in packet[12:16])
    destination_address = ".".join(str(byte) for byte in packet[16:20])
    if len(packet) < ip_header_length + 20:
        return None
    source_port, destination_port = struct.unpack_from(
        "!HH",
        packet,
        ip_header_length,
    )
    data_offset_byte = packet[ip_header_length + 12]
    tcp_header_length = (data_offset_byte >> 4) * 4
    if tcp_header_length < 20:
        return None
    tcp_flags = packet[ip_header_length + 13]
    return (
        source_address,
        source_port,
        destination_address,
        destination_port,
        ip_header_length,
        tcp_header_length,
        tcp_flags,
    )


def parse_ipv4_udp(packet: bytes) -> tuple[str, int, str, int, int] | None:
    """解析 IPv4 + UDP 包头。

    返回 (源地址, 源端口, 目的地址, 目的端口, IPv4 头长度)；
    非 IPv4/UDP 或包不完整时返回 None。
    """
    if len(packet) < 20:
        return None
    version_and_ihl = packet[0]
    if version_and_ihl >> 4 != 4:
        return None
    ip_header_length = (version_and_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(packet) < ip_header_length + 8:
        return None
    if packet[9] != 17:
        return None
    source_address = ".".join(str(byte) for byte in packet[12:16])
    destination_address = ".".join(str(byte) for byte in packet[16:20])
    source_port, destination_port = struct.unpack_from(
        "!HH",
        packet,
        ip_header_length,
    )
    return (
        source_address,
        source_port,
        destination_address,
        destination_port,
        ip_header_length,
    )


def rewrite_ipv4_udp_ports(
    packet: bytearray,
    ip_header_length: int,
    source_port: int | None = None,
    destination_port: int | None = None,
) -> None:
    """原地改写 UDP 端口并把校验和置 0（IPv4 中 0 表示不校验）。"""
    if source_port is not None:
        struct.pack_into("!H", packet, ip_header_length, source_port)
    if destination_port is not None:
        struct.pack_into("!H", packet, ip_header_length + 2, destination_port)
    packet[ip_header_length + 6 : ip_header_length + 8] = b"\x00\x00"


def rewrite_ipv4_tcp_addresses_and_ports(
    packet: bytearray,
    ip_header_length: int,
    source_address: str | None = None,
    source_port: int | None = None,
    destination_address: str | None = None,
    destination_port: int | None = None,
) -> None:
    """原地改写 IPv4/TCP 头部的地址与端口，并重算两处校验和。"""
    if source_address is not None:
        packed = bytes(int(part) for part in source_address.split("."))
        packet[12:16] = packed
    if destination_address is not None:
        packed = bytes(int(part) for part in destination_address.split("."))
        packet[16:20] = packed
    if source_port is not None:
        struct.pack_into("!H", packet, ip_header_length, source_port)
    if destination_port is not None:
        struct.pack_into("!H", packet, ip_header_length + 2, destination_port)

    packet[10:12] = b"\x00\x00"
    ip_checksum = internet_checksum(packet[:ip_header_length])
    packet[10:12] = ip_checksum

    tcp_start = ip_header_length
    packet[tcp_start + 16 : tcp_start + 18] = b"\x00\x00"
    # 校验和只覆盖 IP 总长度内的 TCP 段；捕获缓冲区末尾可能带有链路层
    # 填充，不能按 len(packet) 计算，否则注入的包会被协议栈静默丢弃。
    ip_total_length = struct.unpack_from("!H", packet, 2)[0]
    tcp_length = ip_total_length - tcp_start
    if tcp_length < 20 or tcp_length > len(packet) - tcp_start:
        tcp_length = len(packet) - tcp_start
    pseudo_header = (
        packet[12:16]
        + packet[16:20]
        + b"\x00\x06"
        + struct.pack("!H", tcp_length)
    )
    tcp_checksum = internet_checksum(
        pseudo_header + packet[tcp_start : tcp_start + tcp_length]
    )
    packet[tcp_start + 16 : tcp_start + 18] = tcp_checksum


def internet_checksum(data: bytes) -> bytes:
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return struct.pack("!H", (~total) & 0xFFFF)
