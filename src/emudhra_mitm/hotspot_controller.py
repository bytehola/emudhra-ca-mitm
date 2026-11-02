"""创建系统热点，并为透明代理入口配置网络重定向。"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from emudhra_mitm.app_paths import RESOURCES_ROOT


LINUX_HOTSPOT_CONNECTION_NAME = "emudhra-mitm-hotspot"
LINUX_NFT_TABLE_NAME = "emudhra_mitm_hotspot"
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]+$")


class HotspotError(RuntimeError):
    """热点或透明重定向配置失败。"""


@dataclass(frozen=True, slots=True)
class LinuxInstallPlan:
    package_manager: str
    packages: tuple[str, ...]
    commands: tuple[tuple[str, ...], ...]
    manual_steps: tuple[str, ...]


class HotspotController:
    def __init__(
        self,
        runtime_platform: str | None = None,
        administrator_checker: Callable[[], bool] | None = None,
    ) -> None:
        self.runtime_platform = runtime_platform or sys.platform
        self.administrator_checker = (
            administrator_checker or self._default_administrator_check
        )
        self._backend = ""
        self._running = False
        self._ssid = ""
        self._interface = ""
        self._redirect_enabled = False
        self._windows_firewall_rules_enabled = False
        self._windows_off_count = 0

    def status(self) -> dict[str, Any]:
        try:
            if self.runtime_platform == "win32":
                return self._windows_status()
            if self.runtime_platform.startswith("linux"):
                return self._linux_status()
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
            return self._status_error(str(error))
        return self._status_error("当前系统不支持热点共享")

    def list_interfaces(self) -> list[dict[str, str]]:
        if not self.runtime_platform.startswith("linux"):
            return []
        return self._linux_interfaces()

    def preflight(self) -> None:
        status = self.status()
        if status.get("ready"):
            return
        if self.runtime_platform == "win32" and not self.administrator_checker():
            raise HotspotError("Windows 热点透明转发需要以管理员身份运行本工具")
        if not self.runtime_platform.startswith("linux"):
            raise HotspotError(
                status.get("error") or "当前系统缺少热点或透明代理所需组件"
            )
        if not status.get("available"):
            raise HotspotError(self._manual_install_message(status))

        try:
            self._install_linux_dependencies()
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
            refreshed_status = self.status()
            raise HotspotError(
                "Linux 依赖自动安装失败: "
                f"{error}\n{self._manual_install_message(refreshed_status)}"
            ) from error

        refreshed_status = self.status()
        if not refreshed_status.get("ready"):
            raise HotspotError(self._manual_install_message(refreshed_status))

    def start_access_point(
        self,
        ssid: str,
        password: str,
        interface: str = "",
    ) -> dict[str, Any]:
        self.validate_access_point(ssid, password, interface)
        self.preflight()
        if self.runtime_platform == "win32":
            return self._start_windows_access_point(
                ssid,
                password,
            )
        return self._start_linux_access_point(ssid, password, interface)

    def validate_access_point(
        self,
        ssid: str,
        password: str,
        interface: str = "",
    ) -> None:
        if self.runtime_platform.startswith("linux") and not interface:
            raise HotspotError("请选择用于创建热点的无线接口")
        self._validate_access_point(ssid, password, interface)

    def enable_transparent_redirect(
        self,
        interface: str,
        transparent_port: int,
        client_network: str = "",
    ) -> None:
        self._validate_port(transparent_port)
        try:
            if self.runtime_platform == "win32":
                self._enable_windows_firewall_rules(
                    transparent_port,
                    client_network,
                )
            elif self.runtime_platform.startswith("linux"):
                self._install_linux_redirect(interface, transparent_port)
            else:
                raise HotspotError("当前系统不支持透明重定向")
        except Exception:
            self.disable_transparent_redirect()
            raise
        self._redirect_enabled = True

    def disable_transparent_redirect(self) -> None:
        if self.runtime_platform == "win32":
            self._remove_windows_firewall_rules()
        elif self.runtime_platform.startswith("linux"):
            self._remove_linux_redirect()
        self._redirect_enabled = False

    def stop_access_point(self) -> None:
        if self.runtime_platform == "win32":
            self._stop_windows_access_point()
        elif self.runtime_platform.startswith("linux"):
            self._stop_linux_access_point()
        self._running = False
        self._ssid = ""
        self._interface = ""

    def _linux_status(self) -> dict[str, Any]:
        nmcli = shutil.which("nmcli")
        nft = self._privileged_command("nft")
        ip = shutil.which("ip")
        pkexec = self._trusted_system_executable("pkexec")
        administrator = bool(self.administrator_checker())
        backend = self._linux_backend()
        can_elevate = administrator or pkexec is not None

        missing_reasons = []
        missing_packages = []
        if not nft:
            missing_reasons.append("nftables")
            missing_packages.append("nftables")
        if not ip:
            missing_reasons.append("iproute2")
            missing_packages.append("iproute2")
        if not backend:
            missing_reasons.append(
                "NetworkManager nmcli（服务需运行）或 create_ap"
            )
            missing_packages.append("networkmanager")

        install_plan = (
            self._linux_install_plan(missing_packages)
            if missing_packages
            else None
        )
        install_steps: list[str] = (
            list(install_plan.manual_steps)
            if install_plan is not None
            else []
        )
        components_ready = not missing_reasons
        if not can_elevate:
            missing_reasons.append("root 或 pkexec")
            install_steps.append("以 root 权限重新运行本工具")

        ready = components_ready and can_elevate
        available = can_elevate and (
            components_ready or install_plan is not None
        )
        if not components_ready and install_plan is None:
            install_steps.append(
                "使用发行版包管理器安装 NetworkManager、nftables、iproute2"
            )

        running = self._running
        interface = self._interface
        if nmcli and self._networkmanager_connection_active():
            running = True
            interface = self._networkmanager_connection_device(
                interface or self._first_linux_wifi_interface()
            )
            self._backend = "networkmanager"
            self._interface = interface
            self._running = True
            if not self._ssid:
                self._ssid = self._networkmanager_connection_ssid()

        client_devices = (
            self._linux_client_devices(interface) if interface else []
        )
        return {
            "ok": True,
            "platform": "linux",
            "ready": ready,
            "available": available,
            "error": (
                "缺少或需要: " + ", ".join(missing_reasons)
                if missing_reasons
                else ""
            ),
            "missing_dependencies": missing_reasons,
            "install_steps": install_steps,
            "requires_administrator": not administrator,
            "administrator": administrator,
            "running": running,
            "ssid": self._ssid,
            "interface": interface,
            "interface_guid": "",
            "address": self._ipv4_address(interface) if interface else "",
            "prefix_length": 0,
            "client_network": "",
            "backend": backend,
            "clients": len(client_devices),
            "clients_available": bool(
                interface and (shutil.which("iw") or ip)
            ),
            "client_devices": client_devices,
            "interfaces": self._linux_interfaces(),
            "redirect_enabled": self._redirect_enabled,
        }

    def windows_dns_servers(self) -> list[str]:
        """探测宿主机当前在用的 IPv4 DNS 服务器，供 DNS 转发器使用。

        通过 PowerShell 的 Get-DnsClientServerAddress 读取全部网卡的
        DNS，过滤掉热点自身的 192.168.137.* 与无效值，最多取两个。
        探测失败时返回空列表，由调用方决定是否降级启动。
        """
        if self.runtime_platform != "win32":
            return []
        powershell = self._windows_system_executable(
            "WindowsPowerShell\\v1.0\\powershell.exe"
        ) or shutil.which("pwsh")
        if not powershell:
            return []
        try:
            completed = self._run(
                [
                    powershell,
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    (
                        "(Get-DnsClientServerAddress -AddressFamily IPv4 "
                        "-ErrorAction SilentlyContinue | "
                        "ForEach-Object {$_.ServerAddresses}) -join ','"
                    ),
                ],
                check=False,
                timeout=20,
            )
        except (
            HotspotError,
            OSError,
            RuntimeError,
            subprocess.TimeoutExpired,
        ):
            return []
        servers: list[str] = []
        for raw_server in completed.stdout.split(","):
            candidate = raw_server.strip()
            if not candidate:
                continue
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if address.version != 4:
                continue
            if candidate.startswith("192.168.137."):
                continue
            if candidate not in servers:
                servers.append(candidate)
        return servers[:2]

    def _windows_status(self) -> dict[str, Any]:
        administrator = bool(self.administrator_checker())
        script_path = RESOURCES_ROOT / "windows" / "hotspot.ps1"
        if not script_path.is_file():
            return self._status_error(f"找不到 Windows 热点脚本: {script_path}")

        result = self._run_powershell_script(
            script_path,
            ["-Action", "status"],
            timeout=30,
        )
        status_ok = bool(result.get("ok"))
        reported_state = str(result.get("state", ""))
        if status_ok and reported_state == "On":
            running = True
            self._running = True
            self._windows_off_count = 0
        elif status_ok and reported_state == "Off":
            if self._running:
                self._windows_off_count += 1
                running = self._windows_off_count < 2
                if not running:
                    self._running = False
            else:
                running = False
        else:
            running = self._running
        available = administrator and (status_ok or running)
        if not administrator:
            error_message = "需要以管理员身份运行才能启用 Windows 热点网关"
        elif not status_ok and not running:
            error_message = str(
                result.get("message", "Windows 移动热点暂不可用")
            )
        else:
            error_message = ""
        address = str(result.get("gateway", ""))
        prefix_length = int(result.get("prefix_length", 0) or 0)
        client_network = ""
        if address and prefix_length:
            client_network = str(
                ipaddress.ip_network(
                    f"{address}/{prefix_length}",
                    strict=False,
                )
            )
        client_devices = self._normalize_client_devices(
            result.get("devices")
        )
        return {
            "ok": True,
            "platform": "windows",
            "ready": available,
            "available": available,
            "error": error_message,
            "missing_dependencies": [] if available else [error_message],
            "install_steps": [],
            "requires_administrator": True,
            "administrator": administrator,
            "running": running,
            "ssid": str(result.get("ssid", "")),
            "interface": str(result.get("interface_name", "")),
            "interface_guid": str(result.get("interface_guid", "")),
            "interface_ifindex": int(
                result.get("interface_ifindex", 0) or 0
            ),
            "address": address,
            "prefix_length": prefix_length,
            "client_network": client_network,
            "backend": "windows-mobile-hotspot",
            "clients": int(result.get("clients", 0)),
            "clients_available": True,
            "client_devices": client_devices,
            "interfaces": [],
            "redirect_enabled": self._redirect_enabled,
        }

    def _start_linux_access_point(
        self,
        ssid: str,
        password: str,
        interface: str,
    ) -> dict[str, Any]:
        backend = self._linux_backend()
        if not backend:
            raise HotspotError("未找到可用的 Linux 热点后端")
        self._backend = backend
        try:
            if backend == "create_ap":
                actual_interface = self._start_create_ap(
                    ssid,
                    password,
                    interface,
                )
            else:
                actual_interface = self._start_networkmanager_hotspot(
                    ssid,
                    password,
                    interface,
                )
        except Exception:
            self._stop_linux_access_point()
            raise

        self._running = True
        self._ssid = ssid
        self._interface = actual_interface
        self._wait_for_linux_address(actual_interface)
        return self._linux_status()

    def _start_create_ap(
        self,
        ssid: str,
        password: str,
        interface: str,
    ) -> str:
        create_ap = self._privileged_command("create_ap")
        if create_ap is None:
            raise HotspotError("未找到 create_ap")

        uplink_interface = self._default_route_interface()
        initial_interfaces = {
            interface_info["name"]
            for interface_info in self._iw_interfaces()
        }
        initial_address = self._ipv4_address(interface)
        self._run_privileged(
            [
                create_ap,
                "--daemon",
                interface,
                uplink_interface,
                ssid,
                password,
            ],
            timeout=60,
        )
        return self._wait_for_create_ap_interface(
            interface,
            initial_interfaces,
            initial_address,
        )

    def _start_networkmanager_hotspot(
        self,
        ssid: str,
        password: str,
        interface: str,
    ) -> str:
        nmcli = shutil.which("nmcli")
        if nmcli is None:
            raise HotspotError("未找到 nmcli")

        self._run(
            [
                nmcli,
                "connection",
                "delete",
                LINUX_HOTSPOT_CONNECTION_NAME,
            ],
            check=False,
        )
        self._run(
            [
                nmcli,
                "device",
                "wifi",
                "hotspot",
                "ifname",
                interface,
                "con-name",
                LINUX_HOTSPOT_CONNECTION_NAME,
                "ssid",
                ssid,
                "password",
                password,
            ],
            timeout=60,
        )
        return self._networkmanager_connection_device(interface)

    def _stop_linux_access_point(self) -> None:
        try:
            if self._redirect_enabled:
                self.disable_transparent_redirect()
        finally:
            if self._backend == "create_ap" and self._interface:
                create_ap = self._privileged_command("create_ap")
                if create_ap:
                    self._run_privileged(
                        [create_ap, "--stop", self._interface],
                        check=False,
                        timeout=30,
                    )
            elif self._backend == "networkmanager":
                nmcli = shutil.which("nmcli")
                if nmcli:
                    self._run(
                        [
                            nmcli,
                            "connection",
                            "down",
                            LINUX_HOTSPOT_CONNECTION_NAME,
                        ],
                        check=False,
                    )
                    self._run(
                        [
                            nmcli,
                            "connection",
                            "delete",
                            LINUX_HOTSPOT_CONNECTION_NAME,
                        ],
                        check=False,
                    )

    def _install_linux_redirect(
        self,
        interface: str,
        transparent_port: int,
    ) -> None:
        if not interface or not INTERFACE_PATTERN.fullmatch(interface):
            raise HotspotError("无线接口名称无效")

        nft = self._privileged_command("nft")
        if nft is None:
            raise HotspotError("未找到 nft")

        self._remove_linux_redirect()
        quoted_interface = json.dumps(interface)
        rules = "; ".join(
            (
                f"add table inet {LINUX_NFT_TABLE_NAME}",
                (
                    f"add chain inet {LINUX_NFT_TABLE_NAME} prerouting "
                    "{ type nat hook prerouting priority dstnat; "
                    "policy accept; }"
                ),
                (
                    f"add rule inet {LINUX_NFT_TABLE_NAME} prerouting "
                    f"iifname {quoted_interface} "
                    f"tcp dport {{ 80, 443 }} "
                    f"redirect to :{transparent_port}"
                ),
                (
                    f"add chain inet {LINUX_NFT_TABLE_NAME} forward "
                    "{ type filter hook forward priority filter; "
                    "policy accept; }"
                ),
                (
                    f"add rule inet {LINUX_NFT_TABLE_NAME} forward "
                    f"iifname {quoted_interface} udp dport 443 reject"
                ),
            )
        )
        self._run_privileged([nft, rules], timeout=30)

    def _remove_linux_redirect(self) -> None:
        nft = self._privileged_command("nft")
        if nft is None:
            return
        self._run_privileged(
            [nft, "delete", "table", "inet", LINUX_NFT_TABLE_NAME],
            check=False,
            timeout=30,
        )

    def _start_windows_access_point(
        self,
        ssid: str,
        password: str,
    ) -> dict[str, Any]:
        script_path = RESOURCES_ROOT / "windows" / "hotspot.ps1"

        result = self._run_powershell_script(
            script_path,
            [
                "-Action",
                "start",
                "-Ssid",
                ssid,
                "-Password",
                password,
            ],
            timeout=45,
        )
        if not result.get("ok"):
            raise HotspotError(
                str(result.get("message", "启动 Windows 移动热点失败"))
            )
        if result.get("state") != "On":
            raise HotspotError(
                "Windows 移动热点未进入 On 状态: "
                f"{result.get('state', 'Unknown')}"
            )

        self._running = True
        self._ssid = str(result.get("ssid", ssid))
        self._interface = ""
        self._backend = "windows-mobile-hotspot"
        return self._windows_status()

    def _stop_windows_access_point(self) -> None:
        if self._redirect_enabled:
            self.disable_transparent_redirect()

        script_path = RESOURCES_ROOT / "windows" / "hotspot.ps1"
        if not script_path.is_file():
            return
        result = self._run_powershell_script(
            script_path,
            ["-Action", "stop"],
            timeout=30,
        )
        if not result.get("ok"):
            raise HotspotError(
                str(
                    result.get(
                        "message",
                        "停止 Windows 移动热点失败",
                    )
                )
            )

    def _enable_windows_firewall_rules(
        self,
        transparent_port: int,
        client_network: str,
    ) -> None:
        script_path = RESOURCES_ROOT / "windows" / "firewall.ps1"
        if not script_path.is_file():
            raise HotspotError(f"找不到 Windows 防火墙脚本: {script_path}")
        # QUIC 阻断规则只针对热点客户端网段；网段无效就无法收窄范围，
        # 宁缺毋滥，避免把宿主机自身的 QUIC 也掐掉。
        try:
            client_network_value = str(
                ipaddress.ip_network(client_network, strict=False)
            )
        except ValueError as error:
            raise HotspotError(
                f"热点客户端网段无效，无法配置 QUIC 阻断: {client_network!r}"
            ) from error
        self._remove_windows_firewall_rules()
        result = self._run_powershell_script(
            script_path,
            [
                "-Action",
                "enable",
                "-TransparentPort",
                str(transparent_port),
                "-HotspotClientNetwork",
                client_network_value,
            ],
            timeout=30,
        )
        if not result.get("ok"):
            raise HotspotError(
                str(
                    result.get(
                        "message",
                        "配置 Windows 透明转发防火墙规则失败",
                    )
                )
            )
        self._windows_firewall_rules_enabled = True

    def _remove_windows_firewall_rules(self) -> None:
        script_path = RESOURCES_ROOT / "windows" / "firewall.ps1"
        if script_path.is_file():
            self._run_powershell_script(
                script_path,
                ["-Action", "disable"],
                timeout=30,
            )
        self._windows_firewall_rules_enabled = False

    def _linux_interfaces(self) -> list[dict[str, str]]:
        nmcli = shutil.which("nmcli")
        if nmcli:
            completed = self._run(
                [
                    nmcli,
                    "-t",
                    "-f",
                    "DEVICE,TYPE,STATE",
                    "device",
                    "status",
                ],
                check=False,
            )
            interfaces = []
            for raw_line in completed.stdout.splitlines():
                device, separator, details = raw_line.partition(":")
                device_type, _, device_state = details.partition(":")
                if separator and device_type == "wifi":
                    interfaces.append(
                        {
                            "name": device,
                            "state": device_state,
                            "backend": "networkmanager",
                        }
                    )
            if interfaces:
                return interfaces

        return [
            {
                "name": interface_name,
                "state": "",
                "backend": "create_ap",
            }
            for interface_name in self._iw_interfaces()
        ]

    def _linux_client_devices(self, interface: str) -> list[dict[str, str]]:
        neighbor_states: dict[str, tuple[str, str]] = {}
        ip = shutil.which("ip")
        if ip:
            completed = self._run(
                ["ip", "neigh", "show", "dev", interface],
                check=False,
            )
            for raw_line in completed.stdout.splitlines():
                fields = raw_line.split()
                if not fields:
                    continue
                ip_address = fields[0]
                mac_address = ""
                state = fields[-1] if fields else ""
                if "lladdr" in fields:
                    mac_index = fields.index("lladdr") + 1
                    if mac_index < len(fields):
                        mac_address = fields[mac_index]
                if state.upper() in {"FAILED", "INCOMPLETE"}:
                    continue
                if mac_address:
                    neighbor_states[mac_address.lower()] = (
                        ip_address,
                        state,
                    )

        station_macs: list[str] = []
        iw = shutil.which("iw")
        if iw:
            completed = self._run(
                [iw, "dev", interface, "station", "dump"],
                check=False,
            )
            for raw_line in completed.stdout.splitlines():
                line = raw_line.strip()
                if line.startswith("Station "):
                    station_macs.append(
                        line.removeprefix("Station ").strip().lower()
                    )

        devices = []
        for mac_address in station_macs:
            ip_address, state = neighbor_states.get(
                mac_address,
                ("", "CONNECTED"),
            )
            devices.append(
                {
                    "ip_address": ip_address,
                    "mac_address": mac_address,
                    "state": state,
                }
            )

        known_macs = set(station_macs)
        for mac_address, (ip_address, state) in neighbor_states.items():
            if mac_address in known_macs:
                continue
            devices.append(
                {
                    "ip_address": ip_address,
                    "mac_address": mac_address,
                    "state": state,
                }
            )
        return self._normalize_client_devices(devices)

    @staticmethod
    def _normalize_client_devices(raw_devices: Any) -> list[dict[str, str]]:
        if isinstance(raw_devices, dict):
            raw_devices = [raw_devices]
        if not isinstance(raw_devices, list):
            return []

        devices = []
        for raw_device in raw_devices:
            if not isinstance(raw_device, dict):
                continue
            ip_address = str(raw_device.get("ip_address", "")).strip()
            mac_address = str(
                raw_device.get("mac_address", "")
            ).strip().replace("-", ":").lower()
            state = str(raw_device.get("state", "")).strip()
            if not mac_address or mac_address in {
                "00:00:00:00:00:00",
                "ff:ff:ff:ff:ff:ff",
            }:
                continue
            if ip_address:
                try:
                    ipaddress.ip_address(ip_address)
                except ValueError:
                    continue
            devices.append(
                {
                    "ip_address": ip_address,
                    "mac_address": mac_address,
                    "state": state,
                }
            )

        devices.sort(
            key=lambda device: (
                ipaddress.ip_address(device["ip_address"])
                if device["ip_address"]
                else ipaddress.ip_address("255.255.255.255"),
                device["mac_address"],
            )
        )
        return devices

    def _iw_interfaces(self) -> list[str]:
        iw = shutil.which("iw")
        if iw is None:
            return []
        completed = self._run([iw, "dev"], check=False)
        interfaces = []
        for raw_line in completed.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("Interface "):
                interfaces.append(line.removeprefix("Interface ").strip())
        return interfaces

    def _linux_backend(self) -> str:
        create_ap = self._privileged_command("create_ap")
        if create_ap and all(
            shutil.which(command)
            for command in ("hostapd", "dnsmasq", "iw", "iptables")
        ):
            return "create_ap"
        nmcli = shutil.which("nmcli")
        if nmcli:
            completed = self._run(
                [nmcli, "-t", "-f", "RUNNING", "general"],
                check=False,
            )
            if (
                completed.returncode == 0
                and completed.stdout.strip().lower() == "running"
            ):
                return "networkmanager"
        return ""

    def _first_linux_wifi_interface(self) -> str:
        interfaces = self._linux_interfaces()
        return interfaces[0]["name"] if interfaces else ""

    def _networkmanager_connection_active(self) -> bool:
        nmcli = shutil.which("nmcli")
        if nmcli is None:
            return False
        completed = self._run(
            ["nmcli", "-t", "-f", "NAME", "connection", "show", "--active"],
            check=False,
        )
        return LINUX_HOTSPOT_CONNECTION_NAME in completed.stdout.splitlines()

    def _networkmanager_connection_device(self, fallback: str) -> str:
        nmcli = shutil.which("nmcli")
        if nmcli is None:
            return fallback
        completed = self._run(
            [
                nmcli,
                "-t",
                "-f",
                "GENERAL.DEVICES",
                "connection",
                "show",
                LINUX_HOTSPOT_CONNECTION_NAME,
            ],
            check=False,
        )
        line = completed.stdout.strip()
        if line.startswith("GENERAL.DEVICES:"):
            line = line.removeprefix("GENERAL.DEVICES:")
        device = line.split(":", 1)[0].strip()
        return device or fallback

    def _networkmanager_connection_ssid(self) -> str:
        nmcli = shutil.which("nmcli")
        if nmcli is None:
            return ""
        completed = self._run(
            [
                nmcli,
                "-g",
                "802-11-wireless.ssid",
                "connection",
                "show",
                LINUX_HOTSPOT_CONNECTION_NAME,
            ],
            check=False,
        )
        return completed.stdout.strip()

    def _default_route_interface(self) -> str:
        ip = shutil.which("ip")
        if ip is None:
            raise HotspotError("未找到 ip 命令，无法确定上网接口")
        completed = self._run([ip, "route", "show", "default"], check=False)
        for raw_line in completed.stdout.splitlines():
            fields = raw_line.split()
            if "dev" in fields:
                device_index = fields.index("dev") + 1
                if device_index < len(fields):
                    return fields[device_index]
        raise HotspotError("未找到默认上网接口")

    def _ipv4_address(self, interface: str) -> str:
        ip = shutil.which("ip")
        if not interface or ip is None:
            return ""
        completed = self._run(
            [ip, "-4", "-o", "address", "show", "dev", interface],
            check=False,
        )
        fields = completed.stdout.split()
        if "inet" not in fields:
            return ""
        address_index = fields.index("inet") + 1
        if address_index >= len(fields):
            return ""
        return fields[address_index].split("/", 1)[0]

    def _wait_for_linux_address(self, interface: str) -> None:
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self._ipv4_address(interface):
                return
            time.sleep(0.5)
        raise HotspotError("热点已启动，但未获取到无线接口 IPv4 地址")

    def _wait_for_create_ap_interface(
        self,
        selected_interface: str,
        initial_interfaces: set[str],
        initial_address: str,
    ) -> str:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            for interface_name in self._iw_interfaces():
                if (
                    interface_name not in initial_interfaces
                    and self._ipv4_address(interface_name)
                ):
                    return interface_name

            selected_address = self._ipv4_address(selected_interface)
            if selected_address and selected_address != initial_address:
                return selected_interface
            time.sleep(0.5)
        raise HotspotError("无法确定 create_ap 创建的热点接口")

    def _run_powershell_script(
        self,
        script_path: Path,
        arguments: list[str],
        timeout: float,
    ) -> dict[str, Any]:
        powershell = self._windows_system_executable(
            "WindowsPowerShell\\v1.0\\powershell.exe"
        ) or shutil.which("pwsh")
        if not powershell:
            raise HotspotError("未找到 PowerShell")
        completed = self._run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                *arguments,
            ],
            timeout=timeout,
        )
        output_lines = [
            line.strip()
            for line in completed.stdout.splitlines()
            if line.strip()
        ]
        if not output_lines:
            raise HotspotError("PowerShell 未返回热点状态")
        try:
            result = json.loads(output_lines[-1])
        except json.JSONDecodeError as error:
            raise HotspotError("PowerShell 返回了无效的热点状态") from error
        if not isinstance(result, dict):
            raise HotspotError("PowerShell 返回了无效的热点状态")
        return result

    def _run_privileged(
        self,
        command: list[str],
        check: bool = True,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        if self.administrator_checker():
            return self._run(command, check=check, timeout=timeout)
        pkexec = self._trusted_system_executable("pkexec")
        if pkexec is None:
            raise HotspotError("需要 root 权限，但未找到可信的 pkexec")
        return self._run(
            [pkexec, *command],
            check=check,
            timeout=timeout,
        )

    def _privileged_command(self, executable_name: str) -> str | None:
        if self.administrator_checker():
            return self._find_executable(executable_name)
        return self._trusted_system_executable(executable_name)

    @classmethod
    def _trusted_system_executable(cls, executable_name: str) -> str | None:
        executable = cls._find_executable(executable_name)
        if executable is None:
            return None

        resolved_path = Path(executable).resolve()
        try:
            file_status = resolved_path.stat()
        except OSError:
            return None
        if not stat.S_ISREG(file_status.st_mode):
            return None
        if file_status.st_uid != 0:
            return None
        if file_status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return None

        for parent in resolved_path.parents:
            try:
                parent_status = parent.stat()
            except OSError:
                return None
            if parent_status.st_uid != 0:
                return None
            if parent_status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return None
        return str(resolved_path)

    @staticmethod
    def _find_executable(executable_name: str) -> str | None:
        discovered = shutil.which(executable_name)
        if discovered:
            return discovered
        for directory in (
            "/usr/local/sbin",
            "/usr/local/bin",
            "/usr/sbin",
            "/usr/bin",
            "/sbin",
            "/bin",
            "/run/current-system/sw/bin",
        ):
            candidate = Path(directory) / executable_name
            if candidate.is_file():
                return str(candidate)
        return None

    @staticmethod
    def _windows_system_executable(relative_path: str) -> str | None:
        windows_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        if windows_root:
            candidate = Path(windows_root) / "System32" / relative_path
            if candidate.is_file():
                return str(candidate)
        return shutil.which(Path(relative_path).name)

    def _linux_required_packages(self) -> list[str]:
        required_packages = []
        if self._privileged_command("nft") is None:
            required_packages.append("nftables")
        if shutil.which("ip") is None:
            required_packages.append("iproute2")
        if not self._linux_backend():
            required_packages.append("networkmanager")
        return required_packages

    def _linux_install_plan(
        self,
        required_packages: list[str],
    ) -> LinuxInstallPlan | None:
        if not required_packages:
            return None

        package_manager_specs = (
            (
                "apt-get",
                "apt-get",
                "network-manager",
                "update",
            ),
            ("dnf", "dnf", "NetworkManager", "install"),
            ("yum", "yum", "NetworkManager", "install"),
            ("pacman", "pacman", "networkmanager", "update"),
            ("zypper", "zypper", "NetworkManager", "install"),
            ("apk", "apk", "networkmanager", "install"),
        )
        for (
            executable_name,
            package_manager,
            network_manager_package,
            update_action,
        ) in package_manager_specs:
            executable = self._privileged_command(executable_name)
            if executable is None:
                continue

            package_names = []
            for package_name in required_packages:
                if package_name == "networkmanager":
                    package_names.append(network_manager_package)
                else:
                    package_names.append(package_name)

            if package_manager == "apt-get":
                commands = (
                    (executable, update_action),
                    (executable, "install", "-y", *package_names),
                )
            elif package_manager in {"dnf", "yum"}:
                commands = (
                    (executable, "install", "-y", *package_names),
                )
            elif package_manager == "pacman":
                commands = (
                    (
                        executable,
                        "-Sy",
                        "--noconfirm",
                        *package_names,
                    ),
                )
            elif package_manager == "zypper":
                commands = (
                    (
                        executable,
                        "--non-interactive",
                        "install",
                        *package_names,
                    ),
                )
            else:
                commands = (
                    (executable, "add", *package_names),
                )

            systemctl = self._privileged_command("systemctl")
            if (
                "networkmanager" in required_packages
                and systemctl is not None
            ):
                commands = (
                    *commands,
                    (systemctl, "enable", "--now", "NetworkManager"),
                )

            return LinuxInstallPlan(
                package_manager=package_manager,
                packages=tuple(package_names),
                commands=commands,
                manual_steps=tuple(
                    "sudo " + shlex.join(command)
                    for command in commands
                ),
            )
        return None

    def _install_linux_dependencies(self) -> None:
        install_plan = self._linux_install_plan(
            self._linux_required_packages()
        )
        if install_plan is None:
            raise HotspotError(
                "无法识别可用的系统包管理器，请手动安装热点依赖"
            )
        for command in install_plan.commands:
            self._run_privileged(list(command), timeout=300)

    @staticmethod
    def _manual_install_message(status: dict[str, Any]) -> str:
        message = status.get("error") or "热点依赖尚未就绪"
        install_steps = status.get("install_steps") or []
        if install_steps:
            message += "\n请使用 root 权限执行:\n" + "\n".join(install_steps)
        return message

    @staticmethod
    def _run(
        command: list[str],
        check: bool = True,
        timeout: float = 20,
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            creationflags=(
                subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            ),
        )
        if check and completed.returncode != 0:
            error_output = (completed.stderr or completed.stdout).strip()
            raise HotspotError(
                error_output or f"命令失败: {command[0]}"
            )
        return completed

    @staticmethod
    def _validate_access_point(
        ssid: str,
        password: str,
        interface: str,
    ) -> None:
        ssid_bytes = ssid.encode("utf-8")
        if not 1 <= len(ssid_bytes) <= 32 or ssid.startswith("-"):
            raise HotspotError("热点名称按 UTF-8 编码后必须为 1 到 32 字节")
        if (
            not 8 <= len(password) <= 63
            or not password.isascii()
            or password.startswith("-")
        ):
            raise HotspotError("热点密码必须为 8 到 63 个 ASCII 字符")
        if any(ord(character) < 32 for character in ssid + password):
            raise HotspotError("热点名称或密码不能包含控制字符")
        if interface and not INTERFACE_PATTERN.fullmatch(interface):
            raise HotspotError("无线接口名称无效")

    @staticmethod
    def _validate_port(port: int) -> None:
        if not 1 <= port <= 65535:
            raise HotspotError("透明代理端口必须在 1 到 65535 之间")

    def _status_error(self, message: str) -> dict[str, Any]:
        return {
            "ok": False,
            "platform": self.runtime_platform,
            "ready": False,
            "available": False,
            "error": message,
            "missing_dependencies": [],
            "install_steps": [],
            "requires_administrator": True,
            "administrator": bool(self.administrator_checker()),
            "running": False,
            "ssid": "",
            "interface": "",
            "interface_guid": "",
            "address": "",
            "prefix_length": 0,
            "client_network": "",
            "backend": "",
            "clients": 0,
            "clients_available": False,
            "client_devices": [],
            "interfaces": [],
            "redirect_enabled": False,
        }

    @staticmethod
    def _default_administrator_check() -> bool:
        if os.name == "nt":
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except (AttributeError, OSError):
                return False
        return hasattr(os, "geteuid") and os.geteuid() == 0
