from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from emudhra_mitm.config import ProxyConfig
from emudhra_mitm.settings_store import SettingsStore
from emudhra_mitm.webview_api import WebviewApi


class FakeController:
    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self.is_running = False
        self.stopped = False

    def start(self) -> dict[str, object]:
        self.is_running = True
        return {
            "event": "ready",
            "mode": self.config.mode_spec,
            "socks_endpoint": self.config.socks_endpoint,
            "upstream": self.config.upstream,
        }

    def stop(self) -> None:
        self.is_running = False
        self.stopped = True

    def stderr_text(self) -> str:
        return ""


class FakeFridaController:
    def __init__(self) -> None:
        self.running = False
        self.package_name = ""
        self.start_error: Exception | None = None

    def status(self) -> dict[str, object]:
        return {
            "available": True,
            "unavailable_reason": "",
            "frida_path": "frida.exe",
            "script_path": "bypass_ssl_pinning.js",
            "running": self.running,
            "package_name": self.package_name,
            "log": [],
        }

    def start(
        self,
        package_name: str,
        device_id: str = "",
    ) -> dict[str, object]:
        if self.start_error is not None:
            raise self.start_error
        self.running = True
        self.package_name = package_name
        self.device_id = device_id
        return self.status()

    def stop(self) -> None:
        self.running = False

    def shutdown(self) -> None:
        self.stop()

    def command_text(self, package_name: str, device_id: str = "") -> str:
        device_arguments = f"-D {device_id}" if device_id else "-U"
        return f"frida {device_arguments} -f {package_name}"


class FakeAdbController:
    def __init__(self) -> None:
        self.proxy_value = ""
        self.restore_all_count = 0

    def status(self) -> dict[str, object]:
        return {
            "available": True,
            "adb_path": "adb.exe",
            "version": "Version 37.0.1",
            "devices": [
                {
                    "serial": "emulator-5554",
                    "state": "device",
                    "product": "sdk",
                    "model": "Pixel",
                    "device": "generic",
                }
            ],
            "error": "",
        }

    def list_packages(self, device_serial: str = "") -> list[dict[str, str]]:
        return [
            {
                "package_name": "com.example.first",
                "label": "First App",
            },
            {
                "package_name": "com.example.second",
                "label": "Second App",
            },
        ]

    def connect(self, endpoint: str) -> str:
        return f"connected to {endpoint}"

    def pair_and_connect(
        self,
        pairing_endpoint: str,
        pairing_code: str,
        device_endpoint: str,
    ) -> dict[str, str]:
        return {
            "pair_output": f"Successfully paired to {pairing_endpoint}",
            "connect_output": f"connected to {device_endpoint}",
        }

    def disconnect(self, endpoint: str = "") -> str:
        return "disconnected"

    def enable_http_proxy(
        self,
        device_serial: str,
        local_port: int,
    ) -> dict[str, object]:
        previous_proxy = self.proxy_value
        self.proxy_value = f"127.0.0.1:{local_port}"
        return {
            "serial": device_serial,
            "proxy": self.proxy_value,
            "previous_proxy": previous_proxy,
        }

    def get_http_proxy(self, device_serial: str) -> str:
        return self.proxy_value

    def restore_http_proxy(self, device_serial: str) -> dict[str, object]:
        self.proxy_value = ""
        return {"serial": device_serial, "proxy": ""}

    def restore_all_http_proxies(self) -> list[str]:
        self.restore_all_count += 1
        self.proxy_value = ""
        return []


class FakeFridaSetupController:
    def __init__(self) -> None:
        self.prepare_calls: list[tuple[str, str]] = []
        self.ready = True

    def prepare(
        self,
        device_serial: str,
        package_name: str,
    ) -> dict[str, object]:
        self.prepare_calls.append((device_serial, package_name))
        return {
            "ready": self.ready,
            "mode": "root",
            "version": "17.18.0",
            "abi": "arm64-v8a",
            "message": (
                "已准备 frida-server"
                if self.ready
                else "设备没有 root，目标 App 也不可调试"
            ),
        }

    def progress(self) -> list[str]:
        return []


class FakeHotspotController:
    def __init__(self) -> None:
        self.runtime_platform = "linux"
        self.available = True
        self.running = False
        self.clients = 0
        self.redirect_enabled = False
        self.address_override: str | None = None
        self.client_network_override: str | None = None
        self.start_error: Exception | None = None
        self.redirect_error: Exception | None = None
        self.start_calls: list[tuple[str, str, str]] = []
        self.redirect_calls: list[tuple[str, int, str]] = []
        self.operation_order: list[str] = []
        self.stop_count = 0

    def preflight(self) -> None:
        if not self.available:
            raise RuntimeError("热点不可用")

    def validate_access_point(
        self,
        ssid: str,
        password: str,
        interface: str = "",
    ) -> None:
        if not ssid or not password:
            raise RuntimeError("热点参数无效")

    def status(self) -> dict[str, object]:
        return {
            "ok": True,
            "platform": "linux",
            "available": self.available,
            "error": "" if self.available else "热点不可用",
            "requires_administrator": False,
            "administrator": True,
            "running": self.running,
            "ssid": self.start_calls[-1][0] if self.running else "",
            "interface": "wlan0" if self.running else "",
            "interface_guid": (
                "{11111111-2222-3333-4444-555555555555}"
                if self.running
                else ""
            ),
            "interface_ifindex": 17 if self.running else 0,
            "address": (
                self.address_override
                if self.address_override is not None
                else ("10.42.0.1" if self.running else "")
            ),
            "prefix_length": 24 if self.running else 0,
            "client_network": (
                self.client_network_override
                if self.client_network_override is not None
                else ("10.42.0.0/24" if self.running else "")
            ),
            "backend": "networkmanager",
            "clients": self.clients,
            "clients_available": False,
            "client_devices": [],
            "interfaces": [{"name": "wlan0", "state": "disconnected"}],
            "redirect_enabled": self.redirect_enabled,
        }

    def start_access_point(
        self,
        ssid: str,
        password: str,
        interface: str = "",
    ) -> dict[str, object]:
        self.operation_order.append("start")
        self.start_calls.append((ssid, password, interface))
        if self.start_error is not None:
            raise self.start_error
        self.running = True
        return self.status()

    def enable_transparent_redirect(
        self,
        interface: str,
        transparent_port: int,
        client_network: str = "",
    ) -> None:
        if self.redirect_error is not None:
            raise self.redirect_error
        self.operation_order.append("enable")
        self.redirect_calls.append((interface, transparent_port, client_network))
        self.redirect_enabled = True

    def disable_transparent_redirect(self) -> None:
        self.redirect_enabled = False

    def windows_dns_servers(self) -> list[str]:
        self.dns_probe_calls = getattr(self, "dns_probe_calls", 0) + 1
        return ["192.168.8.1", "119.29.29.29"]

    def stop_access_point(self) -> None:
        self.stop_count += 1
        self.running = False


class FakeTransparentBridgeController:
    def __init__(self, **kwargs) -> None:
        self.proxy_host = kwargs["proxy_host"]
        self.proxy_port = kwargs["proxy_port"]
        self.listen_host = kwargs["listen_host"]
        self.listen_port = kwargs["listen_port"]
        self.redirect_host = kwargs.get("redirect_host", "")
        self.client_network = kwargs.get("client_network", "")
        self.hotspot_if_index = kwargs.get("hotspot_if_index", 0)
        self.dns_listen_ip = kwargs.get("dns_listen_ip", "")
        self.dns_upstream_servers = kwargs.get("dns_upstream_servers", [])
        self.is_running = False
        self.start_error: Exception | None = None
        self.stop_count = 0

    def start(self) -> dict[str, object]:
        if self.start_error is not None:
            raise self.start_error
        self.is_running = True
        return {"event": "ready"}

    def stop(self) -> None:
        self.stop_count += 1
        self.is_running = False

    def status(self) -> dict[str, object]:
        return {
            "running": self.is_running,
            "listen_host": self.listen_host,
            "listen_port": self.listen_port,
            "proxy_host": self.proxy_host,
            "proxy_port": self.proxy_port,
            "stderr": [],
        }


class WebviewApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.created_controllers: list[FakeController] = []

        def create_controller(config: ProxyConfig) -> FakeController:
            controller = FakeController(config)
            self.created_controllers.append(controller)
            return controller

        self.project_root = Path(__file__).resolve().parents[1]
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.settings_store = SettingsStore(
            Path(self.temporary_directory.name) / "config" / "settings.json"
        )
        self.frida_controller = FakeFridaController()
        self.frida_setup_controller = FakeFridaSetupController()
        self.adb_controller = FakeAdbController()
        self.hotspot_controller = FakeHotspotController()
        self.transparent_controllers: list[FakeTransparentBridgeController] = []
        self.transparent_start_error: Exception | None = None

        def create_transparent_controller(
            **kwargs,
        ) -> FakeTransparentBridgeController:
            controller = FakeTransparentBridgeController(**kwargs)
            controller.start_error = self.transparent_start_error
            self.transparent_controllers.append(controller)
            return controller

        self.api = WebviewApi(
            cas_root=self.project_root / "cas",
            controller_factory=create_controller,
            settings_store=self.settings_store,
            frida_controller=self.frida_controller,
            adb_controller=self.adb_controller,
            frida_setup_controller=self.frida_setup_controller,
            hotspot_controller=self.hotspot_controller,
            transparent_controller_factory=create_transparent_controller,
        )
        self.port_check_patcher = mock.patch.object(
            WebviewApi,
            "_ensure_transparent_port_available",
        )
        self.port_check_patcher.start()
        self.addCleanup(self.port_check_patcher.stop)
        self.proxy_port_check_patcher = mock.patch.object(
            WebviewApi,
            "_ensure_proxy_ports_available",
        )
        self.proxy_port_check_patcher.start()
        self.addCleanup(self.proxy_port_check_patcher.stop)
        self.hotspot_log_patcher = mock.patch(
            "emudhra_mitm.webview_api.append_hotspot_log"
        )
        self.hotspot_log_patcher.start()
        self.addCleanup(self.hotspot_log_patcher.stop)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_bootstrap_lists_cas_and_defaults(self) -> None:
        result = self.api.bootstrap()
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["cas"]), 8)
        self.assertEqual(
            result["defaults"]["socks_port"],
            28082,
        )
        self.assertEqual(result["defaults"]["listen_host"], "0.0.0.0")
        self.assertFalse(result["defaults"]["verify_upstream"])

    def test_starts_and_stops_controller(self) -> None:
        started = self.api.start_proxy(
            {
                "ca_name": "01-EM-OV-TLS-CA-G3C",
                "listen_host": "127.0.0.1",
                "listen_port": 28081,
                "socks_port": 28082,
                "upstream": "http://127.0.0.1:9000",
                "verify_upstream": False,
            }
        )
        self.assertTrue(started["ok"], started)
        self.assertTrue(started["status"]["running"])
        self.assertEqual(started["status"]["socks_endpoint"], "127.0.0.1:28082")
        self.assertFalse(started["status"]["config"]["verify_upstream"])
        self.assertTrue(self.settings_store.settings_path.is_file())

        stopped = self.api.stop_proxy()
        self.assertTrue(stopped["ok"])
        self.assertFalse(stopped["status"]["running"])
        self.assertTrue(self.created_controllers[0].stopped)
        self.assertGreaterEqual(self.adb_controller.restore_all_count, 1)

    def test_rejects_invalid_configuration(self) -> None:
        result = self.api.start_proxy(
            {
                "ca_name": "01-EM-OV-TLS-CA-G3C",
                "listen_host": "127.0.0.1",
                "listen_port": 9000,
                "socks_port": 28082,
                "upstream": "http://127.0.0.1:9000",
                "verify_upstream": False,
            }
        )
        self.assertFalse(result["ok"])
        self.assertIn("代理循环", result["error"])

    def test_restores_saved_configuration(self) -> None:
        requested_configuration = {
            "ca_name": "06-EM-DV-TLS-CA-G3B",
            "listen_host": "127.0.0.1",
            "listen_port": 18081,
            "socks_port": 18082,
            "upstream": "http://127.0.0.1:9001",
            "verify_upstream": True,
        }
        expected_configuration = {
            **requested_configuration,
            "verify_upstream": False,
        }
        started = self.api.start_proxy(requested_configuration)
        self.assertTrue(started["ok"], started)
        self.assertFalse(started["status"]["config"]["verify_upstream"])
        self.api.stop_proxy()

        restored_api = WebviewApi(
            cas_root=self.project_root / "cas",
            controller_factory=lambda config: FakeController(config),
            settings_store=self.settings_store,
        )
        restored = restored_api.bootstrap()
        self.assertEqual(restored["defaults"], expected_configuration)

    def test_exposes_frida_status_and_command(self) -> None:
        status = self.api.get_frida_status()
        self.assertTrue(status["ok"])
        self.assertTrue(status["available"])

        command = self.api.get_frida_command(
            {
                "package_name": "com.example.app",
                "device_id": "emulator-5554",
            }
        )
        self.assertTrue(command["ok"])
        self.assertEqual(
            command["command"],
            "frida -D emulator-5554 -f com.example.app",
        )

    def test_starts_and_stops_frida(self) -> None:
        started = self.api.start_frida(
            {
                "package_name": "com.example.app",
                "device_id": "emulator-5554",
                "ca_name": "01-EM-OV-TLS-CA-G3C",
                "listen_host": "127.0.0.1",
                "listen_port": 28081,
                "socks_port": 28082,
                "upstream": "http://127.0.0.1:9000",
            }
        )
        self.assertTrue(started["ok"])
        self.assertTrue(started["status"]["running"])
        self.assertTrue(started["proxy_status"]["running"])
        self.assertEqual(
            self.adb_controller.proxy_value,
            "127.0.0.1:28081",
        )
        self.assertEqual(
            self.frida_setup_controller.prepare_calls,
            [("emulator-5554", "com.example.app")],
        )

        stopped = self.api.stop_frida()
        self.assertTrue(stopped["ok"])
        self.assertFalse(stopped["status"]["running"])

    def test_rejects_frida_start_when_environment_is_not_ready(self) -> None:
        self.frida_setup_controller.ready = False
        result = self.api.start_frida(
            {
                "package_name": "com.example.app",
                "device_id": "emulator-5554",
            }
        )
        self.assertFalse(result["ok"])
        self.assertIn("不可调试", result["error"])
        self.assertFalse(self.frida_controller.running)
        self.assertFalse(self.api.get_status()["running"])
        self.assertEqual(self.adb_controller.proxy_value, "")

    def test_rolls_back_proxy_when_frida_start_fails(self) -> None:
        self.frida_controller.start_error = RuntimeError("Frida 启动失败")
        result = self.api.start_frida(
            {
                "package_name": "com.example.app",
                "device_id": "emulator-5554",
                "ca_name": "01-EM-OV-TLS-CA-G3C",
                "listen_host": "127.0.0.1",
                "listen_port": 28081,
                "socks_port": 28082,
                "upstream": "http://127.0.0.1:9000",
            }
        )

        self.assertFalse(result["ok"])
        self.assertIn("Frida 启动失败", result["error"])
        self.assertFalse(result["proxy_status"]["running"])
        self.assertEqual(self.adb_controller.proxy_value, "")

    def test_rejects_frida_start_without_proxy_configuration(self) -> None:
        result = self.api.start_frida(
            {
                "package_name": "com.example.app",
                "device_id": "emulator-5554",
            }
        )

        self.assertFalse(result["ok"])
        self.assertIn("代理配置", result["error"])
        self.assertFalse(self.api.get_status()["running"])
        self.assertFalse(self.frida_controller.running)

    def test_starts_and_stops_hotspot_capture(self) -> None:
        payload = {
            "ca_name": "01-EM-OV-TLS-CA-G3C",
            "listen_host": "0.0.0.0",
            "listen_port": 28081,
            "socks_port": 28082,
            "upstream": "http://127.0.0.1:9000",
            "ssid": "test-hotspot",
            "password": "password123",
            "interface": "wlan0",
            "transparent_port": 28083,
        }

        started = self.api.start_hotspot(payload)

        self.assertTrue(started["ok"])
        self.assertTrue(started["proxy_status"]["running"])
        self.assertEqual(
            self.hotspot_controller.start_calls,
            [("test-hotspot", "password123", "wlan0")],
        )
        self.assertEqual(
            self.hotspot_controller.redirect_calls,
            [("wlan0", 28083, "10.42.0.0/24")],
        )
        self.assertEqual(len(self.transparent_controllers), 1)
        transparent_controller = self.transparent_controllers[0]
        self.assertTrue(transparent_controller.is_running)
        self.assertEqual(transparent_controller.proxy_host, "127.0.0.1")
        self.assertEqual(transparent_controller.proxy_port, 28081)
        self.assertEqual(
            transparent_controller.redirect_host,
            "10.42.0.1",
        )
        self.assertEqual(
            transparent_controller.client_network,
            "10.42.0.0/24",
        )

        stopped = self.api.stop_hotspot()

        self.assertTrue(stopped["ok"])
        self.assertFalse(stopped["proxy_status"]["running"])
        self.assertEqual(transparent_controller.stop_count, 1)
        self.assertEqual(self.hotspot_controller.stop_count, 1)

    def test_exposes_hotspot_status(self) -> None:
        status = self.api.get_hotspot_status()

        self.assertTrue(status["ok"])
        self.assertEqual(status["hotspot"]["platform"], "linux")
        self.assertFalse(status["transparent"]["running"])

    def test_windows_hotspot_uses_transparent_path(self) -> None:
        self.hotspot_controller.runtime_platform = "win32"
        payload = {
            "ca_name": "01-EM-OV-TLS-CA-G3C",
            "listen_host": "0.0.0.0",
            "listen_port": 28081,
            "socks_port": 28082,
            "upstream": "http://127.0.0.1:9000",
            "ssid": "test-hotspot",
            "password": "password123",
            "interface": "",
            "transparent_port": 28083,
        }

        started = self.api.start_hotspot(payload)

        self.assertTrue(started["ok"], started)
        self.assertEqual(
            self.hotspot_controller.operation_order,
            ["start", "enable"],
        )
        self.assertEqual(len(self.transparent_controllers), 1)
        transparent_controller = self.transparent_controllers[0]
        self.assertEqual(transparent_controller.proxy_host, "127.0.0.1")
        self.assertEqual(transparent_controller.proxy_port, 28081)
        self.assertEqual(transparent_controller.redirect_host, "10.42.0.1")
        self.assertEqual(
            transparent_controller.client_network,
            "10.42.0.0/24",
        )
        # Windows 专属参数：WinDivert 按热点网卡过滤 IPv6，
        # DNS 转发器绑定热点网关地址并使用宿主机 DNS，公共 DNS 兜底。
        self.assertEqual(transparent_controller.hotspot_if_index, 17)
        self.assertEqual(transparent_controller.dns_listen_ip, "10.42.0.1")
        self.assertEqual(
            transparent_controller.dns_upstream_servers,
            ["192.168.8.1", "119.29.29.29", "223.5.5.5"],
        )
        self.assertEqual(
            self.hotspot_controller.redirect_calls,
            [("wlan0", 28083, "10.42.0.0/24")],
        )
        self.assertEqual(
            started["status"]["connection_mode"],
            "transparent",
        )
        self.assertNotIn("tun_gateway", started["status"])

        stopped = self.api.stop_hotspot()

        self.assertTrue(stopped["ok"])
        self.assertEqual(transparent_controller.stop_count, 1)
        self.assertEqual(self.hotspot_controller.stop_count, 1)

    def test_windows_hotspot_without_client_network_fails(self) -> None:
        self.hotspot_controller.runtime_platform = "win32"
        self.hotspot_controller.client_network_override = ""

        result = self.api.start_hotspot(
            {
                "ca_name": "01-EM-OV-TLS-CA-G3C",
                "listen_host": "127.0.0.1",
                "listen_port": 28081,
                "socks_port": 28082,
                "upstream": "http://127.0.0.1:9000",
                "ssid": "test-hotspot",
                "password": "password123",
                "interface": "",
                "transparent_port": 28083,
            }
        )

        self.assertFalse(result["ok"])
        self.assertIn("客户端网段", result["error"])
        self.assertEqual(self.hotspot_controller.stop_count, 1)
        self.assertFalse(self.api.get_status()["running"])

    def test_windows_hotspot_interface_without_gateway_fails(self) -> None:
        self.hotspot_controller.runtime_platform = "win32"
        self.hotspot_controller.address_override = ""

        result = self.api.start_hotspot(
            {
                "ca_name": "01-EM-OV-TLS-CA-G3C",
                "listen_host": "127.0.0.1",
                "listen_port": 28081,
                "socks_port": 28082,
                "upstream": "http://127.0.0.1:9000",
                "ssid": "test-hotspot",
                "password": "password123",
                "interface": "",
                "transparent_port": 28083,
            }
        )

        self.assertFalse(result["ok"])
        self.assertIn("本地网关地址", result["error"])
        self.assertEqual(self.hotspot_controller.stop_count, 1)
        self.assertFalse(self.api.get_status()["running"])

    def test_hotspot_start_failure_rolls_back_proxy(self) -> None:
        self.hotspot_controller.start_error = RuntimeError("热点启动失败")
        result = self.api.start_hotspot(
            {
                "ca_name": "01-EM-OV-TLS-CA-G3C",
                "listen_host": "127.0.0.1",
                "listen_port": 28081,
                "socks_port": 28082,
                "upstream": "http://127.0.0.1:9000",
                "ssid": "test-hotspot",
                "password": "password123",
                "interface": "wlan0",
                "transparent_port": 28083,
            }
        )

        self.assertFalse(result["ok"])
        self.assertIn("热点启动失败", result["error"])
        self.assertFalse(self.api.get_status()["running"])

    def test_stopping_hotspot_keeps_proxy_started_by_user(self) -> None:
        proxy_configuration = {
            "ca_name": "01-EM-OV-TLS-CA-G3C",
            "listen_host": "127.0.0.1",
            "listen_port": 28081,
            "socks_port": 28082,
            "upstream": "http://127.0.0.1:9000",
        }
        self.assertTrue(self.api.start_proxy(proxy_configuration)["ok"])

        started = self.api.start_hotspot(
            {
                **proxy_configuration,
                "ssid": "test-hotspot",
                "password": "password123",
                "interface": "wlan0",
                "transparent_port": 28083,
            }
        )
        self.assertTrue(started["ok"])

        stopped = self.api.stop_hotspot()

        self.assertTrue(stopped["ok"])
        self.assertTrue(stopped["proxy_status"]["running"])

    def test_transparent_bridge_failure_stops_started_hotspot(self) -> None:
        self.transparent_start_error = RuntimeError("透明桥启动失败")
        result = self.api.start_hotspot(
            {
                "ca_name": "01-EM-OV-TLS-CA-G3C",
                "listen_host": "127.0.0.1",
                "listen_port": 28081,
                "socks_port": 28082,
                "upstream": "http://127.0.0.1:9000",
                "ssid": "test-hotspot",
                "password": "password123",
                "interface": "wlan0",
                "transparent_port": 28083,
            }
        )

        self.assertFalse(result["ok"])
        self.assertIn("透明桥启动失败", result["error"])
        self.assertFalse(self.api.get_status()["running"])
        self.assertEqual(
            self.hotspot_controller.start_calls,
            [("test-hotspot", "password123", "wlan0")],
        )
        self.assertEqual(self.hotspot_controller.stop_count, 1)

    def test_redirect_failure_rolls_back_hotspot_and_transparent_bridge(self) -> None:
        self.hotspot_controller.redirect_error = RuntimeError("规则安装失败")
        result = self.api.start_hotspot(
            {
                "ca_name": "01-EM-OV-TLS-CA-G3C",
                "listen_host": "127.0.0.1",
                "listen_port": 28081,
                "socks_port": 28082,
                "upstream": "http://127.0.0.1:9000",
                "ssid": "test-hotspot",
                "password": "password123",
                "interface": "wlan0",
                "transparent_port": 28083,
            }
        )

        self.assertFalse(result["ok"])
        self.assertIn("规则安装失败", result["error"])
        self.assertFalse(self.api.get_status()["running"])
        self.assertEqual(self.hotspot_controller.stop_count, 1)
        self.assertEqual(self.transparent_controllers[0].stop_count, 1)

    def test_rejects_transparent_port_conflict(self) -> None:
        result = self.api.start_hotspot(
            {
                "ca_name": "01-EM-OV-TLS-CA-G3C",
                "listen_host": "127.0.0.1",
                "listen_port": 28081,
                "socks_port": 28082,
                "upstream": "http://127.0.0.1:9000",
                "ssid": "test-hotspot",
                "password": "password123",
                "interface": "wlan0",
                "transparent_port": 28081,
            }
        )

        self.assertFalse(result["ok"])
        self.assertIn("透明代理端口", result["error"])
        self.assertFalse(self.api.get_status()["running"])

    def test_exposes_adb_devices_and_packages(self) -> None:
        status = self.api.get_adb_status()
        self.assertTrue(status["ok"])
        self.assertTrue(status["available"])
        self.assertEqual(status["devices"][0]["serial"], "emulator-5554")

        packages = self.api.list_android_packages(
            {"device_serial": "emulator-5554"}
        )
        self.assertTrue(packages["ok"])
        self.assertEqual(
            packages["packages"],
            [
                {
                    "package_name": "com.example.first",
                    "label": "First App",
                },
                {
                    "package_name": "com.example.second",
                    "label": "Second App",
                },
            ],
        )

    def test_connects_pairs_and_disconnects_wireless_adb(self) -> None:
        connected = self.api.connect_adb(
            {"endpoint": "192.168.1.20:5555"}
        )
        self.assertTrue(connected["ok"])
        self.assertIn("connected", connected["message"])

        paired = self.api.pair_and_connect_adb(
            {
                "pairing_endpoint": "192.168.1.20:37123",
                "pairing_code": "123456",
                "device_endpoint": "192.168.1.20:5555",
            }
        )
        self.assertTrue(paired["ok"])
        self.assertIn("Successfully paired", paired["pair_message"])

        disconnected = self.api.disconnect_adb(
            {"endpoint": "192.168.1.20:5555"}
        )
        self.assertTrue(disconnected["ok"])

    def test_sets_and_restores_adb_proxy(self) -> None:
        enabled = self.api.set_adb_proxy(
            {
                "device_serial": "emulator-5554",
                "local_port": 28081,
            }
        )
        self.assertTrue(enabled["ok"])
        self.assertEqual(enabled["proxy"]["proxy"], "127.0.0.1:28081")

        status = self.api.get_adb_proxy_status(
            {"device_serial": "emulator-5554"}
        )
        self.assertTrue(status["ok"])
        self.assertEqual(status["proxy"], "127.0.0.1:28081")

        restored = self.api.restore_adb_proxy(
            {"device_serial": "emulator-5554"}
        )
        self.assertTrue(restored["ok"])
        self.assertEqual(restored["proxy"]["proxy"], "")


if __name__ == "__main__":
    unittest.main()
