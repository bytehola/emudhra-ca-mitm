from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

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
        self.api = WebviewApi(
            cas_root=self.project_root / "cas",
            controller_factory=create_controller,
            settings_store=self.settings_store,
            frida_controller=self.frida_controller,
            adb_controller=self.adb_controller,
            frida_setup_controller=self.frida_setup_controller,
        )

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
        self.assertTrue(started["ok"])
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
        self.assertTrue(started["ok"])
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
