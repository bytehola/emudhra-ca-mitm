from __future__ import annotations

import lzma
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from emudhra_mitm.frida_setup import FridaSetupController


class FakeAdbController:
    def __init__(self) -> None:
        self.is_root = True
        self.is_debuggable = True
        self.device_abi = "arm64-v8a"
        self.native_bridge = ""
        self.package_abi = "arm64-v8a"
        self.pushed_files: list[tuple[Path, str]] = []
        self.root_commands: list[str] = []

    def get_device_property(self, device_serial: str, property_name: str) -> str:
        if property_name == "ro.product.cpu.abi":
            return self.device_abi
        if property_name == "ro.dalvik.vm.native.bridge":
            return self.native_bridge
        return ""

    def get_package_primary_abi(
        self,
        device_serial: str,
        package_name: str,
    ) -> str:
        return self.package_abi

    def has_root(self, device_serial: str) -> bool:
        return self.is_root

    def is_package_debuggable(
        self,
        device_serial: str,
        package_name: str,
    ) -> bool:
        return self.is_debuggable

    def push_file(
        self,
        device_serial: str,
        local_path: Path,
        remote_path: str,
    ) -> None:
        self.pushed_files.append((local_path, remote_path))

    def run_root_shell(self, device_serial: str, command: str) -> str:
        self.root_commands.append(command)
        return ""

    def is_frida_server_running(self, device_serial: str) -> bool:
        return True


class FridaSetupControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.cache_directory = Path(self.temporary_directory.name) / "cache"
        self.adb_controller = FakeAdbController()
        self.frida_controller = mock.Mock()
        self.frida_controller.frida_executable = Path("frida")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _downloader(self, url: str, destination: Path) -> None:
        destination.write_bytes(lzma.compress(f"asset:{url}".encode()))

    def test_root_device_downloads_and_starts_server(self) -> None:
        controller = FridaSetupController(
            self.adb_controller,
            self.frida_controller,
            cache_directory=self.cache_directory,
            downloader=self._downloader,
        )
        with mock.patch.object(
            controller,
            "_read_frida_version",
            return_value="17.18.0",
        ), mock.patch("emudhra_mitm.frida_setup.time.sleep"):
            result = controller.prepare("emulator-5554", "com.example.app")

        self.assertTrue(result["ready"])
        self.assertEqual(result["mode"], "root")
        self.assertEqual(len(self.adb_controller.pushed_files), 1)
        self.assertEqual(
            self.adb_controller.pushed_files[0][1],
            "/data/local/tmp/frida-server-17.18.0-android-arm64",
        )
        self.assertTrue(
            any("nohup" in command for command in self.adb_controller.root_commands)
        )
        stop_commands = [
            command
            for command in self.adb_controller.root_commands
            if "pkill -f" in command
        ]
        self.assertEqual(len(stop_commands), 1)
        self.assertIn("^/data/local/tmp/frida-server", stop_commands[0])
        stop_command_index = self.adb_controller.root_commands.index(
            stop_commands[0]
        )
        start_command_index = next(
            index
            for index, command in enumerate(self.adb_controller.root_commands)
            if "nohup" in command
        )
        self.assertLess(stop_command_index, start_command_index)

    def test_non_root_debuggable_app_prepares_gadget(self) -> None:
        self.adb_controller.is_root = False
        gadget_cache_path = (
            Path(self.temporary_directory.name) / "gadget-android-arm64.so"
        )
        controller = FridaSetupController(
            self.adb_controller,
            self.frida_controller,
            cache_directory=self.cache_directory,
            downloader=self._downloader,
        )
        with mock.patch.object(
            controller,
            "_read_frida_version",
            return_value="17.18.0",
        ), mock.patch.object(
            FridaSetupController,
            "_frida_gadget_cache_path",
            return_value=gadget_cache_path,
        ):
            result = controller.prepare("emulator-5554", "com.example.app")

        self.assertTrue(result["ready"])
        self.assertEqual(result["mode"], "gadget")
        self.assertTrue(gadget_cache_path.is_file())

    def test_rejects_arm_app_on_direct_native_bridge(self) -> None:
        self.adb_controller.device_abi = "x86_64"
        self.adb_controller.native_bridge = "libnb.so"
        self.adb_controller.package_abi = "arm64-v8a"
        controller = FridaSetupController(
            self.adb_controller,
            self.frida_controller,
            cache_directory=self.cache_directory,
            downloader=self._downloader,
        )
        with mock.patch.object(
            controller,
            "_read_frida_version",
            return_value="17.18.0",
        ):
            result = controller.prepare("emulator-5554", "com.example.app")

        self.assertFalse(result["ready"])
        self.assertEqual(result["mode"], "native-bridge")
        self.assertIn("SIGSEGV", result["message"])
        self.assertEqual(self.adb_controller.pushed_files, [])
        self.assertEqual(self.adb_controller.root_commands, [])

    def test_non_root_non_debuggable_app_is_rejected(self) -> None:
        self.adb_controller.is_root = False
        self.adb_controller.is_debuggable = False
        controller = FridaSetupController(
            self.adb_controller,
            self.frida_controller,
            cache_directory=self.cache_directory,
            downloader=self._downloader,
        )
        with mock.patch.object(
            controller,
            "_read_frida_version",
            return_value="17.18.0",
        ):
            result = controller.prepare("emulator-5554", "com.example.app")

        self.assertFalse(result["ready"])
        self.assertIn("重打包 APK", result["message"])


if __name__ == "__main__":
    unittest.main()
