from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from emudhra_mitm.adb_controller import AdbController


class AdbControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.adb_path = Path(self.temporary_directory.name) / "adb"
        self.adb_path.write_text("test executable", encoding="utf-8")
        self.adb_path.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_uses_bundled_adb(self) -> None:
        controller = AdbController()
        self.assertIsNotNone(controller.adb_executable)
        self.assertIn("vendor", str(controller.adb_executable))

    def test_reads_devices_and_version(self) -> None:
        controller = AdbController(adb_executable=self.adb_path)

        def fake_run(command, **kwargs):
            if command[-1] == "version":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=(
                        "Android Debug Bridge version 1.0.41\n"
                        "Version 37.0.1-15733141\n"
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "List of devices attached\n"
                    "emulator-5554\tdevice product:sdk model:Pixel device:generic\n"
                ),
                stderr="",
            )

        with mock.patch(
            "emudhra_mitm.adb_controller.subprocess.run",
            side_effect=fake_run,
        ):
            status = controller.status()

        self.assertTrue(status["available"])
        self.assertEqual(status["version"], "Version 37.0.1-15733141")
        self.assertEqual(status["devices"][0]["serial"], "emulator-5554")
        self.assertEqual(status["devices"][0]["model"], "Pixel")

    def test_lists_third_party_packages(self) -> None:
        controller = AdbController(adb_executable=self.adb_path)

        def fake_run(command, **kwargs):
            if "devices" in command:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=(
                        "List of devices attached\n"
                        "emulator-5554\tdevice product:sdk model:Pixel device:generic\n"
                    ),
                    stderr="",
                )
            if "pm" in command:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=(
                        "package:/data/app/example/second/base.apk="
                        "com.example.second versionCode:2\n"
                        "package:/data/app/example/first/base.apk="
                        "com.example.first versionCode:1\n"
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "com.example.second\tSecond App\n"
                    "com.example.first\tFirst App\n"
                ),
                stderr="",
            )

        with mock.patch(
            "emudhra_mitm.adb_controller.subprocess.run",
            side_effect=fake_run,
        ):
            packages = controller.list_packages("emulator-5554")

        self.assertEqual(
            packages,
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

    def test_reads_package_primary_abi(self) -> None:
        controller = AdbController(adb_executable=self.adb_path)

        def fake_run(command, **kwargs):
            if "devices" in command:
                output = (
                    "List of devices attached\n"
                    "emulator-5554\tdevice product:sdk model:Pixel device:generic\n"
                )
            else:
                output = (
                    "Packages:\n"
                    "  Package [com.example.app] (abc):\n"
                    "    primaryCpuAbi=arm64-v8a\n"
                )
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=output,
                stderr="",
            )

        with mock.patch(
            "emudhra_mitm.adb_controller.subprocess.run",
            side_effect=fake_run,
        ):
            package_abi = controller.get_package_primary_abi(
                "emulator-5554",
                "com.example.app",
            )

        self.assertEqual(package_abi, "arm64-v8a")

    def test_resolves_package_label_from_resource_table(self) -> None:
        controller = AdbController(adb_executable=self.adb_path)
        resolve_activity = subprocess.CompletedProcess(
            ["adb"],
            0,
            stdout=(
                "priority=0 preferredOrder=0\n"
                "labelRes=0x7f100fe8 nonLocalizedLabel=null icon=0x0\n"
            ),
            stderr="",
        )

        with mock.patch.object(
            controller,
            "_run",
            return_value=resolve_activity,
        ), mock.patch.object(
            controller,
            "_read_resource_table",
            return_value=b"resource-table",
        ), mock.patch(
            "emudhra_mitm.adb_controller.ARSCParser",
        ) as parser_type, mock.patch.object(
            controller,
            "_lookup_string_resource",
            return_value="微信",
        ):
            parser_type.return_value.get_resource_xml_name.return_value = (
                "@string/bap"
            )
            label = controller._resolve_package_label(
                "emulator-5554",
                "com.tencent.mm",
                "/data/app/base.apk",
            )

        self.assertEqual(label, "微信")

    def test_rejects_resource_names_as_application_labels(self) -> None:
        self.assertEqual(
            AdbController._normalize_app_label("app_name"),
            "",
        )
        self.assertEqual(
            AdbController._normalize_app_label("application_name"),
            "",
        )

    def test_rejects_unauthorized_device(self) -> None:
        controller = AdbController(adb_executable=self.adb_path)
        completed = subprocess.CompletedProcess(
            ["adb", "devices", "-l"],
            0,
            stdout=(
                "List of devices attached\n"
                "emulator-5554\tunauthorized\n"
            ),
            stderr="",
        )

        with mock.patch(
            "emudhra_mitm.adb_controller.subprocess.run",
            return_value=completed,
        ):
            with self.assertRaises(RuntimeError):
                controller.list_packages()

    def test_connects_and_pairs_wireless_device(self) -> None:
        controller = AdbController(adb_executable=self.adb_path)

        def fake_run(command, **kwargs):
            output = (
                "Successfully paired to 192.168.1.20:37123"
                if "pair" in command
                else "connected to 192.168.1.20:5555"
            )
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=output,
                stderr="",
            )

        with mock.patch(
            "emudhra_mitm.adb_controller.subprocess.run",
            side_effect=fake_run,
        ):
            result = controller.pair_and_connect(
                "192.168.1.20:37123",
                "123456",
                "192.168.1.20:5555",
            )

        self.assertIn("Successfully paired", result["pair_output"])
        self.assertIn("connected", result["connect_output"])

    def test_rejects_invalid_wireless_input(self) -> None:
        controller = AdbController(adb_executable=self.adb_path)
        with self.assertRaises(ValueError):
            controller.connect("192.168.1.20")
        with self.assertRaises(ValueError):
            controller.pair("192.168.1.20:37123", "123")

    def test_sets_and_restores_device_proxy(self) -> None:
        controller = AdbController(adb_executable=self.adb_path)
        commands: list[list[str]] = []

        def fake_run(command, **kwargs):
            commands.append(command)
            if "devices" in command:
                output = (
                    "List of devices attached\n"
                    "emulator-5554\tdevice product:sdk model:Pixel device:generic\n"
                )
            elif "get" in command:
                output = "192.168.1.9:8888\n"
            else:
                output = ""
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=output,
                stderr="",
            )

        with mock.patch(
            "emudhra_mitm.adb_controller.subprocess.run",
            side_effect=fake_run,
        ):
            enabled = controller.enable_http_proxy("emulator-5554", 28081)
            restored = controller.restore_http_proxy("emulator-5554")

        self.assertEqual(enabled["proxy"], "127.0.0.1:28081")
        self.assertEqual(enabled["previous_proxy"], "192.168.1.9:8888")
        self.assertEqual(restored["proxy"], "192.168.1.9:8888")
        self.assertTrue(
            any(
                command[-3:] == ["reverse", "tcp:28081", "tcp:28081"]
                for command in commands
            )
        )
        self.assertTrue(
            any(
                command[-4:]
                == ["put", "global", "http_proxy", "127.0.0.1:28081"]
                for command in commands
            )
        )

    def test_reapplying_proxy_preserves_original_value(self) -> None:
        controller = AdbController(adb_executable=self.adb_path)
        proxy_reads = 0

        def fake_run(command, **kwargs):
            nonlocal proxy_reads
            if "devices" in command:
                output = (
                    "List of devices attached\n"
                    "emulator-5554\tdevice product:sdk model:Pixel device:generic\n"
                )
            elif "get" in command:
                proxy_reads += 1
                output = "192.168.1.9:8888\n"
            else:
                output = ""
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=output,
                stderr="",
            )

        with mock.patch(
            "emudhra_mitm.adb_controller.subprocess.run",
            side_effect=fake_run,
        ):
            controller.enable_http_proxy("emulator-5554", 28081)
            controller.enable_http_proxy("emulator-5554", 28081)
            restored = controller.restore_http_proxy("emulator-5554")

        self.assertEqual(proxy_reads, 1)
        self.assertEqual(restored["proxy"], "192.168.1.9:8888")


if __name__ == "__main__":
    unittest.main()
