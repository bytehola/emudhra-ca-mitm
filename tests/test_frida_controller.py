from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from emudhra_mitm.frida_controller import FridaController


class FridaControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.script_path = Path(self.temporary_directory.name) / "script.js"
        self.script_path.write_text("console.log('loaded');\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_reports_available_tools(self) -> None:
        controller = FridaController(
            script_path=self.script_path,
            frida_executable=Path(sys.executable),
        )
        status = controller.status()
        self.assertTrue(status["available"])
        self.assertFalse(status["running"])

    def test_builds_command(self) -> None:
        controller = FridaController(
            script_path=self.script_path,
            frida_executable=Path(sys.executable),
        )
        command = controller.command_text("com.example.app")
        self.assertIn("-U -f com.example.app", command)
        self.assertIn(str(self.script_path), command)
        self.assertNotIn("--no-pause", command)
        self.assertIn("--exit-on-error", command)

        device_command = controller.command_text(
            "com.example.app",
            "emulator-5554",
        )
        self.assertIn("-D emulator-5554 -f com.example.app", device_command)

    def test_rejects_invalid_package(self) -> None:
        controller = FridaController(
            script_path=self.script_path,
            frida_executable=Path(sys.executable),
        )
        with self.assertRaises(ValueError):
            controller.command_text("not a package")


if __name__ == "__main__":
    unittest.main()
