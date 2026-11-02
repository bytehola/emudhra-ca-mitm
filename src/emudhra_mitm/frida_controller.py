"""Android Frida 脚本进程管理。"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
from collections import deque
from pathlib import Path
from typing import Any

from emudhra_mitm.app_paths import FRIDA_SCRIPT_PATH


PACKAGE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
DEVICE_PATTERN = re.compile(r"^[A-Za-z0-9._:-]+$")
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class FridaController:
    def __init__(
        self,
        script_path: Path = FRIDA_SCRIPT_PATH,
        frida_executable: Path | None = None,
    ) -> None:
        self.script_path = script_path
        self.frida_executable = self._resolve_frida(frida_executable)
        self._lock = threading.RLock()
        self._process: subprocess.Popen[str] | None = None
        self._package_name = ""
        self._device_id = ""
        self._output_lines: deque[str] = deque(maxlen=300)
        self._reader_thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def status(self) -> dict[str, Any]:
        with self._lock:
            unavailable_reason = ""
            if self.frida_executable is None:
                unavailable_reason = "未找到 frida，请安装 frida-tools 14 或更高版本"
            elif not self.script_path.is_file():
                unavailable_reason = f"找不到 Frida 脚本: {self.script_path}"

            return {
                "available": not unavailable_reason,
                "unavailable_reason": unavailable_reason,
                "frida_path": (
                    str(self.frida_executable)
                    if self.frida_executable is not None
                    else ""
                ),
                "script_path": str(self.script_path),
                "running": self.is_running,
                "package_name": self._package_name,
                "device_id": self._device_id,
                "log": list(self._output_lines),
            }

    def command_text(self, package_name: str, device_id: str = "") -> str:
        normalized_package = self._validate_package(package_name)
        normalized_device = self._validate_device_id(device_id)
        device_arguments = (
            f"-D {normalized_device}" if normalized_device else "-U"
        )
        return (
            f'frida {device_arguments} -f {normalized_package} '
            f'-l "{self.script_path}" -q -t inf --exit-on-error'
        )

    def start(self, package_name: str, device_id: str = "") -> dict[str, Any]:
        normalized_package = self._validate_package(package_name)
        normalized_device = self._validate_device_id(device_id)
        with self._lock:
            if self.is_running:
                raise RuntimeError("Frida 已在运行")
            if self.frida_executable is None:
                raise FileNotFoundError(
                    "未找到 frida，请在当前 Python 环境安装 frida-tools"
                )
            if not self.script_path.is_file():
                raise FileNotFoundError(f"找不到 Frida 脚本: {self.script_path}")

            command = [
                str(self.frida_executable),
                *(
                    ["-D", normalized_device]
                    if normalized_device
                    else ["-U"]
                ),
                "-f",
                normalized_package,
                "-l",
                str(self.script_path),
                "-q",
                "-t",
                "inf",
                "--exit-on-error",
            ]
            environment = os.environ.copy()
            environment["PYTHONUTF8"] = "1"
            environment["PYTHONIOENCODING"] = "utf-8"
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

            self._output_lines.clear()
            self._package_name = normalized_package
            self._device_id = normalized_device
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=environment,
                creationflags=creation_flags,
            )
            self._reader_thread = threading.Thread(
                target=self._read_output,
                args=(self._process,),
                name="emudhra-frida-output",
                daemon=True,
            )
            self._reader_thread.start()
            return self.status()

    def stop(self) -> None:
        with self._lock:
            process = self._process
            if process is None:
                return

            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

            if process.stdin is not None:
                process.stdin.close()
            if self._reader_thread is not None:
                self._reader_thread.join(timeout=1)
                self._reader_thread = None
            if process.stdout is not None:
                process.stdout.close()

    def shutdown(self) -> None:
        self.stop()

    def _read_output(self, process: subprocess.Popen[str]) -> None:
        if process.stdout is None:
            return
        for raw_line in process.stdout:
            line = ANSI_ESCAPE_PATTERN.sub("", raw_line).rstrip()
            if line:
                with self._lock:
                    self._output_lines.append(line)

    @staticmethod
    def _validate_package(package_name: str) -> str:
        normalized_package = package_name.strip()
        if not PACKAGE_PATTERN.fullmatch(normalized_package):
            raise ValueError("请输入有效的 Android 包名，例如 com.example.app")
        return normalized_package

    @staticmethod
    def _validate_device_id(device_id: str) -> str:
        normalized_device = device_id.strip()
        if normalized_device and not DEVICE_PATTERN.fullmatch(normalized_device):
            raise ValueError("Android 设备序列号格式无效")
        return normalized_device

    @staticmethod
    def _resolve_frida(explicit_path: Path | None) -> Path | None:
        if explicit_path is not None:
            resolved_path = explicit_path.expanduser().resolve()
            return resolved_path if resolved_path.is_file() else None

        configured_path = os.environ.get("FRIDA_EXECUTABLE")
        if configured_path:
            candidate = Path(configured_path).expanduser().resolve()
            if candidate.is_file():
                return candidate

        executable_name = "frida.exe" if os.name == "nt" else "frida"
        environment_frida = Path(sys.executable).with_name(executable_name)
        if environment_frida.is_file():
            return environment_frida

        discovered_frida = shutil.which("frida")
        return Path(discovered_frida).resolve() if discovered_frida else None
