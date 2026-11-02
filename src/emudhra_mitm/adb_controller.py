"""内置 ADB 的设备和应用查询。"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from pyaxmlparser.arscparser import ARSCParser
from pyaxmlparser.arscutil import ARSCResTableConfig

from emudhra_mitm.app_paths import ADB_ROOT


ANDROID_PACKAGE_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$"
)
APP_LABEL_RESOURCE_PATTERN = re.compile(
    r"labelRes=(0x[0-9A-Fa-f]+)\s+"
    r"nonLocalizedLabel=(.*?)\s+icon="
)
MAX_LABEL_RESOLUTIONS_PER_REFRESH = 4
APP_LABEL_RESOURCE_NAMES = {"app_name", "application_name"}

logging.getLogger("pyaxmlparser").setLevel(logging.ERROR)


class AdbController:
    def __init__(
        self,
        adb_executable: Path | None = None,
        adb_root: Path = ADB_ROOT,
        command_timeout: float = 15.0,
    ) -> None:
        self.command_timeout = command_timeout
        self.adb_executable, self._resolution_error = self._resolve_adb(
            adb_executable,
            adb_root,
        )
        self._proxy_sessions: dict[str, tuple[str, int]] = {}
        self._app_label_cache: dict[tuple[str, str, str, str], str] = {}

    def status(self) -> dict[str, Any]:
        if self.adb_executable is None:
            return {
                "available": False,
                "adb_path": "",
                "version": "",
                "devices": [],
                "error": self._resolution_error,
            }

        try:
            version = self._read_version()
            devices = self.list_devices()
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            return {
                "available": True,
                "adb_path": str(self.adb_executable),
                "version": "",
                "devices": [],
                "error": str(error),
            }

        return {
            "available": True,
            "adb_path": str(self.adb_executable),
            "version": version,
            "devices": devices,
            "error": "",
        }

    def list_devices(self) -> list[dict[str, str]]:
        completed = self._run(("devices", "-l"))
        devices: list[dict[str, str]] = []
        for raw_line in completed.stdout.splitlines():
            line = raw_line.strip()
            if (
                not line
                or line.startswith("List of devices")
                or line.startswith("*")
            ):
                continue

            fields = line.split()
            if len(fields) < 2:
                continue
            device = {
                "serial": fields[0],
                "state": fields[1],
                "product": "",
                "model": "",
                "device": "",
            }
            for field in fields[2:]:
                key, separator, value = field.partition(":")
                if separator and key in device:
                    device[key] = value
            devices.append(device)
        return devices

    def list_packages(self, device_serial: str = "") -> list[dict[str, str]]:
        target_serial = self._select_device(device_serial)
        completed = self._run(
            (
                "-s",
                target_serial,
                "shell",
                "pm",
                "list",
                "packages",
                "-3",
                "-f",
                "--show-versioncode",
            )
        )
        package_records: list[dict[str, str]] = []
        for raw_line in completed.stdout.splitlines():
            line = raw_line.strip()
            if not line.startswith("package:"):
                continue

            package_details = line.removeprefix("package:")
            package_details, _, version_details = package_details.partition(" ")
            apk_path, separator, package_name = package_details.rpartition("=")
            if not separator:
                apk_path = ""
                package_name = package_details
            package_name = package_name.strip()
            if not package_name:
                continue

            version_code = version_details.removeprefix("versionCode:").strip()
            package_records.append(
                {
                    "package_name": package_name,
                    "apk_path": apk_path.strip(),
                    "version_code": version_code,
                }
            )

        package_records.sort(key=lambda record: record["package_name"].casefold())
        labels = self._resolve_package_labels(target_serial, package_records)
        packages = [
            {
                "package_name": record["package_name"],
                "label": labels.get(
                    record["package_name"],
                    record["package_name"],
                ),
            }
            for record in package_records
        ]
        return sorted(
            packages,
            key=lambda package: (
                package["label"].casefold(),
                package["package_name"].casefold(),
            ),
        )

    def _resolve_package_labels(
        self,
        device_serial: str,
        package_records: list[dict[str, str]],
    ) -> dict[str, str]:
        labels: dict[str, str] = {}
        unresolved_records: list[dict[str, str]] = []
        for record in package_records:
            cache_key = self._app_label_cache_key(device_serial, record)
            cached_label = self._app_label_cache.get(cache_key)
            if cached_label:
                labels[record["package_name"]] = cached_label
            else:
                unresolved_records.append(record)

        if not unresolved_records:
            return labels

        try:
            common_labels = self._lookup_common_app_labels(
                device_serial,
                [record["package_name"] for record in unresolved_records],
            )
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            common_labels = {}
        remaining_records: list[dict[str, str]] = []
        for record in unresolved_records:
            package_name = record["package_name"]
            common_label = common_labels.get(package_name, "")
            if common_label:
                cache_key = self._app_label_cache_key(device_serial, record)
                self._app_label_cache[cache_key] = common_label
                labels[package_name] = common_label
            else:
                remaining_records.append(record)

        for record in remaining_records[:MAX_LABEL_RESOLUTIONS_PER_REFRESH]:
            package_name = record["package_name"]
            try:
                resolved_label = self._resolve_package_label(
                    device_serial,
                    package_name,
                    record["apk_path"],
                )
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                continue
            label = resolved_label or package_name
            cache_key = self._app_label_cache_key(device_serial, record)
            self._app_label_cache[cache_key] = label
            labels[package_name] = label

        return labels

    def _lookup_common_app_labels(
        self,
        device_serial: str,
        package_names: list[str],
    ) -> dict[str, str]:
        if not package_names:
            return {}

        quoted_package_names = " ".join(
            shlex.quote(package_name)
            for package_name in package_names
        )
        command = (
            f"for package_name in {quoted_package_names}; do "
            'label=$(cmd overlay lookup "$package_name" '
            '"$package_name:string/app_name" 2>/dev/null); '
            'if [ -z "$label" ]; then '
            'label=$(cmd overlay lookup "$package_name" '
            '"$package_name:string/application_name" 2>/dev/null); '
            "fi; "
            'printf \'%s\\t%s\\n\' "$package_name" "$label"; '
            "done"
        )
        completed = self._run(
            ("-s", device_serial, "shell", command),
            check=False,
        )
        labels: dict[str, str] = {}
        for raw_line in completed.stdout.splitlines():
            package_name, separator, raw_label = raw_line.partition("\t")
            if not separator:
                continue
            label = self._normalize_app_label(raw_label)
            if package_name and label:
                labels[package_name] = label
        return labels

    def _resolve_package_label(
        self,
        device_serial: str,
        package_name: str,
        apk_path: str,
    ) -> str:
        completed = self._run(
            (
                "-s",
                device_serial,
                "shell",
                "cmd",
                "package",
                "resolve-activity",
                "-a",
                "android.intent.action.MAIN",
                "-c",
                "android.intent.category.LAUNCHER",
                package_name,
            ),
            check=False,
        )
        match = APP_LABEL_RESOURCE_PATTERN.search(completed.stdout)
        if match is None:
            return ""

        non_localized_label = self._normalize_app_label(match.group(2))
        if non_localized_label:
            return non_localized_label
        if not apk_path:
            return ""

        label_resource_id = int(match.group(1), 16)
        resource_table = self._read_resource_table(device_serial, apk_path)
        if not resource_table:
            return ""

        try:
            resource_parser = ARSCParser(resource_table)
            resource_name = resource_parser.get_resource_xml_name(
                label_resource_id,
                package_name,
            )
            if resource_name.startswith("@string/"):
                label = self._lookup_string_resource(
                    device_serial,
                    package_name,
                    resource_name.removeprefix("@string/"),
                )
                if label:
                    return label

            resolved_values = resource_parser.get_resolved_res_configs(
                label_resource_id,
                ARSCResTableConfig.default_config(),
            )
            for _, resolved_value in resolved_values:
                label = self._normalize_app_label(str(resolved_value))
                if label:
                    return label
        except Exception:
            # APP 的资源表格式差异较大，解析失败时回退到包名。
            return ""
        return ""

    def _lookup_string_resource(
        self,
        device_serial: str,
        package_name: str,
        resource_name: str,
    ) -> str:
        completed = self._run(
            (
                "-s",
                device_serial,
                "shell",
                "cmd",
                "overlay",
                "lookup",
                package_name,
                f"{package_name}:string/{resource_name}",
            ),
            check=False,
        )
        if completed.returncode != 0:
            return ""
        return self._normalize_app_label(completed.stdout)

    def _read_resource_table(
        self,
        device_serial: str,
        apk_path: str,
    ) -> bytes:
        completed = self._run_bytes(
            (
                "-s",
                device_serial,
                "exec-out",
                "unzip",
                "-p",
                apk_path,
                "resources.arsc",
            ),
            check=False,
        )
        if completed.returncode != 0:
            return b""
        return completed.stdout

    @staticmethod
    def _app_label_cache_key(
        device_serial: str,
        package_record: dict[str, str],
    ) -> tuple[str, str, str, str]:
        return (
            device_serial,
            package_record["package_name"],
            package_record["apk_path"],
            package_record["version_code"],
        )

    @staticmethod
    def _normalize_app_label(raw_label: str) -> str:
        label = raw_label.strip().strip('"')
        if " -> " in label:
            label = label.rsplit(" -> ", 1)[1].strip()
        if (
            not label
            or label.casefold() == "null"
            or label.startswith("@")
            or label in APP_LABEL_RESOURCE_NAMES
        ):
            return ""
        return label

    def connect(self, endpoint: str) -> str:
        normalized_endpoint = self._validate_endpoint(endpoint)
        completed = self._run(("connect", normalized_endpoint))
        output = (completed.stdout or completed.stderr).strip()
        normalized_output = output.casefold()
        if (
            "connected to" not in normalized_output
            and "already connected" not in normalized_output
        ):
            raise RuntimeError(output or f"无法连接无线设备 {normalized_endpoint}")
        return output

    def pair(self, endpoint: str, pairing_code: str) -> str:
        normalized_endpoint = self._validate_endpoint(endpoint)
        normalized_code = pairing_code.strip()
        if not normalized_code.isdigit() or len(normalized_code) != 6:
            raise ValueError("无线 ADB 配对码必须是 6 位数字")

        completed = self._run(("pair", normalized_endpoint, normalized_code))
        output = (completed.stdout or completed.stderr).strip()
        if "successfully paired" not in output.casefold():
            raise RuntimeError(output or "无线 ADB 配对失败")
        return output

    def pair_and_connect(
        self,
        pairing_endpoint: str,
        pairing_code: str,
        device_endpoint: str,
    ) -> dict[str, str]:
        pair_output = self.pair(pairing_endpoint, pairing_code)
        connect_output = self.connect(device_endpoint)
        return {
            "pair_output": pair_output,
            "connect_output": connect_output,
        }

    def disconnect(self, endpoint: str = "") -> str:
        arguments = ["disconnect"]
        if endpoint.strip():
            arguments.append(self._validate_endpoint(endpoint))
        completed = self._run(tuple(arguments))
        return (completed.stdout or completed.stderr).strip()

    def get_http_proxy(self, device_serial: str) -> str:
        target_serial = self._select_device(device_serial)
        return self._read_http_proxy(target_serial)

    def enable_http_proxy(self, device_serial: str, local_port: int) -> dict[str, Any]:
        target_serial = self._select_device(device_serial)
        if not 1 <= local_port <= 65535:
            raise ValueError("代理端口必须在 1 到 65535 之间")

        existing_session = self._proxy_sessions.get(target_serial)
        if existing_session is None:
            previous_proxy = self._read_http_proxy(target_serial)
        else:
            previous_proxy, previous_port = existing_session
            if previous_port != local_port:
                self._run(
                    (
                        "-s",
                        target_serial,
                        "reverse",
                        "--remove",
                        f"tcp:{previous_port}",
                    ),
                    check=False,
                )
        reverse_port = f"tcp:{local_port}"
        self._run(
            ("-s", target_serial, "reverse", "--remove", reverse_port),
            check=False,
        )
        self._run(
            ("-s", target_serial, "reverse", reverse_port, reverse_port)
        )
        proxy_value = f"127.0.0.1:{local_port}"
        try:
            self._run(
                (
                    "-s",
                    target_serial,
                    "shell",
                    "settings",
                    "put",
                    "global",
                    "http_proxy",
                    proxy_value,
                )
            )
        except (OSError, RuntimeError):
            self._run(
                ("-s", target_serial, "reverse", "--remove", reverse_port),
                check=False,
            )
            raise

        self._proxy_sessions[target_serial] = (previous_proxy, local_port)
        return {
            "serial": target_serial,
            "proxy": proxy_value,
            "previous_proxy": previous_proxy,
        }

    def restore_http_proxy(self, device_serial: str) -> dict[str, Any]:
        target_serial = self._select_device(device_serial)
        previous_proxy, local_port = self._proxy_sessions.get(
            target_serial,
            ("", 0),
        )
        restore_value = previous_proxy or ":0"
        self._run(
            (
                "-s",
                target_serial,
                "shell",
                "settings",
                "put",
                "global",
                "http_proxy",
                restore_value,
            )
        )
        if local_port:
            self._run(
                (
                    "-s",
                    target_serial,
                    "reverse",
                    "--remove",
                    f"tcp:{local_port}",
                ),
                check=False,
            )
        self._proxy_sessions.pop(target_serial, None)
        return {
            "serial": target_serial,
            "proxy": "" if restore_value == ":0" else restore_value,
        }

    def restore_all_http_proxies(self) -> list[str]:
        errors: list[str] = []
        for device_serial in list(self._proxy_sessions):
            try:
                self.restore_http_proxy(device_serial)
            except (OSError, RuntimeError, ValueError) as error:
                errors.append(f"{device_serial}: {error}")
        return errors

    def get_device_property(self, device_serial: str, property_name: str) -> str:
        target_serial = self._select_device(device_serial)
        completed = self._run(
            ("-s", target_serial, "shell", "getprop", property_name)
        )
        return completed.stdout.strip()

    def get_package_primary_abi(
        self,
        device_serial: str,
        package_name: str,
    ) -> str:
        target_serial = self._select_device(device_serial)
        normalized_package = package_name.strip()
        if not ANDROID_PACKAGE_PATTERN.fullmatch(normalized_package):
            raise ValueError("Android 包名格式无效")

        completed = self._run(
            (
                "-s",
                target_serial,
                "shell",
                "dumpsys",
                "package",
                normalized_package,
            )
        )
        for raw_line in completed.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("primaryCpuAbi="):
                return line.partition("=")[2].strip()
        return ""

    def has_root(self, device_serial: str) -> bool:
        target_serial = self._select_device(device_serial)
        shell_identity = self._run(
            ("-s", target_serial, "shell", "id", "-u"),
            check=False,
        )
        if shell_identity.returncode == 0 and shell_identity.stdout.strip() == "0":
            return True

        root_identity = self._run(
            ("-s", target_serial, "shell", "su -c 'id -u'"),
            check=False,
        )
        return (
            root_identity.returncode == 0
            and root_identity.stdout.strip() == "0"
        )

    def is_package_debuggable(self, device_serial: str, package_name: str) -> bool:
        target_serial = self._select_device(device_serial)
        if not package_name.strip():
            return False
        completed = self._run(
            ("-s", target_serial, "shell", "run-as", package_name, "id"),
            check=False,
        )
        return completed.returncode == 0

    def push_file(self, device_serial: str, local_path: Path, remote_path: str) -> None:
        target_serial = self._select_device(device_serial)
        self._run(
            ("-s", target_serial, "push", str(local_path), remote_path)
        )

    def run_shell(self, device_serial: str, command: str) -> str:
        target_serial = self._select_device(device_serial)
        completed = self._run(
            ("-s", target_serial, "shell", command)
        )
        return completed.stdout.strip()

    def run_root_shell(self, device_serial: str, command: str) -> str:
        target_serial = self._select_device(device_serial)
        completed = self._run(
            (
                "-s",
                target_serial,
                "shell",
                f"su -c {shlex.quote(command)}",
            )
        )
        return completed.stdout.strip()

    def is_frida_server_running(self, device_serial: str) -> bool:
        target_serial = self._select_device(device_serial)
        completed = self._run(
            ("-s", target_serial, "shell", "ps", "-A"),
            check=False,
        )
        return any(
            "frida-server" in line
            for line in completed.stdout.splitlines()
        )

    def _select_device(self, requested_serial: str) -> str:
        devices = self.list_devices()
        if not devices:
            raise RuntimeError("未发现 Android 设备，请检查 USB 调试和连接")

        normalized_serial = requested_serial.strip()
        if normalized_serial:
            matching_devices = [
                device
                for device in devices
                if device["serial"] == normalized_serial
            ]
            if not matching_devices:
                raise RuntimeError("所选 Android 设备已断开")
            selected_device = matching_devices[0]
        elif len(devices) == 1:
            selected_device = devices[0]
        else:
            raise RuntimeError("检测到多个 Android 设备，请先选择设备")

        state = selected_device["state"]
        if state == "unauthorized":
            raise RuntimeError("设备未授权，请在手机上确认 USB 调试授权")
        if state != "device":
            raise RuntimeError(f"设备当前不可用: {state}")
        return selected_device["serial"]

    def _read_version(self) -> str:
        completed = self._run(("version",))
        for line in completed.stdout.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("Version "):
                return stripped_line
        return completed.stdout.splitlines()[0].strip() if completed.stdout else ""

    def _read_http_proxy(self, device_serial: str) -> str:
        completed = self._run(
            (
                "-s",
                device_serial,
                "shell",
                "settings",
                "get",
                "global",
                "http_proxy",
            )
        )
        proxy_value = completed.stdout.strip()
        if proxy_value.casefold() in {"", "null", ":0", "0.0.0.0:0"}:
            return ""
        return proxy_value

    @staticmethod
    def _validate_endpoint(endpoint: str) -> str:
        normalized_endpoint = endpoint.strip()
        if not normalized_endpoint:
            raise ValueError("无线设备地址不能为空")

        if normalized_endpoint.startswith("["):
            closing_bracket = normalized_endpoint.find("]")
            trailing_endpoint = normalized_endpoint[closing_bracket + 1 :]
            if closing_bracket <= 1 or not trailing_endpoint.startswith(":"):
                raise ValueError("无线设备地址格式应为 [IPv6]:端口")
            host = normalized_endpoint[1:closing_bracket]
            port_text = normalized_endpoint[closing_bracket + 2 :]
            try:
                ipaddress.IPv6Address(host)
            except ValueError as error:
                raise ValueError("无线 IPv6 地址无效") from error
        else:
            host, separator, port_text = normalized_endpoint.rpartition(":")
            if not separator or not host or ":" in host:
                raise ValueError("无线设备地址格式应为 主机:端口")
            if any(character.isspace() for character in host):
                raise ValueError("无线设备主机名不能包含空白字符")

        if not port_text.isdigit():
            raise ValueError("无线设备端口无效")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError("无线设备端口必须在 1 到 65535 之间")
        return (
            f"[{host}]:{port}"
            if normalized_endpoint.startswith("[")
            else f"{host}:{port}"
        )

    def _run(
        self,
        arguments: tuple[str, ...],
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        adb_executable = self.adb_executable
        if adb_executable is None:
            raise FileNotFoundError(self._resolution_error)

        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        environment = os.environ.copy()
        environment["PYTHONUTF8"] = "1"
        completed = subprocess.run(
            [str(adb_executable), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.command_timeout,
            check=False,
            env=environment,
            creationflags=creation_flags,
        )
        if check and completed.returncode != 0:
            error_output = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(error_output or f"adb 命令失败: {completed.returncode}")
        return completed

    def _run_bytes(
        self,
        arguments: tuple[str, ...],
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        adb_executable = self.adb_executable
        if adb_executable is None:
            raise FileNotFoundError(self._resolution_error)

        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        environment = os.environ.copy()
        environment["PYTHONUTF8"] = "1"
        completed = subprocess.run(
            [str(adb_executable), *arguments],
            capture_output=True,
            timeout=self.command_timeout,
            check=False,
            env=environment,
            creationflags=creation_flags,
        )
        if check and completed.returncode != 0:
            error_output = (
                completed.stderr or completed.stdout
            ).decode("utf-8", errors="replace").strip()
            raise RuntimeError(error_output or f"adb 命令失败: {completed.returncode}")
        return completed

    @staticmethod
    def _resolve_adb(
        explicit_path: Path | None,
        adb_root: Path,
    ) -> tuple[Path | None, str]:
        candidates: list[Path] = []
        if explicit_path is not None:
            candidates.append(explicit_path.expanduser())

        configured_path = os.environ.get("ADB_EXECUTABLE")
        if configured_path:
            candidates.append(Path(configured_path).expanduser())

        if os.name == "nt":
            candidates.append(adb_root / "windows" / "adb.exe")
        elif sys.platform.startswith("linux"):
            candidates.append(adb_root / "linux" / "adb")

        for candidate in candidates:
            resolved_path = candidate.resolve()
            if resolved_path.is_file():
                if os.name != "nt":
                    os.chmod(resolved_path, 0o755)
                return resolved_path, ""

        discovered_adb = shutil.which("adb")
        if discovered_adb:
            return Path(discovered_adb).resolve(), ""

        return None, "未找到内置或系统 adb"
