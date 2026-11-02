"""按设备权限自动准备 frida-server 或 Gadget。"""

from __future__ import annotations

import lzma
import os
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from emudhra_mitm.adb_controller import AdbController
from emudhra_mitm.app_paths import FRIDA_CACHE_DIRECTORY
from emudhra_mitm.frida_controller import FridaController


ABI_MAPPING = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}
FRIDA_RELEASE_URL = "https://github.com/frida/frida/releases/download"
X86_ABIS = {"x86", "x86_64"}
ARM_ABI_PREFIX = "arm"


def native_bridge_incompatibility_message(
    device_abi: str,
    native_bridge: str,
    package_abi: str,
) -> str | None:
    if device_abi not in X86_ABIS:
        return None
    if not native_bridge or not package_abi.startswith(ARM_ABI_PREFIX):
        return None
    return (
        f"检测到 {device_abi} 设备通过 {native_bridge} 转译 "
        f"{package_abi} 应用。当前 Frida x86_64 Spawn 方式"
        "无法安全注入 ARM native 代码，继续执行会导致应用 SIGSEGV。"
        "请改用 ARM64 原生模拟器或 ARM64 真机；"
        "或者重打包 APK 并注入 Frida Gadget。"
    )


class FridaSetupController:
    def __init__(
        self,
        adb_controller: AdbController,
        frida_controller: FridaController,
        cache_directory: Path = FRIDA_CACHE_DIRECTORY,
        downloader: Callable[[str, Path], None] | None = None,
    ) -> None:
        self.adb_controller = adb_controller
        self.frida_controller = frida_controller
        self.cache_directory = cache_directory
        self.downloader = downloader or self._download_file
        self._lock = threading.RLock()
        self._progress: list[str] = []

    def prepare(self, device_serial: str, package_name: str) -> dict[str, Any]:
        with self._lock:
            self._progress.clear()
        self._log("读取 Frida 版本")
        version = self._read_frida_version()
        self._log("检测设备 ABI")
        abi = self.adb_controller.get_device_property(
            device_serial,
            "ro.product.cpu.abi",
        )
        architecture = ABI_MAPPING.get(abi)
        if architecture is None:
            raise RuntimeError(f"暂不支持 Android ABI: {abi}")
        self._log(f"Frida {version}, 设备 ABI {abi}")

        native_bridge = self.adb_controller.get_device_property(
            device_serial,
            "ro.dalvik.vm.native.bridge",
        )
        package_abi = ""
        if abi in X86_ABIS and native_bridge and package_name.strip():
            package_abi = self.adb_controller.get_package_primary_abi(
                device_serial,
                package_name,
            )
        incompatibility_message = native_bridge_incompatibility_message(
            abi,
            native_bridge,
            package_abi,
        )
        if incompatibility_message is not None:
            self._log("检测到不兼容的 Native Bridge 环境")
            return {
                "ready": False,
                "mode": "native-bridge",
                "version": version,
                "abi": abi,
                "native_bridge": native_bridge,
                "package_abi": package_abi,
                "message": incompatibility_message,
            }

        self._log("检测 root 权限；如有弹窗，请在手机上确认")
        if self.adb_controller.has_root(device_serial):
            self._log("检测到 root，准备 frida-server")
            server_path = self._download_frida_asset(
                version,
                f"frida-server-{version}-android-{architecture}.xz",
            )
            self._install_root_server(device_serial, server_path)
            return {
                "ready": True,
                "mode": "root",
                "version": version,
                "abi": abi,
                "message": "已下载并启动匹配版本的 frida-server",
            }

        self._log("未检测到 root，检查目标 App 是否可调试")
        if not package_name.strip():
            return {
                "ready": False,
                "mode": "gadget",
                "version": version,
                "abi": abi,
                "message": "设备没有 root，且没有选择目标 App",
            }
        if not self.adb_controller.is_package_debuggable(
            device_serial,
            package_name,
        ):
            return {
                "ready": False,
                "mode": "gadget",
                "version": version,
                "abi": abi,
                "message": (
                    "设备没有 root，目标 App 也不可调试。"
                    "需要重打包 APK 注入 Frida Gadget，"
                    "仅下载 Gadget 无法直接 spawn。"
                ),
            }

        self._log("目标 App 可调试，准备 Frida Gadget")
        gadget_path = self._download_frida_asset(
            version,
            f"frida-gadget-{version}-android-{architecture}.so.xz",
        )
        cache_path = self._frida_gadget_cache_path(architecture)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(gadget_path, cache_path)
        self._log("Frida Gadget 已准备到默认缓存")
        return {
            "ready": True,
            "mode": "gadget",
            "version": version,
            "abi": abi,
            "gadget_path": str(cache_path),
            "message": "已准备 Gadget；目标 App 必须保持可调试",
        }

    def _read_frida_version(self) -> str:
        executable = self.frida_controller.frida_executable
        if executable is None:
            raise FileNotFoundError("未找到 frida，请先安装 frida-tools 14+")
        completed = subprocess.run(
            [str(executable), "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
        version = completed.stdout.strip()
        if completed.returncode != 0 or not version:
            raise RuntimeError(
                completed.stderr.strip() or "无法读取 Frida 版本"
            )
        return version

    def progress(self) -> list[str]:
        with self._lock:
            return list(self._progress)

    def _log(self, message: str) -> None:
        with self._lock:
            self._progress.append(message)

    def _install_root_server(
        self,
        device_serial: str,
        server_path: Path,
    ) -> None:
        remote_path = f"/data/local/tmp/{server_path.name}"
        self._log(f"推送 {server_path.name} 到设备")
        self.adb_controller.push_file(device_serial, server_path, remote_path)
        quoted_remote_path = shlex.quote(remote_path)
        self._log("设置 frida-server 执行权限")
        self.adb_controller.run_root_shell(
            device_serial,
            f"chmod 755 {quoted_remote_path}",
        )
        self.adb_controller.run_root_shell(
            device_serial,
            # 锚定完整路径，避免 pkill -f 匹配并终止当前 ADB shell。
            f"pkill -f {shlex.quote('^/data/local/tmp/frida-server')} || true",
        )
        self._log("通过 root 启动 frida-server")
        self.adb_controller.run_root_shell(
            device_serial,
            (
                f"nohup {quoted_remote_path} -D "
                ">/dev/null 2>&1 </dev/null &"
            ),
        )
        time.sleep(1.5)
        if not self.adb_controller.is_frida_server_running(device_serial):
            raise RuntimeError(
                "frida-server 启动失败，请检查 root 授权和 SELinux 状态"
            )
        self._log("frida-server 已启动")

    def _download_frida_asset(
        self,
        version: str,
        asset_name: str,
    ) -> Path:
        self.cache_directory.mkdir(parents=True, exist_ok=True)
        output_name = asset_name.removesuffix(".xz")
        output_path = self.cache_directory / output_name
        if output_path.is_file() and output_path.stat().st_size > 0:
            self._log(f"使用缓存 {output_path.name}")
            return output_path

        archive_url = f"{FRIDA_RELEASE_URL}/{version}/{asset_name}"
        self._log(f"下载 {asset_name}，首次使用可能需要几分钟")
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=".frida-download-",
            suffix=".xz",
            dir=self.cache_directory,
        )
        os.close(file_descriptor)
        archive_path = Path(temporary_name)
        try:
            self.downloader(archive_url, archive_path)
            with lzma.open(archive_path, "rb") as source_file:
                with tempfile.NamedTemporaryFile(
                    prefix=".frida-output-",
                    dir=self.cache_directory,
                    delete=False,
                ) as output_file:
                    shutil.copyfileobj(source_file, output_file)
                    temporary_output_path = Path(output_file.name)
            os.replace(temporary_output_path, output_path)
            self._log(f"下载完成 {output_path.name}")
            return output_path
        finally:
            archive_path.unlink(missing_ok=True)

    @staticmethod
    def _download_file(url: str, destination: Path) -> None:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "emudhra-ca-mitm"},
        )
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                with destination.open("wb") as destination_file:
                    shutil.copyfileobj(response, destination_file)
        except (urllib.error.URLError, TimeoutError):
            proxy_handler = urllib.request.ProxyHandler(
                {
                    "http": "http://127.0.0.1:7890",
                    "https": "http://127.0.0.1:7890",
                }
            )
            proxy_opener = urllib.request.build_opener(proxy_handler)
            with proxy_opener.open(request, timeout=90) as response:
                with destination.open("wb") as destination_file:
                    shutil.copyfileobj(response, destination_file)

    @staticmethod
    def _frida_gadget_cache_path(architecture: str) -> Path:
        if os.name == "nt":
            local_app_data = os.environ.get("LOCALAPPDATA")
            if not local_app_data:
                raise RuntimeError("Windows 缺少 LOCALAPPDATA")
            cache_root = (
                Path(local_app_data)
                / "Microsoft"
                / "Windows"
                / "INetCache"
                / "frida"
            )
        else:
            cache_root = Path.home() / ".cache" / "frida"
        return cache_root / f"gadget-android-{architecture}.so"
