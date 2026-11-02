"""pywebview 与代理 controller 之间的受控接口。"""

from __future__ import annotations

import contextlib
import datetime
import socket
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from emudhra_mitm import __version__
from emudhra_mitm.adb_controller import AdbController
from emudhra_mitm.app_paths import HOTSPOT_LOG_PATH
from emudhra_mitm.ca_catalog import discover_cas
from emudhra_mitm.config import ProxyConfig, format_host_port
from emudhra_mitm.frida_controller import FridaController
from emudhra_mitm.frida_setup import FridaSetupController
from emudhra_mitm.hotspot_controller import HotspotController, HotspotError
from emudhra_mitm.proxy_controller import ProxyController, WorkerStartError
from emudhra_mitm.settings_store import SettingsStore
from emudhra_mitm.socks5 import internal_http_proxy_host
from emudhra_mitm.transparent_controller import (
    TransparentBridgeController,
    TransparentBridgeStartError,
)


DEFAULT_TRANSPARENT_PORT = 28083
HOTSPOT_LOG_MAX_BYTES = 1024 * 1024


def append_hotspot_log(message: str) -> None:
    try:
        HOTSPOT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if (
            HOTSPOT_LOG_PATH.is_file()
            and HOTSPOT_LOG_PATH.stat().st_size >= HOTSPOT_LOG_MAX_BYTES
        ):
            rotated_path = Path(f"{HOTSPOT_LOG_PATH}.1")
            with contextlib.suppress(OSError):
                rotated_path.unlink()
            with contextlib.suppress(OSError):
                HOTSPOT_LOG_PATH.replace(rotated_path)
        timestamp = datetime.datetime.now().astimezone().isoformat(
            timespec="seconds"
        )
        with HOTSPOT_LOG_PATH.open("a", encoding="utf-8") as log_file:
            log_file.write(f"{timestamp} {message}\n")
    except OSError:
        pass


class WebviewApi:
    def __init__(
        self,
        cas_root: Path | None = None,
        controller_factory: Callable[[ProxyConfig], ProxyController] = ProxyController,
        settings_store: SettingsStore | None = None,
        frida_controller: FridaController | None = None,
        adb_controller: AdbController | None = None,
        frida_setup_controller: FridaSetupController | None = None,
        hotspot_controller: HotspotController | None = None,
        transparent_controller_factory: (
            Callable[..., TransparentBridgeController] | None
        ) = None,
    ) -> None:
        self.cas_root = cas_root
        self.controller_factory = controller_factory
        self.settings_store = settings_store or SettingsStore()
        self.frida_controller = frida_controller or FridaController()
        self.adb_controller = adb_controller or AdbController()
        self.frida_setup_controller = (
            frida_setup_controller
            or FridaSetupController(
                self.adb_controller,
                self.frida_controller,
            )
        )
        self.hotspot_controller = hotspot_controller or HotspotController()
        self.transparent_controller_factory = (
            transparent_controller_factory or TransparentBridgeController
        )
        initial_settings = self.settings_store.load()
        self._persisted_config = initial_settings.config
        self._lock = threading.RLock()
        self._controller: ProxyController | None = None
        self._config: ProxyConfig | None = None
        self._ready_event: dict[str, Any] | None = None
        self._last_stderr: list[str] = []
        self._hotspot_lock = threading.RLock()
        self._transparent_controller: TransparentBridgeController | None = None
        self._hotspot_started = False
        self._hotspot_proxy_started_here = False
        self._hotspot_ssid = ""
        self._hotspot_interface = ""
        self._hotspot_transparent_port = DEFAULT_TRANSPARENT_PORT
        self._hotspot_proxy_endpoint = ""
        self._last_hotspot_running = False

    def bootstrap(self) -> dict[str, Any]:
        try:
            ca_entries = discover_cas(self.cas_root)
        except (FileNotFoundError, OSError, ValueError) as error:
            return {"ok": False, "error": str(error)}

        loaded_settings = self.settings_store.load()
        self._persisted_config = loaded_settings.config
        result = {
            "ok": True,
            "version": __version__,
            "defaults": asdict(loaded_settings.config),
            "cas": [
                {
                    "name": entry.ca_name,
                    "cn": entry.info.get("CN", entry.ca_name),
                    "issuer": entry.info.get("issuer", ""),
                    "validity": entry.info.get("validity", ""),
                }
                for entry in ca_entries
            ],
        }
        if loaded_settings.warning:
            result["warning"] = loaded_settings.warning
        return result

    def start_proxy(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self._controller is not None and self._controller.is_running:
                return {"ok": False, "error": "代理已在运行"}

            try:
                config = self._proxy_config_from_payload(payload)
            except (TypeError, ValueError) as error:
                return {"ok": False, "error": str(error)}

            try:
                self._ensure_proxy_ports_available(config)
            except ValueError as error:
                return {"ok": False, "error": str(error)}

            controller = self.controller_factory(config)
            try:
                ready_event = controller.start()
            except (OSError, WorkerStartError, ValueError) as error:
                self._last_stderr = controller.stderr_text().splitlines()[-20:]
                controller.stop()
                return {"ok": False, "error": str(error)}

            self._controller = controller
            self._config = config
            self._ready_event = ready_event
            self._last_stderr = []
            result: dict[str, Any] = {
                "ok": True,
                "status": self._status_locked(),
            }
            try:
                self.settings_store.save(config)
                self._persisted_config = config
            except OSError as error:
                result["warning"] = f"代理已启动，但配置保存失败: {error}"
            return result

    def stop_proxy(self) -> dict[str, Any]:
        with self._lock:
            restore_errors = self.adb_controller.restore_all_http_proxies()
            controller = self._controller
            if controller is not None:
                controller.stop()
                self._last_stderr = controller.stderr_text().splitlines()[-20:]
                self._controller = None
            result = {"ok": True, "status": self._status_locked()}
            if restore_errors:
                result["warning"] = "部分设备代理恢复失败: " + "; ".join(
                    restore_errors
                )
            return result

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return self._status_locked()

    def get_frida_status(self) -> dict[str, Any]:
        return {
            "ok": True,
            **self.frida_controller.status(),
            "setup_progress": self.frida_setup_controller.progress(),
        }

    def start_frida(self, payload: dict[str, Any]) -> dict[str, Any]:
        device_id = str(payload.get("device_id", ""))
        package_name = str(payload.get("package_name", ""))
        if not device_id:
            return {"ok": False, "error": "请先选择 Android 设备"}

        preparation = None
        proxy_started_here = False
        device_proxy_applied = False
        try:
            preparation = self.frida_setup_controller.prepare(
                device_id,
                package_name,
            )
            if not preparation["ready"]:
                return {
                    "ok": False,
                    "error": preparation["message"],
                    "preparation": preparation,
                }

            with self._lock:
                proxy_is_running = (
                    self._controller is not None
                    and self._controller.is_running
                )
                if proxy_is_running and self._config is not None:
                    local_port = self._config.listen_port
                else:
                    local_port = self._proxy_config_from_payload(
                        payload
                    ).listen_port

            if not proxy_is_running:
                proxy_result = self.start_proxy(payload)
                if not proxy_result["ok"]:
                    return proxy_result
                proxy_started_here = True

            device_proxy = self.adb_controller.enable_http_proxy(
                device_id,
                local_port,
            )
            device_proxy_applied = True
            status = self.frida_controller.start(package_name, device_id)
        except (
            FileNotFoundError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as error:
            rollback_warning = self._rollback_frida_capture(
                device_id,
                proxy_started_here,
                device_proxy_applied,
            )
            result = {
                "ok": False,
                "error": str(error),
                "proxy_status": self.get_status(),
            }
            if preparation is not None:
                result["preparation"] = preparation
            if rollback_warning:
                result["warning"] = rollback_warning
            return result
        return {
            "ok": True,
            "status": status,
            "preparation": preparation,
            "proxy_status": self.get_status(),
            "device_proxy": device_proxy,
        }

    def stop_frida(self) -> dict[str, Any]:
        self.frida_controller.stop()
        return {"ok": True, "status": self.frida_controller.status()}

    def get_hotspot_status(self) -> dict[str, Any]:
        with self._hotspot_lock:
            return self._hotspot_status_locked()

    def start_hotspot(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._hotspot_lock:
            current_hotspot_status = self.hotspot_controller.status()
            if self._hotspot_started or current_hotspot_status.get("running"):
                return {
                    "ok": False,
                    "error": "热点透明转发已在运行",
                    "status": self._hotspot_status_locked(),
                }
            if self._transparent_controller is not None:
                try:
                    self._transparent_controller.stop()
                finally:
                    self._transparent_controller = None

            ssid = str(payload.get("ssid", "")).strip()
            password = str(payload.get("password", ""))
            interface = str(payload.get("interface", "")).strip()
            try:
                transparent_port = int(
                    payload.get(
                        "transparent_port",
                        DEFAULT_TRANSPARENT_PORT,
                    )
                )
                if not 1 <= transparent_port <= 65535:
                    raise ValueError("透明代理端口必须在 1 到 65535 之间")
                self._ensure_transparent_port_available(
                    transparent_port
                )
                self.hotspot_controller.validate_access_point(
                    ssid,
                    password,
                    interface,
                )
                self.hotspot_controller.preflight()
            except (
                HotspotError,
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
            ) as error:
                append_hotspot_log(f"热点预检失败: {error}")
                return {
                    "ok": False,
                    "error": str(error),
                    "status": self._hotspot_status_locked(),
                }

            proxy_started_here = False
            hotspot_started = False
            redirect_enabled = False
            transparent_controller: TransparentBridgeController | None = None
            try:
                proxy_is_running = self.get_status()["running"]
                if not proxy_is_running:
                    proxy_result = self.start_proxy(payload)
                    if not proxy_result["ok"]:
                        return proxy_result
                    proxy_started_here = True

                active_config = self._active_proxy_config(payload)
                self._validate_transparent_port(
                    transparent_port,
                    active_config,
                )
                hotspot_status = self.hotspot_controller.start_access_point(
                    ssid,
                    password,
                    interface,
                )
                hotspot_started = True
                actual_interface = str(
                    hotspot_status.get("interface", interface)
                )
                redirect_host = str(hotspot_status.get("address", ""))
                client_network = str(
                    hotspot_status.get("client_network", "")
                )
                if self.hotspot_controller.runtime_platform == "win32":
                    append_hotspot_log(
                        "Windows 热点启动结果: "
                        f"running={hotspot_status.get('running')}, "
                        f"interface={actual_interface}, "
                        "interface_guid="
                        f"{hotspot_status.get('interface_guid', '')}, "
                        f"address={redirect_host}"
                    )
                    if not redirect_host:
                        raise HotspotError("Windows 热点未返回本地网关地址")
                    if not client_network:
                        raise HotspotError(
                            "Windows 热点未识别客户端网段，"
                            "透明转发无法确定重定向范围"
                        )
                transparent_controller = (
                    self.transparent_controller_factory(
                        proxy_host=internal_http_proxy_host(
                            active_config.listen_host
                        ),
                        proxy_port=active_config.listen_port,
                        listen_host="0.0.0.0",
                        listen_port=transparent_port,
                        redirect_host=redirect_host,
                        client_network=client_network,
                        hotspot_if_index=int(
                            hotspot_status.get("interface_ifindex", 0) or 0
                        ),
                        dns_listen_ip=redirect_host,
                        dns_upstream_servers=list(
                            dict.fromkeys(
                                self.hotspot_controller.windows_dns_servers()
                                + ["223.5.5.5", "119.29.29.29"]
                            )
                        ),
                    )
                )
                transparent_controller.start()
                self.hotspot_controller.enable_transparent_redirect(
                    actual_interface,
                    transparent_port,
                    client_network,
                )
                redirect_enabled = True
            except (
                HotspotError,
                OSError,
                RuntimeError,
                subprocess.TimeoutExpired,
                TransparentBridgeStartError,
                TypeError,
                ValueError,
            ) as error:
                append_hotspot_log(f"热点启动失败: {error}")
                rollback_warnings = self._rollback_hotspot_start(
                    transparent_controller,
                    hotspot_started,
                    proxy_started_here,
                    redirect_enabled,
                )
                result = {
                    "ok": False,
                    "error": str(error),
                    "status": self._hotspot_status_locked(),
                }
                if rollback_warnings:
                    result["warning"] = "; ".join(rollback_warnings)
                    append_hotspot_log(
                        "热点回滚警告: " + "; ".join(rollback_warnings)
                    )
                return result

            self._transparent_controller = transparent_controller
            self._hotspot_started = True
            self._hotspot_proxy_started_here = proxy_started_here
            self._hotspot_ssid = ssid
            self._hotspot_interface = actual_interface
            self._hotspot_transparent_port = transparent_port
            append_hotspot_log(
                f"热点已启动: ssid={ssid}, "
                f"address={redirect_host or actual_interface}, "
                f"port={transparent_port}"
            )
            return {
                "ok": True,
                "status": self._hotspot_status_locked(),
                "proxy_status": self.get_status(),
            }

    @staticmethod
    def _is_tcp_port_available(port: int) -> bool:
        probe_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe_socket.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False
        finally:
            probe_socket.close()

    @classmethod
    def _ensure_port_available(
        cls,
        port: int,
        label: str,
        stale_worker_cleanup: Callable[[], list[int]],
    ) -> None:
        if cls._is_tcp_port_available(port):
            return
        try:
            stale_worker_cleanup()
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            pass

        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if cls._is_tcp_port_available(port):
                return
            time.sleep(0.1)
        raise ValueError(
            f"{label}端口 {port} 已被其他进程占用，"
            "请关闭残留实例或更换端口"
        )

    @classmethod
    def _ensure_transparent_port_available(cls, port: int) -> None:
        cls._ensure_port_available(
            port,
            "透明",
            TransparentBridgeController.stop_stale_workers,
        )

    @classmethod
    def _ensure_proxy_ports_available(cls, config: ProxyConfig) -> None:
        existing_ports = [
            port
            for port in (config.listen_port, config.socks_port)
            if not cls._is_tcp_port_available(port)
        ]
        if not existing_ports:
            return
        try:
            ProxyController.stop_stale_workers()
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            pass

        for port, label in (
            (config.listen_port, "HTTP 代理"),
            (config.socks_port, "SOCKS5 代理"),
        ):
            cls._ensure_port_available(
                port,
                label,
                lambda: [],
            )

    def stop_hotspot(self) -> dict[str, Any]:
        with self._hotspot_lock:
            warnings: list[str] = []
            current_hotspot = self.hotspot_controller.status()
            hotspot_should_stop = (
                self._hotspot_started
                or bool(current_hotspot.get("running"))
            )
            try:
                if (
                    self._transparent_controller is not None
                    or (
                        hotspot_should_stop
                        and self.hotspot_controller.runtime_platform != "win32"
                    )
                ):
                    self.hotspot_controller.disable_transparent_redirect()
            except (
                HotspotError,
                OSError,
                RuntimeError,
                subprocess.TimeoutExpired,
                ValueError,
            ) as error:
                warnings.append(f"移除透明重定向失败: {error}")

            if self._transparent_controller is not None:
                try:
                    self._transparent_controller.stop()
                except (OSError, RuntimeError) as error:
                    warnings.append(f"停止透明转发桥失败: {error}")
                finally:
                    self._transparent_controller = None

            if hotspot_should_stop:
                try:
                    self.hotspot_controller.stop_access_point()
                except (
                    HotspotError,
                    OSError,
                    RuntimeError,
                    subprocess.TimeoutExpired,
                    ValueError,
                ) as error:
                    warnings.append(f"停止热点失败: {error}")
                finally:
                    self._hotspot_started = False

            if self._hotspot_proxy_started_here:
                proxy_result = self.stop_proxy()
                if proxy_result.get("warning"):
                    warnings.append(str(proxy_result["warning"]))
                self._hotspot_proxy_started_here = False

            self._hotspot_ssid = ""
            self._hotspot_interface = ""
            self._hotspot_proxy_endpoint = ""
            result = {
                "ok": True,
                "status": self._hotspot_status_locked(),
                "proxy_status": self.get_status(),
            }
            if warnings:
                result["warning"] = "; ".join(warnings)
                append_hotspot_log(
                    "热点停止警告: " + "; ".join(warnings)
                )
            else:
                append_hotspot_log("热点已停止")
            return result

    def get_frida_command(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            command = self.frida_controller.command_text(
                str(payload.get("package_name", "")),
                str(payload.get("device_id", "")),
            )
        except ValueError as error:
            return {"ok": False, "error": str(error)}
        return {"ok": True, "command": command}

    def get_adb_status(self) -> dict[str, Any]:
        return {"ok": True, **self.adb_controller.status()}

    def list_android_packages(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            packages = self.adb_controller.list_packages(
                str(payload.get("device_serial", ""))
            )
        except (OSError, RuntimeError, ValueError) as error:
            return {"ok": False, "error": str(error)}
        return {"ok": True, "packages": packages}

    def connect_adb(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            output = self.adb_controller.connect(
                str(payload.get("endpoint", ""))
            )
        except (OSError, RuntimeError, ValueError) as error:
            return {"ok": False, "error": str(error)}
        return {
            "ok": True,
            "message": output,
            "status": self.adb_controller.status(),
        }

    def pair_and_connect_adb(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            output = self.adb_controller.pair_and_connect(
                str(payload.get("pairing_endpoint", "")),
                str(payload.get("pairing_code", "")),
                str(payload.get("device_endpoint", "")),
            )
        except (OSError, RuntimeError, ValueError) as error:
            return {"ok": False, "error": str(error)}
        return {
            "ok": True,
            "message": output["connect_output"],
            "pair_message": output["pair_output"],
            "status": self.adb_controller.status(),
        }

    def disconnect_adb(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            output = self.adb_controller.disconnect(
                str(payload.get("endpoint", ""))
            )
        except (OSError, RuntimeError, ValueError) as error:
            return {"ok": False, "error": str(error)}
        return {
            "ok": True,
            "message": output,
            "status": self.adb_controller.status(),
        }

    def set_adb_proxy(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            local_port = int(payload.get("local_port"))
            proxy = self.adb_controller.enable_http_proxy(
                str(payload.get("device_serial", "")),
                local_port,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            return {"ok": False, "error": str(error)}
        return {"ok": True, "proxy": proxy}

    def get_adb_proxy_status(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            proxy_value = self.adb_controller.get_http_proxy(
                str(payload.get("device_serial", ""))
            )
        except (OSError, RuntimeError, ValueError) as error:
            return {"ok": False, "error": str(error)}
        return {"ok": True, "proxy": proxy_value}

    def restore_adb_proxy(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            proxy = self.adb_controller.restore_http_proxy(
                str(payload.get("device_serial", ""))
            )
        except (OSError, RuntimeError, ValueError) as error:
            return {"ok": False, "error": str(error)}
        return {"ok": True, "proxy": proxy}

    def shutdown(self) -> None:
        self.stop_hotspot()
        self.adb_controller.restore_all_http_proxies()
        with self._lock:
            if self._controller is not None:
                self._controller.stop()
                self._controller = None
        self.frida_controller.shutdown()

    def _active_proxy_config(self, payload: dict[str, Any]) -> ProxyConfig:
        with self._lock:
            if self._controller is not None and self._config is not None:
                return self._config
        return self._proxy_config_from_payload(payload)

    @staticmethod
    def _validate_transparent_port(
        transparent_port: int,
        config: ProxyConfig,
    ) -> None:
        upstream_port = urlsplit(config.upstream).port
        occupied_ports = {
            config.listen_port,
            config.socks_port,
            upstream_port,
        }
        occupied_ports.discard(None)
        if transparent_port in occupied_ports:
            raise ValueError(
                "透明代理端口不能与 HTTP、SOCKS5 或上游代理端口相同"
            )

    def _rollback_hotspot_start(
        self,
        transparent_controller: TransparentBridgeController | None,
        hotspot_started: bool,
        proxy_started_here: bool,
        redirect_enabled: bool,
    ) -> list[str]:
        warnings: list[str] = []
        if redirect_enabled:
            try:
                self.hotspot_controller.disable_transparent_redirect()
            except (
                HotspotError,
                OSError,
                RuntimeError,
                subprocess.TimeoutExpired,
                ValueError,
            ) as error:
                warnings.append(f"移除透明重定向失败: {error}")

        if transparent_controller is not None:
            try:
                transparent_controller.stop()
            except (OSError, RuntimeError) as error:
                warnings.append(f"停止透明转发桥失败: {error}")

        if hotspot_started:
            try:
                self.hotspot_controller.stop_access_point()
            except (
                HotspotError,
                OSError,
                RuntimeError,
                subprocess.TimeoutExpired,
                ValueError,
            ) as error:
                warnings.append(f"停止热点失败: {error}")

        if proxy_started_here:
            proxy_result = self.stop_proxy()
            if proxy_result.get("warning"):
                warnings.append(str(proxy_result["warning"]))
        return warnings

    def _hotspot_status_locked(self) -> dict[str, Any]:
        hotspot_status = self.hotspot_controller.status()
        hotspot_running = bool(hotspot_status.get("running"))
        if self._last_hotspot_running and not hotspot_running:
            append_hotspot_log(
                "检测到 Windows 热点已从 On 变为 Off"
            )
        self._last_hotspot_running = hotspot_running
        transparent_status = (
            self._transparent_controller.status()
            if self._transparent_controller is not None
            else {
                "running": False,
                "listen_host": "0.0.0.0",
                "listen_port": self._hotspot_transparent_port,
                "proxy_host": "",
                "proxy_port": 0,
                "stderr": [],
            }
        )
        return {
            "ok": True,
            "hotspot": hotspot_status,
            "transparent": transparent_status,
            "connection_mode": "transparent",
            "client_proxy_endpoint": self._hotspot_proxy_endpoint,
            "ssid": self._hotspot_ssid,
            "interface": self._hotspot_interface,
            "transparent_port": self._hotspot_transparent_port,
        }

    @staticmethod
    def _proxy_config_from_payload(payload: dict[str, Any]) -> ProxyConfig:
        try:
            ca_name = str(payload.get("ca_name", ""))
            listen_host = str(payload.get("listen_host", ""))
            listen_port = int(payload.get("listen_port"))
            socks_port = int(payload.get("socks_port"))
            upstream = str(payload.get("upstream", ""))
        except (TypeError, ValueError) as error:
            raise ValueError("代理配置无效或缺少必要字段") from error
        return ProxyConfig(
            ca_name=ca_name,
            listen_host=listen_host,
            listen_port=listen_port,
            socks_port=socks_port,
            upstream=upstream,
            verify_upstream=False,
        )

    def _rollback_frida_capture(
        self,
        device_id: str,
        proxy_started_here: bool,
        device_proxy_applied: bool,
    ) -> str:
        if proxy_started_here:
            stop_result = self.stop_proxy()
            return str(stop_result.get("warning") or "")
        if not device_proxy_applied:
            return ""

        try:
            self.adb_controller.restore_http_proxy(device_id)
        except (OSError, RuntimeError, ValueError) as error:
            return f"恢复设备代理失败: {error}"
        return ""

    def _status_locked(self) -> dict[str, Any]:
        running = self._controller is not None and self._controller.is_running
        stderr_lines = list(self._last_stderr)
        if self._controller is not None:
            current_stderr = self._controller.stderr_text().splitlines()
            if current_stderr:
                stderr_lines = current_stderr[-20:]

        if self._config is None:
            config_payload = asdict(self._persisted_config)
            http_endpoint = format_host_port(
                config_payload["listen_host"],
                config_payload["listen_port"],
            )
            socks_endpoint = format_host_port(
                config_payload["listen_host"],
                config_payload["socks_port"],
            )
            upstream = config_payload["upstream"]
        else:
            config_payload = asdict(self._config)
            http_endpoint = format_host_port(
                self._config.listen_host,
                self._config.listen_port,
            )
            socks_endpoint = self._config.socks_endpoint
            upstream = self._config.upstream

        return {
            "ok": True,
            "running": running,
            "config": config_payload,
            "http_endpoint": http_endpoint,
            "socks_endpoint": socks_endpoint,
            "upstream": upstream,
            "ready_event": self._ready_event,
            "stderr": stderr_lines,
        }
