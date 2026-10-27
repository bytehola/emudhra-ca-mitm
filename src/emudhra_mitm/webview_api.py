"""pywebview 与代理 controller 之间的受控接口。"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from emudhra_mitm import __version__
from emudhra_mitm.adb_controller import AdbController
from emudhra_mitm.ca_catalog import discover_cas
from emudhra_mitm.config import ProxyConfig, format_host_port
from emudhra_mitm.frida_controller import FridaController
from emudhra_mitm.frida_setup import FridaSetupController
from emudhra_mitm.proxy_controller import ProxyController, WorkerStartError
from emudhra_mitm.settings_store import SettingsStore


class WebviewApi:
    def __init__(
        self,
        cas_root: Path | None = None,
        controller_factory: Callable[[ProxyConfig], ProxyController] = ProxyController,
        settings_store: SettingsStore | None = None,
        frida_controller: FridaController | None = None,
        adb_controller: AdbController | None = None,
        frida_setup_controller: FridaSetupController | None = None,
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
        initial_settings = self.settings_store.load()
        self._persisted_config = initial_settings.config
        self._lock = threading.RLock()
        self._controller: ProxyController | None = None
        self._config: ProxyConfig | None = None
        self._ready_event: dict[str, Any] | None = None
        self._last_stderr: list[str] = []

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
                self._startup_warning = None
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
        self.adb_controller.restore_all_http_proxies()
        with self._lock:
            if self._controller is not None:
                self._controller.stop()
                self._controller = None
        self.frida_controller.shutdown()

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
