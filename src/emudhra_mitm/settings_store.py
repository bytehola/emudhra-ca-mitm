"""代理配置的本地 JSON 持久化。"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from emudhra_mitm.app_paths import SETTINGS_PATH
from emudhra_mitm.config import ProxyConfig


SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class LoadedSettings:
    config: ProxyConfig
    warning: str | None = None


class SettingsStore:
    def __init__(self, settings_path: Path = SETTINGS_PATH) -> None:
        self.settings_path = settings_path

    def load(self) -> LoadedSettings:
        if not self.settings_path.is_file():
            return LoadedSettings(config=ProxyConfig())

        try:
            payload = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            return LoadedSettings(
                config=ProxyConfig(),
                warning=f"读取配置失败，已使用默认值: {error}",
            )

        if not isinstance(payload, dict):
            return LoadedSettings(
                config=ProxyConfig(),
                warning="配置文件格式无效，已使用默认值",
            )
        if payload.get("schema_version") != SCHEMA_VERSION:
            return LoadedSettings(
                config=ProxyConfig(),
                warning="配置文件版本不受支持，已使用默认值",
            )

        try:
            config = ProxyConfig(
                ca_name=self._required_string(payload, "ca_name"),
                listen_host=self._required_string(payload, "listen_host"),
                listen_port=self._required_integer(payload, "listen_port"),
                socks_port=self._required_integer(payload, "socks_port"),
                upstream=self._required_string(payload, "upstream"),
                verify_upstream=self._required_boolean(
                    payload,
                    "verify_upstream",
                ),
            )
        except (TypeError, ValueError) as error:
            return LoadedSettings(
                config=ProxyConfig(),
                warning=f"配置内容无效，已使用默认值: {error}",
            )

        return LoadedSettings(config=config)

    def save(self, config: ProxyConfig) -> None:
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": SCHEMA_VERSION,
            **asdict(config),
        }
        serialized_payload = json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        ) + "\n"

        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=".settings-",
            suffix=".json",
            dir=self.settings_path.parent,
            text=True,
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(
                file_descriptor,
                "w",
                encoding="utf-8",
                newline="\n",
            ) as temporary_file:
                temporary_file.write(serialized_payload)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, self.settings_path)
            if os.name != "nt":
                os.chmod(self.settings_path, 0o600)
        finally:
            temporary_path.unlink(missing_ok=True)

    @staticmethod
    def _required_string(payload: dict[str, Any], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str):
            raise TypeError(f"{key} 必须是字符串")
        return value

    @staticmethod
    def _required_integer(payload: dict[str, Any], key: str) -> int:
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{key} 必须是整数")
        return value

    @staticmethod
    def _required_boolean(payload: dict[str, Any], key: str) -> bool:
        value = payload.get(key)
        if not isinstance(value, bool):
            raise TypeError(f"{key} 必须是布尔值")
        return value
