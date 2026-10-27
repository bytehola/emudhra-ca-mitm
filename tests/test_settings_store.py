from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from emudhra_mitm.config import ProxyConfig
from emudhra_mitm.settings_store import SCHEMA_VERSION, SettingsStore


class SettingsStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.settings_path = (
            Path(self.temporary_directory.name) / "config" / "settings.json"
        )
        self.store = SettingsStore(self.settings_path)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_missing_file_uses_defaults(self) -> None:
        loaded = self.store.load()
        self.assertEqual(loaded.config, ProxyConfig())
        self.assertIsNone(loaded.warning)

    def test_saves_and_reloads_config(self) -> None:
        config = ProxyConfig(
            ca_name="06-EM-DV-TLS-CA-G3B",
            listen_host="0.0.0.0",
            listen_port=18081,
            socks_port=18082,
            upstream="http://127.0.0.1:9001",
            verify_upstream=True,
        )
        self.store.save(config)

        loaded = self.store.load()
        self.assertEqual(loaded.config, config)
        self.assertIsNone(loaded.warning)
        self.assertIn(
            f'"schema_version": {SCHEMA_VERSION}',
            self.settings_path.read_text(encoding="utf-8"),
        )

    def test_corrupt_file_returns_defaults_with_warning(self) -> None:
        self.settings_path.parent.mkdir(parents=True)
        self.settings_path.write_text("{invalid", encoding="utf-8")

        loaded = self.store.load()
        self.assertEqual(loaded.config, ProxyConfig())
        self.assertIn("读取配置失败", loaded.warning)

    def test_invalid_config_returns_defaults_with_warning(self) -> None:
        self.settings_path.parent.mkdir(parents=True)
        self.settings_path.write_text(
            """
{
  "schema_version": 1,
  "ca_name": "01-EM-OV-TLS-CA-G3C",
  "listen_host": "127.0.0.1",
  "listen_port": 28081,
  "socks_port": 28082,
  "upstream": "http://127.0.0.1:9000",
  "verify_upstream": "false"
}
""".strip(),
            encoding="utf-8",
        )

        loaded = self.store.load()
        self.assertEqual(loaded.config, ProxyConfig())
        self.assertIn("配置内容无效", loaded.warning)


if __name__ == "__main__":
    unittest.main()
