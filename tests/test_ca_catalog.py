from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from emudhra_mitm.ca_catalog import discover_cas, resolve_ca


class CaCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.cas_root = Path(self.temporary_directory.name)
        self.ca_directory = self.cas_root / "01-test-ca"
        self.ca_directory.mkdir()
        (self.ca_directory / "mitmproxy-ca.pem").write_text(
            "test bundle",
            encoding="utf-8",
        )
        (self.ca_directory / "INFO.txt").write_text(
            "CN : Test CA\nprivate d : 4\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_discovers_ca(self) -> None:
        entries = discover_cas(self.cas_root)
        self.assertEqual([entry.ca_name for entry in entries], ["01-test-ca"])
        self.assertEqual(entries[0].info["CN"], "Test CA")

    def test_resolves_ca(self) -> None:
        entry = resolve_ca("01-test-ca", self.cas_root)
        self.assertEqual(entry.bundle_path.name, "mitmproxy-ca.pem")

    def test_rejects_path_outside_cas_root(self) -> None:
        with self.assertRaises(ValueError):
            resolve_ca("../outside", self.cas_root)


if __name__ == "__main__":
    unittest.main()
