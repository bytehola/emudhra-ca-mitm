from __future__ import annotations

import unittest

from emudhra_mitm.config import (
    ConfigurationError,
    ProxyConfig,
    normalize_upstream,
)


class ProxyConfigTests(unittest.TestCase):
    def test_uses_expected_defaults(self) -> None:
        config = ProxyConfig()
        self.assertEqual(config.listen_host, "0.0.0.0")
        self.assertFalse(config.verify_upstream)

    def test_normalizes_upstream(self) -> None:
        self.assertEqual(
            normalize_upstream("HTTP://127.0.0.1:9000/"),
            "http://127.0.0.1:9000",
        )
        self.assertEqual(
            normalize_upstream("https://proxy.example"),
            "https://proxy.example:443",
        )

    def test_formats_ipv6_upstream(self) -> None:
        self.assertEqual(
            normalize_upstream("http://[::1]:9000"),
            "http://[::1]:9000",
        )

    def test_rejects_invalid_upstream(self) -> None:
        for upstream in (
            "socks5://127.0.0.1:9000",
            "http://",
            "http://127.0.0.1:9000/path",
            "http://user:password@127.0.0.1:9000",
        ):
            with self.subTest(upstream=upstream):
                with self.assertRaises(ConfigurationError):
                    normalize_upstream(upstream)

    def test_rejects_proxy_loop(self) -> None:
        with self.assertRaises(ConfigurationError):
            ProxyConfig(
                listen_host="127.0.0.1",
                listen_port=9000,
                socks_port=28082,
                upstream="http://127.0.0.1:9000",
            )

    def test_rejects_socks_port_conflicts(self) -> None:
        with self.assertRaises(ConfigurationError):
            ProxyConfig(
                listen_port=28081,
                socks_port=28081,
            )
        with self.assertRaises(ConfigurationError):
            ProxyConfig(
                socks_port=9000,
                upstream="http://127.0.0.1:9000",
            )

    def test_builds_upstream_mode(self) -> None:
        config = ProxyConfig(
            listen_host="127.0.0.1",
            listen_port=28081,
            socks_port=28082,
            upstream="http://127.0.0.1:9000",
        )
        self.assertEqual(
            config.mode_spec,
            "upstream:http://127.0.0.1:9000@127.0.0.1:28081",
        )
        self.assertEqual(config.socks_endpoint, "127.0.0.1:28082")


if __name__ == "__main__":
    unittest.main()
