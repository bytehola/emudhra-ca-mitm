from __future__ import annotations

import socket
import unittest

from emudhra_mitm.config import ProxyConfig
from emudhra_mitm.proxy_controller import ProxyController


def find_free_ports(port_count: int) -> list[int]:
    listeners: list[socket.socket] = []
    try:
        for _ in range(port_count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listeners.append(listener)
        return [listener.getsockname()[1] for listener in listeners]
    finally:
        for listener in listeners:
            listener.close()


class ProxyControllerTests(unittest.TestCase):
    def test_builds_worker_arguments(self) -> None:
        config = ProxyConfig()
        controller = ProxyController(config)
        arguments = controller.worker_arguments()
        self.assertIn("emudhra_mitm.proxy_worker", arguments)
        self.assertIn("--control-stdin", arguments)
        self.assertIn("http://127.0.0.1:9000", arguments)

    def test_starts_and_stops_worker(self) -> None:
        http_port, socks_port = find_free_ports(2)
        config = ProxyConfig(
            listen_host="127.0.0.1",
            listen_port=http_port,
            socks_port=socks_port,
            upstream="http://127.0.0.1:9",
        )
        controller = ProxyController(config)
        try:
            ready_event = controller.start()
            self.assertEqual(ready_event["event"], "ready")
            self.assertEqual(
                ready_event["socks_endpoint"],
                f"127.0.0.1:{config.socks_port}",
            )
            self.assertTrue(controller.is_running)
        finally:
            controller.stop()
        self.assertFalse(controller.is_running)
        for port in (config.listen_port, config.socks_port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                self.assertNotEqual(
                    client.connect_ex(("127.0.0.1", port)),
                    0,
                )


if __name__ == "__main__":
    unittest.main()
