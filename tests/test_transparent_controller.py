from __future__ import annotations

import io
import threading
import unittest
from unittest import mock

from emudhra_mitm.transparent_controller import (
    TransparentBridgeController,
    TransparentBridgeStartError,
)
from emudhra_mitm.worker_cleanup import parse_worker_pids


class TransparentBridgeControllerTests(unittest.TestCase):
    def test_collects_transparent_flow_statistics(self) -> None:
        controller = TransparentBridgeController(
            proxy_host="127.0.0.1",
            proxy_port=28081,
            listen_port=28083,
        )
        process = mock.Mock()
        process.stdout = io.StringIO(
            '{"event":"forward-flow","client":"192.168.137.52:41000",'
            '"destination":"example.com:443","synthetic_port":20000}\n'
            '{"event":"forward-ignored","client":"192.168.8.101:41001",'
            '"destination":"example.net:443"}\n'
            '{"event":"return-flow","synthetic_port":20000}\n'
        )

        controller._read_stdout(process)

        status = controller.status()
        self.assertEqual(status["forwarded_flows"], 1)
        self.assertEqual(status["ignored_flows"], 1)
        self.assertEqual(status["returned_flows"], 1)
        self.assertEqual(
            status["last_forward_flow"]["destination"],
            "example.com:443",
        )
        self.assertEqual(
            status["last_ignored_flow"]["client"],
            "192.168.8.101:41001",
        )

    def test_startup_error_stops_worker_process(self) -> None:
        controller = TransparentBridgeController(
            proxy_host="127.0.0.1",
            proxy_port=28081,
        )
        process = mock.Mock()
        process.poll.return_value = None

        def feed_startup_error() -> None:
            reader_process = mock.Mock()
            reader_process.stdout = io.StringIO(
                    '{"event": "startup-error", '
                    '"message": "WinDivert 不可用"}\n'
            )
            controller._read_stdout(reader_process)

        with mock.patch(
            "emudhra_mitm.transparent_controller.subprocess.Popen",
            return_value=process,
        ), mock.patch.object(
            controller,
            "_start_output_threads",
            side_effect=lambda: threading.Thread(
                target=feed_startup_error,
                daemon=True,
            ).start(),
        ):
            with self.assertRaises(TransparentBridgeStartError):
                controller.start(timeout=5.0)

        # startup-error 路径必须立即回收仍存活的 worker 进程。
        process.stdin.write.assert_called_once_with("stop\n")
        self.assertIsNone(controller._process)

    def test_parses_stale_worker_process_ids(self) -> None:
        process_ids = parse_worker_pids("1234\r\ninvalid\r\n5678\r\n")

        self.assertEqual(process_ids, [1234, 5678])

    def test_builds_worker_arguments(self) -> None:
        controller = TransparentBridgeController(
            proxy_host="127.0.0.1",
            proxy_port=28081,
            listen_host="0.0.0.0",
            listen_port=28083,
            redirect_host="192.168.137.1",
            client_network="192.168.137.0/24",
        )

        arguments = controller.worker_arguments()

        self.assertIn("emudhra_mitm.transparent_bridge", arguments)
        self.assertIn("--listen-port", arguments)
        self.assertIn("28083", arguments)
        self.assertIn("--proxy-port", arguments)
        self.assertIn("28081", arguments)
        self.assertIn("--redirect-host", arguments)
        self.assertIn("192.168.137.1", arguments)
        self.assertIn("--client-network", arguments)
        self.assertIn("192.168.137.0/24", arguments)


if __name__ == "__main__":
    unittest.main()
