from __future__ import annotations

import unittest
from types import SimpleNamespace

from emudhra_mitm.streaming import StreamingForwarder


class StreamingForwarderTests(unittest.TestCase):
    def test_streams_request_and_response(self) -> None:
        flow = SimpleNamespace(
            request=SimpleNamespace(stream=False),
            response=SimpleNamespace(stream=False),
        )
        addon = StreamingForwarder()

        addon.requestheaders(flow)
        addon.responseheaders(flow)

        self.assertTrue(flow.request.stream)
        self.assertTrue(flow.response.stream)


if __name__ == "__main__":
    unittest.main()
