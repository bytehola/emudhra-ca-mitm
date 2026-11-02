from __future__ import annotations

import unittest
from unittest import mock

from emudhra_mitm import application


class ApplicationTests(unittest.TestCase):
    @mock.patch("emudhra_mitm.application.ApplicationInstanceLock")
    @mock.patch("emudhra_mitm.application.webview")
    @mock.patch("emudhra_mitm.application.WebviewApi")
    def test_creates_fixed_zoomable_window(
        self,
        webview_api_class: mock.Mock,
        webview_module: mock.Mock,
        instance_lock_class: mock.Mock,
    ) -> None:
        instance_lock_class.return_value.__enter__.return_value.acquired = True

        result = application.main()

        self.assertEqual(result, 0)
        window_options = webview_module.create_window.call_args.kwargs
        self.assertFalse(window_options["resizable"])
        self.assertTrue(window_options["zoomable"])
        self.assertTrue(window_options["text_select"])
        self.assertEqual(window_options["width"], 1000)
        self.assertEqual(window_options["height"], 700)
        webview_api_class.return_value.shutdown.assert_called_once()

    @mock.patch("emudhra_mitm.application.show_already_running_message")
    @mock.patch("emudhra_mitm.application.ApplicationInstanceLock")
    @mock.patch("emudhra_mitm.application.webview")
    def test_rejects_second_application_instance(
        self,
        webview_module: mock.Mock,
        instance_lock_class: mock.Mock,
        show_message: mock.Mock,
    ) -> None:
        instance_lock_class.return_value.__enter__.return_value.acquired = False

        result = application.main()

        self.assertEqual(result, 0)
        webview_module.create_window.assert_not_called()
        show_message.assert_called_once()


if __name__ == "__main__":
    unittest.main()
