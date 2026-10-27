"""pywebview 桌面应用入口。"""

from __future__ import annotations

import os
import sys

import webview

from emudhra_mitm.app_paths import UI_PATH
from emudhra_mitm.webview_api import WebviewApi


def main() -> int:
    if not UI_PATH.is_file():
        print(f"[!] 找不到界面文件: {UI_PATH}", file=sys.stderr)
        return 1

    api = WebviewApi()
    webview.create_window(
        "eMudhra MITM",
        url=str(UI_PATH),
        js_api=api,
        width=1000,
        height=700,
        resizable=False,
        zoomable=True,
        text_select=True,
        background_color="#ffffff",
    )
    try:
        webview.start(debug=os.environ.get("EMUDHRA_WEBVIEW_DEBUG") == "1")
    finally:
        api.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
