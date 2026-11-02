"""pywebview 桌面应用入口。"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Any

import webview

from emudhra_mitm.app_paths import (
    CONFIG_DIRECTORY,
    INSTANCE_LOCK_PATH,
    UI_PATH,
)
from emudhra_mitm.webview_api import WebviewApi


class ApplicationInstanceLock:
    def __init__(self) -> None:
        self.acquired = False
        self._windows_handle: Any | None = None
        self._lock_file: Any | None = None

    def __enter__(self) -> ApplicationInstanceLock:
        self.acquired = self._acquire()
        return self

    def __exit__(self, *_: Any) -> None:
        self._release()

    def _acquire(self) -> bool:
        if os.name == "nt":
            kernel32 = ctypes.windll.kernel32
            ctypes.set_last_error(0)
            handle = kernel32.CreateMutexW(
                None,
                False,
                "Local\\eMudhraMitmDesktop",
            )
            if not handle:
                raise OSError("无法创建单实例锁")
            self._windows_handle = handle
            return ctypes.get_last_error() != 183

        import fcntl

        CONFIG_DIRECTORY.mkdir(parents=True, exist_ok=True)
        self._lock_file = Path(INSTANCE_LOCK_PATH).open(
            "a+",
            encoding="ascii",
        )
        try:
            fcntl.flock(
                self._lock_file.fileno(),
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            return False
        return True

    def _release(self) -> None:
        if self._windows_handle is not None:
            ctypes.windll.kernel32.CloseHandle(self._windows_handle)
            self._windows_handle = None
        if self._lock_file is not None:
            self._lock_file.close()
            self._lock_file = None
        self.acquired = False


def show_already_running_message() -> None:
    message = "eMudhra MITM 已在运行，请关闭现有窗口后再启动。"
    if os.name == "nt":
        ctypes.windll.user32.MessageBoxW(
            None,
            message,
            "eMudhra MITM",
            0x40,
        )
    else:
        print(message, file=sys.stderr)


def main() -> int:
    if not UI_PATH.is_file():
        print(f"[!] 找不到界面文件: {UI_PATH}", file=sys.stderr)
        return 1

    with ApplicationInstanceLock() as instance_lock:
        if not instance_lock.acquired:
            show_already_running_message()
            return 0

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
            webview.start(
                debug=os.environ.get("EMUDHRA_WEBVIEW_DEBUG") == "1"
            )
        finally:
            api.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
