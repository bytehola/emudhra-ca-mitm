"""在主进程中管理独立代理 worker。"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from emudhra_mitm.config import ProxyConfig


class WorkerStartError(RuntimeError):
    """代理 worker 未能启动。"""


class ProxyController:
    def __init__(
        self,
        config: ProxyConfig,
        python_executable: Path | None = None,
    ) -> None:
        self.config = config
        self.python_executable = python_executable or Path(sys.executable)
        self._process: subprocess.Popen[str] | None = None
        self._events: queue.Queue[dict[str, Any]] = queue.Queue()
        self._stderr_lines: deque[str] = deque(maxlen=200)
        self._output_threads: list[threading.Thread] = []

    def worker_arguments(self) -> list[str]:
        arguments = [
            str(self.python_executable),
            "-X",
            "utf8",
            "-m",
            "emudhra_mitm.proxy_worker",
            "--ca-name",
            self.config.ca_name,
            "--listen-host",
            self.config.listen_host,
            "--listen-port",
            str(self.config.listen_port),
            "--socks-port",
            str(self.config.socks_port),
            "--upstream",
            self.config.upstream,
            "--control-stdin",
        ]
        if self.config.verify_upstream:
            arguments.append("--verify-upstream")
        return arguments

    def start(self, timeout: float = 15.0) -> dict[str, Any]:
        if self.is_running:
            raise WorkerStartError("代理 worker 已在运行")

        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        self._process = subprocess.Popen(
            self.worker_arguments(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creation_flags,
        )
        self._events = queue.Queue()
        self._stderr_lines.clear()
        self._start_output_threads()

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                event = self._events.get(timeout=0.1)
            except queue.Empty:
                if self._process.poll() is not None:
                    break
                continue

            if event.get("event") == "ready":
                return event
            if event.get("event") == "startup-error":
                raise WorkerStartError(str(event.get("message", "worker 启动失败")))

        if self._process.poll() is not None:
            error_output = "\n".join(self._stderr_lines).strip()
            self.stop()
            raise WorkerStartError(
                error_output or "代理 worker 在就绪前退出"
            )

        self.stop()
        raise WorkerStartError("等待代理 worker 就绪超时")

    def _start_output_threads(self) -> None:
        process = self._require_process()
        stdout_thread = threading.Thread(
            target=self._read_stdout,
            args=(process,),
            name="emudhra-worker-stdout",
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=self._read_stderr,
            args=(process,),
            name="emudhra-worker-stderr",
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        self._output_threads = [stdout_thread, stderr_thread]

    def _read_stdout(self, process: subprocess.Popen[str]) -> None:
        if process.stdout is None:
            return
        for line in process.stdout:
            stripped_line = line.strip()
            if not stripped_line:
                continue
            try:
                event = json.loads(stripped_line)
            except json.JSONDecodeError:
                event = {"event": "output", "message": stripped_line}
            if not isinstance(event, dict):
                event = {"event": "output", "message": stripped_line}
            self._events.put(event)

    def _read_stderr(self, process: subprocess.Popen[str]) -> None:
        if process.stderr is None:
            return
        for line in process.stderr:
            self._stderr_lines.append(line.rstrip())

    def _require_process(self) -> subprocess.Popen[str]:
        if self._process is None:
            raise RuntimeError("代理 worker 尚未启动")
        return self._process

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def stop(self, timeout: float = 5.0) -> None:
        process = self._process
        if process is None:
            return

        if process.poll() is None:
            try:
                if process.stdin is not None:
                    process.stdin.write("stop\n")
                    process.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

        if process.stdin is not None:
            process.stdin.close()
        for thread in self._output_threads:
            thread.join(timeout=1)
        self._output_threads.clear()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()

    def drain_events(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        while True:
            try:
                events.append(self._events.get_nowait())
            except queue.Empty:
                return events

    def stderr_text(self) -> str:
        return "\n".join(self._stderr_lines)
