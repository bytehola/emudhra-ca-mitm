"""管理独立运行的热点透明转发桥进程。"""

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

from emudhra_mitm.worker_cleanup import stop_stale_workers


class TransparentBridgeStartError(RuntimeError):
    """透明转发桥未能启动。"""


class TransparentBridgeController:
    def __init__(
        self,
        proxy_host: str,
        proxy_port: int,
        listen_host: str = "0.0.0.0",
        listen_port: int = 28083,
        redirect_host: str = "",
        client_network: str = "",
        hotspot_if_index: int = 0,
        dns_listen_ip: str = "",
        dns_upstream_servers: list[str] | None = None,
        python_executable: Path | None = None,
    ) -> None:
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.redirect_host = redirect_host
        self.client_network = client_network
        self.hotspot_if_index = hotspot_if_index
        self.dns_listen_ip = dns_listen_ip
        self.dns_upstream_servers = list(dns_upstream_servers or [])
        self.python_executable = python_executable or Path(sys.executable)
        self._process: subprocess.Popen[str] | None = None
        self._events: queue.Queue[dict[str, Any]] = queue.Queue()
        self._stderr_lines: deque[str] = deque(maxlen=200)
        self._output_threads: list[threading.Thread] = []
        self._ready_event: dict[str, Any] | None = None
        self._stats_lock = threading.Lock()
        self._forward_flow_count = 0
        self._ignored_flow_count = 0
        self._return_flow_count = 0
        self._last_forward_flow: dict[str, Any] | None = None
        self._last_ignored_flow: dict[str, Any] | None = None

    def worker_arguments(self) -> list[str]:
        arguments = [
            str(self.python_executable),
            "-X",
            "utf8",
            "-m",
            "emudhra_mitm.transparent_bridge",
            "--listen-host",
            self.listen_host,
            "--listen-port",
            str(self.listen_port),
            "--proxy-host",
            self.proxy_host,
            "--proxy-port",
            str(self.proxy_port),
        ]
        if self.redirect_host:
            arguments.extend(
                ["--redirect-host", self.redirect_host]
            )
        if self.client_network:
            arguments.extend(
                ["--client-network", self.client_network]
            )
        if self.hotspot_if_index:
            arguments.extend(
                ["--hotspot-ifindex", str(self.hotspot_if_index)]
            )
        if self.dns_listen_ip and self.dns_upstream_servers:
            arguments.extend(
                [
                    "--dns-listen-ip",
                    self.dns_listen_ip,
                    "--dns-upstream",
                    ",".join(self.dns_upstream_servers),
                ]
            )
        return arguments

    @staticmethod
    def stop_stale_workers() -> list[int]:
        return stop_stale_workers(("emudhra_mitm.transparent_bridge",))

    def start(self, timeout: float = 15.0) -> dict[str, Any]:
        if self.is_running:
            raise TransparentBridgeStartError("透明转发桥已在运行")

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
        self._ready_event = None
        with self._stats_lock:
            self._forward_flow_count = 0
            self._ignored_flow_count = 0
            self._return_flow_count = 0
            self._last_forward_flow = None
            self._last_ignored_flow = None
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
                self._ready_event = event
                return event
            if event.get("event") == "startup-error":
                message = str(event.get("message", "透明转发桥启动失败"))
                self.stop()
                raise TransparentBridgeStartError(message)

        if self._process.poll() is not None:
            error_output = self.stderr_text().strip()
            self.stop()
            raise TransparentBridgeStartError(
                error_output or "透明转发桥在就绪前退出"
            )

        self.stop()
        raise TransparentBridgeStartError("等待透明转发桥就绪超时")

    def _start_output_threads(self) -> None:
        process = self._require_process()
        stdout_thread = threading.Thread(
            target=self._read_stdout,
            args=(process,),
            name="emudhra-transparent-stdout",
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=self._read_stderr,
            args=(process,),
            name="emudhra-transparent-stderr",
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        self._output_threads = [stdout_thread, stderr_thread]

    def _read_stdout(self, process: subprocess.Popen[str]) -> None:
        if process.stdout is None:
            return
        for raw_line in process.stdout:
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                event = {"event": "output", "message": line}
            if not isinstance(event, dict):
                event = {"event": "output", "message": line}
            event_name = event.get("event")
            if event_name == "forward-flow":
                with self._stats_lock:
                    self._forward_flow_count += 1
                    self._last_forward_flow = event
                continue
            if event_name == "return-flow":
                with self._stats_lock:
                    self._return_flow_count += 1
                continue
            if event_name == "forward-ignored":
                with self._stats_lock:
                    self._ignored_flow_count += 1
                    self._last_ignored_flow = event
                continue
            self._events.put(event)

    def _read_stderr(self, process: subprocess.Popen[str]) -> None:
        if process.stderr is None:
            return
        for line in process.stderr:
            self._stderr_lines.append(line.rstrip())

    def _require_process(self) -> subprocess.Popen[str]:
        if self._process is None:
            raise RuntimeError("透明转发桥尚未启动")
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
        self._process = None

    def stderr_text(self) -> str:
        return "\n".join(self._stderr_lines)

    def status(self) -> dict[str, Any]:
        with self._stats_lock:
            forwarded_flows = self._forward_flow_count
            ignored_flows = self._ignored_flow_count
            returned_flows = self._return_flow_count
            last_forward_flow = self._last_forward_flow
            last_ignored_flow = self._last_ignored_flow
        return {
            "running": self.is_running,
            "listen_host": self.listen_host,
            "listen_port": self.listen_port,
            "proxy_host": self.proxy_host,
            "proxy_port": self.proxy_port,
            "redirect_host": self.redirect_host,
            "client_network": self.client_network,
            "dns_listen_ip": self.dns_listen_ip,
            "dns_upstream_servers": self.dns_upstream_servers,
            "forwarded_flows": forwarded_flows,
            "ignored_flows": ignored_flows,
            "returned_flows": returned_flows,
            "last_forward_flow": last_forward_flow,
            "last_ignored_flow": last_ignored_flow,
            "ready_event": self._ready_event,
            "stderr": self.stderr_text().splitlines()[-20:],
        }
