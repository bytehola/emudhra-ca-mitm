"""清理异常退出后遗留的本项目后台 worker。"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path


def stop_stale_workers(module_names: tuple[str, ...]) -> list[int]:
    if not module_names:
        return []
    if os.name == "nt":
        return _stop_windows_workers(module_names)
    return _stop_linux_workers(module_names)


def _stop_windows_workers(module_names: tuple[str, ...]) -> list[int]:
    windows_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    powershell = (
        str(
            Path(windows_root)
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe"
        )
        if windows_root
        else shutil.which("powershell.exe")
    )
    if not powershell:
        return []

    command_line_checks = " -or ".join(
        f"$_.CommandLine.Contains('{module_name}')"
        for module_name in module_names
    )
    script = (
        "$workers = Get-CimInstance Win32_Process | "
        f"Where-Object {{ $_.CommandLine -and ({command_line_checks}) }}; "
        "foreach ($worker in $workers) { "
        "Stop-Process -Id $worker.ProcessId -Force "
        "-ErrorAction SilentlyContinue; "
        "[Console]::WriteLine($worker.ProcessId) }"
    )
    completed = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    return parse_worker_pids(completed.stdout)


def _stop_linux_workers(module_names: tuple[str, ...]) -> list[int]:
    encoded_module_names = tuple(
        module_name.encode("ascii") for module_name in module_names
    )
    stopped_pids = []
    for process_directory in Path("/proc").iterdir():
        if not process_directory.name.isdigit():
            continue
        process_id = int(process_directory.name)
        if process_id == os.getpid():
            continue
        try:
            command_line = (process_directory / "cmdline").read_bytes()
        except OSError:
            continue
        if not any(
            module_name in command_line
            for module_name in encoded_module_names
        ):
            continue
        try:
            os.kill(process_id, signal.SIGTERM)
        except OSError:
            continue
        stopped_pids.append(process_id)

    for process_id in stopped_pids:
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            try:
                os.kill(process_id, 0)
            except OSError:
                break
            time.sleep(0.05)
        else:
            with contextlib.suppress(OSError):
                os.kill(process_id, signal.SIGKILL)
    return stopped_pids


def parse_worker_pids(output: str) -> list[int]:
    process_ids = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.isdigit():
            process_ids.append(int(line))
    return process_ids
