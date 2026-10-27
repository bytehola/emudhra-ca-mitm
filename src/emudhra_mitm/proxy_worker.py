"""独立代理 worker 进程。"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import signal
import sys
import tempfile
from pathlib import Path
from typing import Any

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from emudhra_mitm.ca_catalog import resolve_ca
from emudhra_mitm.config import (
    ProxyConfig,
    add_proxy_config_arguments,
    proxy_config_from_arguments,
)
from emudhra_mitm.socks5 import Socks5Bridge, internal_http_proxy_host
from emudhra_mitm.streaming import StreamingForwarder


def emit_event(event_name: str, **payload: Any) -> None:
    event = {"event": event_name, **payload}
    print(json.dumps(event, ensure_ascii=False), flush=True)


class WorkerLifecycle:
    def __init__(self, ready_event: asyncio.Event) -> None:
        self.ready_event = ready_event

    def running(self) -> None:
        self.ready_event.set()


def build_mitmproxy_options(
    config: ProxyConfig,
    confdir_path: Path,
) -> options.Options:
    mitmproxy_options = options.Options()
    mitmproxy_options.update(
        confdir=str(confdir_path),
        mode=[config.mode_spec],
        ssl_insecure=not config.verify_upstream,
        http2=True,
    )
    return mitmproxy_options


def prepare_confdir(ca_name: str) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    ca_entry = resolve_ca(ca_name)
    temporary_confdir = tempfile.TemporaryDirectory(prefix="emudhra-mitm-")
    confdir_path = Path(temporary_confdir.name)
    os.chmod(confdir_path, 0o700)
    shutil.copyfile(ca_entry.bundle_path, confdir_path / "mitmproxy-ca.pem")
    return temporary_confdir, confdir_path


async def watch_control_stdin(master: DumpMaster) -> None:
    event_loop = asyncio.get_running_loop()
    while not master.should_exit.is_set():
        command = await event_loop.run_in_executor(None, sys.stdin.readline)
        if not command or command.strip().lower() == "stop":
            master.shutdown()
            return


def install_shutdown_handlers(master: DumpMaster) -> None:
    event_loop = asyncio.get_running_loop()

    def request_shutdown() -> None:
        master.shutdown()

    for signal_number in (signal.SIGINT, signal.SIGTERM):
        try:
            event_loop.add_signal_handler(signal_number, request_shutdown)
        except NotImplementedError:
            signal.signal(signal_number, lambda *_: request_shutdown())


async def run_worker(config: ProxyConfig, control_stdin: bool) -> None:
    temporary_confdir, confdir_path = prepare_confdir(config.ca_name)
    socks_bridge = Socks5Bridge(
        listen_host=config.listen_host,
        listen_port=config.socks_port,
        http_proxy_host=internal_http_proxy_host(config.listen_host),
        http_proxy_port=config.listen_port,
    )
    control_task: asyncio.Task[None] | None = None
    master_task: asyncio.Task[None] | None = None
    try:
        await socks_bridge.start()
        mitmproxy_options = build_mitmproxy_options(config, confdir_path)
        master = DumpMaster(
            mitmproxy_options,
            with_termlog=False,
            with_dumper=False,
        )
        master.options.update(block_global=False)
        ready_event = asyncio.Event()
        master.addons.add(
            StreamingForwarder(),
            WorkerLifecycle(ready_event),
        )
        install_shutdown_handlers(master)
        if control_stdin:
            control_task = asyncio.create_task(watch_control_stdin(master))

        master_task = asyncio.create_task(master.run())
        ready_wait_task = asyncio.create_task(ready_event.wait())
        try:
            completed_tasks, _ = await asyncio.wait(
                {master_task, ready_wait_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if master_task in completed_tasks:
                await master_task
                raise RuntimeError("代理 worker 在就绪前退出")

            emit_event(
                "ready",
                mode=config.mode_spec,
                socks_endpoint=config.socks_endpoint,
                upstream=config.upstream,
            )
            await master_task
        finally:
            ready_wait_task.cancel()
            await asyncio.gather(ready_wait_task, return_exceptions=True)
    finally:
        if master_task is not None and not master_task.done():
            master.shutdown()
        if control_task is not None:
            control_task.cancel()
            try:
                await control_task
            except asyncio.CancelledError:
                pass
        await socks_bridge.close()
        if master_task is not None:
            await asyncio.gather(master_task, return_exceptions=True)
        temporary_confdir.cleanup()
        emit_event("stopped")


def parse_worker_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="运行 eMudhra MITM 代理 worker。")
    add_proxy_config_arguments(parser)
    parser.add_argument(
        "--control-stdin",
        action="store_true",
        help="从标准输入接收 stop 命令；输入关闭时也退出。",
    )
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    arguments = parse_worker_arguments()
    try:
        config = proxy_config_from_arguments(arguments)
        asyncio.run(run_worker(config, arguments.control_stdin))
    except KeyboardInterrupt:
        return 130
    except (FileNotFoundError, OSError, ValueError) as error:
        print(f"[!] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
