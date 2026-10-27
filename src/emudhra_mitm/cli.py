"""无窗口代理启动入口。"""

from __future__ import annotations

import argparse
import sys
import time

from emudhra_mitm.config import (
    add_proxy_config_arguments,
    proxy_config_from_arguments,
)
from emudhra_mitm.proxy_controller import ProxyController, WorkerStartError


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="启动 HTTP 与 SOCKS5 入口，把流量转给 Reqable 等上游代理。"
    )
    add_proxy_config_arguments(parser)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        config = proxy_config_from_arguments(arguments)
        controller = ProxyController(config)
        ready_event = controller.start()
    except (FileNotFoundError, ValueError, WorkerStartError) as error:
        print(f"[!] {error}", file=sys.stderr)
        return 1

    print("MITM upstream 链路已启动：")
    print("  客户端监听:", ready_event.get("mode", "-"))
    print("  SOCKS5:", ready_event.get("socks_endpoint", "-"))
    print("  上游代理:", ready_event.get("upstream", "-"))
    print("  停止方式: Ctrl-C")

    try:
        while controller.is_running:
            time.sleep(0.2)
    except KeyboardInterrupt:
        return 130
    finally:
        controller.stop()

    error_output = controller.stderr_text().strip()
    if error_output:
        print(error_output, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
