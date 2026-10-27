"""代理配置的解析、规范化和校验。"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from urllib.parse import urlsplit


DEFAULT_CA_NAME = "01-EM-OV-TLS-CA-G3C"
DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_LISTEN_PORT = 28081
DEFAULT_SOCKS_PORT = 28082
DEFAULT_UPSTREAM = "http://127.0.0.1:9000"
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
WILDCARD_HOSTS = {"", "0.0.0.0", "::"}


class ConfigurationError(ValueError):
    """代理配置无效。"""


def validate_port(port: int, option_name: str) -> None:
    if not 1 <= port <= 65535:
        raise ConfigurationError(f"{option_name} 必须在 1 到 65535 之间")


def format_host_port(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def normalize_upstream(upstream: str) -> str:
    parsed_upstream = urlsplit(upstream)
    if parsed_upstream.scheme not in {"http", "https"}:
        raise ConfigurationError("上游代理只支持 http:// 或 https://")
    if not parsed_upstream.hostname:
        raise ConfigurationError("上游代理缺少主机名")
    if parsed_upstream.username or parsed_upstream.password:
        raise ConfigurationError("当前版本不处理上游代理用户名和密码")
    if parsed_upstream.path not in {"", "/"} or parsed_upstream.query:
        raise ConfigurationError("上游代理不能包含路径或查询参数")

    try:
        upstream_port = parsed_upstream.port
    except ValueError as error:
        raise ConfigurationError("上游代理端口无效") from error

    if upstream_port is None:
        upstream_port = 443 if parsed_upstream.scheme == "https" else 80

    validate_port(upstream_port, "上游代理端口")
    return (
        f"{parsed_upstream.scheme}://"
        f"{format_host_port(parsed_upstream.hostname, upstream_port)}"
    )


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    ca_name: str = DEFAULT_CA_NAME
    listen_host: str = DEFAULT_LISTEN_HOST
    listen_port: int = DEFAULT_LISTEN_PORT
    socks_port: int = DEFAULT_SOCKS_PORT
    upstream: str = DEFAULT_UPSTREAM
    verify_upstream: bool = False

    def __post_init__(self) -> None:
        normalized_ca_name = self.ca_name.strip()
        normalized_listen_host = self.listen_host.strip()
        if not normalized_ca_name:
            raise ConfigurationError("CA 名称不能为空")
        if not normalized_listen_host:
            raise ConfigurationError("监听地址不能为空")

        validate_port(self.listen_port, "监听端口")
        validate_port(self.socks_port, "SOCKS5 端口")
        if self.socks_port == self.listen_port:
            raise ConfigurationError("HTTP 监听端口和 SOCKS5 端口不能相同")

        normalized_upstream = normalize_upstream(self.upstream)
        parsed_upstream = urlsplit(normalized_upstream)
        listens_on_loopback = (
            normalized_listen_host in LOOPBACK_HOSTS
            or normalized_listen_host in WILDCARD_HOSTS
        )
        if (
            listens_on_loopback
            and parsed_upstream.hostname in LOOPBACK_HOSTS
            and self.listen_port == parsed_upstream.port
        ):
            raise ConfigurationError(
                "监听端口和上游代理端口不能相同，否则会形成代理循环"
            )
        if (
            listens_on_loopback
            and parsed_upstream.hostname in LOOPBACK_HOSTS
            and self.socks_port == parsed_upstream.port
        ):
            raise ConfigurationError("SOCKS5 端口和上游代理端口不能相同")

        object.__setattr__(self, "ca_name", normalized_ca_name)
        object.__setattr__(self, "listen_host", normalized_listen_host)
        object.__setattr__(self, "upstream", normalized_upstream)

    @property
    def mode_spec(self) -> str:
        listen_endpoint = format_host_port(self.listen_host, self.listen_port)
        return f"upstream:{self.upstream}@{listen_endpoint}"

    @property
    def socks_endpoint(self) -> str:
        return format_host_port(self.listen_host, self.socks_port)


def add_proxy_config_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ca-name",
        default=DEFAULT_CA_NAME,
        help=f"cas 目录中的 CA 名称，默认 {DEFAULT_CA_NAME}",
    )
    parser.add_argument(
        "--listen-host",
        default=DEFAULT_LISTEN_HOST,
        help=f"客户端代理监听地址，默认 {DEFAULT_LISTEN_HOST}",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=DEFAULT_LISTEN_PORT,
        help=f"客户端代理监听端口，默认 {DEFAULT_LISTEN_PORT}",
    )
    parser.add_argument(
        "--socks-port",
        type=int,
        default=DEFAULT_SOCKS_PORT,
        help=f"SOCKS5 代理监听端口，默认 {DEFAULT_SOCKS_PORT}",
    )
    parser.add_argument(
        "--upstream",
        default=DEFAULT_UPSTREAM,
        help=f"上游 HTTP(S) 代理地址，默认 {DEFAULT_UPSTREAM}",
    )
    parser.add_argument(
        "--verify-upstream",
        action="store_true",
        help="校验上游代理出示的证书；Reqable 二次 MITM 时通常需要关闭。",
    )


def proxy_config_from_arguments(arguments: argparse.Namespace) -> ProxyConfig:
    return ProxyConfig(
        ca_name=arguments.ca_name,
        listen_host=arguments.listen_host,
        listen_port=arguments.listen_port,
        socks_port=arguments.socks_port,
        upstream=arguments.upstream,
        verify_upstream=arguments.verify_upstream,
    )
