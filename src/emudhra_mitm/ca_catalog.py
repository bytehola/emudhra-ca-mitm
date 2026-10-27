"""发现和读取 cas 目录中的 CA 资源。"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def default_cas_root() -> Path:
    configured_root = os.environ.get("EMUDHRA_CAS_ROOT")
    if configured_root:
        return Path(configured_root).expanduser().resolve()

    source_root = Path(__file__).resolve().parents[2] / "cas"
    if source_root.is_dir():
        return source_root

    return (Path.cwd() / "cas").resolve()


@dataclass(frozen=True, slots=True)
class CaEntry:
    ca_name: str
    directory: Path
    bundle_path: Path
    info: dict[str, str]


def read_ca_info(info_path: Path) -> dict[str, str]:
    metadata: dict[str, str] = {}
    if not info_path.is_file():
        return metadata

    for raw_line in info_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip()
    return metadata


def resolve_ca(ca_name: str, cas_root: Path | None = None) -> CaEntry:
    root = (cas_root or default_cas_root()).resolve()
    ca_directory = (root / ca_name).resolve()
    if not ca_directory.is_relative_to(root):
        raise ValueError("CA 名称必须指向 cas 目录内的子目录")

    bundle_path = ca_directory / "mitmproxy-ca.pem"
    if not ca_directory.is_dir():
        raise FileNotFoundError(f"找不到 CA 目录: {ca_directory}")
    if not bundle_path.is_file():
        raise FileNotFoundError(f"找不到 CA 文件: {bundle_path}")

    return CaEntry(
        ca_name=ca_directory.name,
        directory=ca_directory,
        bundle_path=bundle_path,
        info=read_ca_info(ca_directory / "INFO.txt"),
    )


def discover_cas(cas_root: Path | None = None) -> list[CaEntry]:
    root = (cas_root or default_cas_root()).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"找不到 cas 目录: {root}")

    entries: list[CaEntry] = []
    for candidate in sorted(root.iterdir(), key=lambda path: path.name):
        if not candidate.is_dir():
            continue
        try:
            entries.append(resolve_ca(candidate.name, root))
        except (FileNotFoundError, ValueError):
            continue

    if not entries:
        raise FileNotFoundError(f"cas 目录中没有可用的 CA: {root}")
    return entries
