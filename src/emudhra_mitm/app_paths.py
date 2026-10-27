"""应用源码目录和本地运行文件位置。"""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESOURCES_ROOT = PROJECT_ROOT / "resources"
UI_PATH = RESOURCES_ROOT / "ui" / "index.html"
FRIDA_SCRIPT_PATH = PROJECT_ROOT / "frida" / "bypass_ssl_pinning.js"
ADB_ROOT = PROJECT_ROOT / "vendor" / "adb"
CONFIG_DIRECTORY = PROJECT_ROOT / "config"
FRIDA_CACHE_DIRECTORY = CONFIG_DIRECTORY / "frida"
SETTINGS_PATH = CONFIG_DIRECTORY / "settings.json"
