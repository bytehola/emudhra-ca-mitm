"""从仓库根目录启动桌面界面。"""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = PROJECT_ROOT / "src"


def main() -> int:
    if str(SOURCE_ROOT) not in sys.path:
        sys.path.insert(0, str(SOURCE_ROOT))
    from emudhra_mitm.application import main as application_main

    return application_main()


if __name__ == "__main__":
    raise SystemExit(main())
