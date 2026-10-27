#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

VENV_DIRECTORY="$PROJECT_ROOT/.venv"
VENV_PYTHON="$VENV_DIRECTORY/bin/python"
DEPENDENCY_STATE_FILE="$VENV_DIRECTORY/.emudhra-dependencies.sha256"

python_version_is_supported() {
    "$1" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)"
}

if [[ -x "$VENV_PYTHON" ]]; then
    if ! python_version_is_supported "$VENV_PYTHON"; then
        printf '%s\n' \
            "[!] The existing .venv does not use Python 3.12 or newer." >&2
        exit 1
    fi
elif [[ -e "$VENV_DIRECTORY" ]]; then
    printf '%s\n' \
        "[!] .venv exists but is not a usable Linux virtual environment." >&2
    exit 1
else
    if [[ -n "${PYTHON_BIN:-}" ]]; then
        python_candidates=("$PYTHON_BIN")
    else
        python_candidates=(python3 python3.12)
    fi

    selected_python=""
    for python_candidate in "${python_candidates[@]}"; do
        if command -v "$python_candidate" >/dev/null 2>&1 \
            && python_version_is_supported "$python_candidate"; then
            selected_python="$python_candidate"
            break
        fi
    done

    if [[ -z "$selected_python" ]]; then
        printf '%s\n' \
            "[!] Python 3.12 or newer was not found." \
            "    Set PYTHON_BIN to a compatible Python executable." >&2
        exit 1
    fi

    printf '%s\n' "[1/3] Creating the virtual environment..."
    if ! "$selected_python" -m venv "$VENV_DIRECTORY"; then
        printf '%s\n' "[!] Failed to create the virtual environment." >&2
        exit 1
    fi
fi

python_runtime_id="$(
    "$VENV_PYTHON" -c \
        "import sys; print(f'{sys.implementation.name}:{sys.version_info.major}.{sys.version_info.minor}')"
)"
pyproject_hash="$(
    "$VENV_PYTHON" -c \
        "import hashlib, pathlib; print(hashlib.sha256(pathlib.Path('pyproject.toml').read_bytes()).hexdigest())"
)"
dependency_state="$pyproject_hash:$python_runtime_id"

if [[ -f "$DEPENDENCY_STATE_FILE" ]] \
    && [[ "$(<"$DEPENDENCY_STATE_FILE")" == "$dependency_state" ]]; then
    printf '%s\n' "[2/3] Dependencies are up to date."
else
    printf '%s\n' "[2/3] Installing dependencies..."
    if ! "$VENV_PYTHON" -m pip install -e ".[android]"; then
        printf '%s\n' "[!] Failed to install dependencies." >&2
        exit 1
    fi
    printf '%s\n' "$dependency_state" > "$DEPENDENCY_STATE_FILE"
fi

printf '%s\n' "[3/3] Starting eMudhra MITM..."
exec "$VENV_PYTHON" main.py
