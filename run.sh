#!/usr/bin/env bash
set -e

# Ensure we are in the repository root
dirname=$(dirname "$0")
cd "$dirname"

# Pick an interpreter. MSYS/MinGW builds of Python report a "mingw" platform
# tag and cannot install packages that only ship Windows wheels (watchfiles,
# ruff, ...), so they are skipped when a native Python is available.
# Override with PYTHON=/path/to/python.
pick_python() {
  if [ -n "${PYTHON:-}" ]; then
    printf '%s\n' "$PYTHON"
    return 0
  fi

  local candidates=()
  local candidate
  if command -v where >/dev/null 2>&1; then
    while IFS= read -r line; do
      candidates+=("${line//\\//}")
    done < <(where python 2>/dev/null || true)
  fi
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      candidates+=("$(command -v "$candidate")")
    fi
  done

  for candidate in ${candidates[@]+"${candidates[@]}"}; do
    if "$candidate" -c 'import sysconfig
raise SystemExit(0 if not sysconfig.get_platform().startswith(("mingw", "msys")) else 1)' >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  printf '%s\n' "python3"
}

PY="$(pick_python)"

# Create virtual environment if missing
if [ ! -d ".venv" ]; then
  echo "Creating virtual environment with $PY..."
  "$PY" -m venv .venv
fi

# POSIX venvs use bin/, Windows venvs use Scripts/
if [ -f ".venv/bin/activate" ]; then
  # shellcheck disable=SC1091
  source ".venv/bin/activate"
elif [ -f ".venv/Scripts/activate" ]; then
  # shellcheck disable=SC1091
  source ".venv/Scripts/activate"
else
  echo "No activate script found in .venv" >&2
  exit 1
fi

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run the FastAPI development server
uvicorn backend.main:app --reload
