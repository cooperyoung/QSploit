#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
qsploit_python="${QSPLOIT_PYTHON:-}"
if [ -z "$qsploit_python" ] && [ -f .runtime-python ]; then
    IFS= read -r qsploit_python < .runtime-python
fi
if [ -z "$qsploit_python" ] || [ ! -x "$qsploit_python" ]; then
    qsploit_python="$PWD/.venv/bin/python"
fi
# Keep Python bytecode out of cloud-synced source directories.
export PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-${TMPDIR:-/tmp}/qsploit-pycache}"
exec "$qsploit_python" -m qsploit --demo "$@"
