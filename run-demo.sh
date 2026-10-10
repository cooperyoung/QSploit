#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  echo 'Install first: python3.12 -m venv .venv && .venv/bin/pip install -e .'
  exit 1
fi
exec .venv/bin/python -m qsploit --demo "$@"
