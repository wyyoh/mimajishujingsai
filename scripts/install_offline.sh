#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/verify_package.py
python3 - <<'PY'
import platform, re, ssl, sys
assert sys.version_info[:2] == (3, 14), 'Offline wheels require CPython 3.14'
assert platform.machine() == 'x86_64', 'Offline native libraries require Linux x86_64'
assert platform.libc_ver()[0] == 'glibc' and tuple(map(int, platform.libc_ver()[1].split('.'))) >= (2,43), 'Tested native runtime requires glibc >=2.43'
match = re.match(r'OpenSSL (\d+)\.(\d+)\.(\d+)', ssl.OPENSSL_VERSION)
assert match and tuple(map(int, match.groups())) >= (3,5,5), 'OpenSSL >=3.5.5 required'
PY
python3 -m venv .venv
.venv/bin/python -m pip --isolated install --no-index --find-links .build/wheelhouse -r requirements.lock.txt
export PYTHONPATH="$PWD"
.venv/bin/python -m services.cli init --profile SAB
printf 'Offline installation complete. Run: bash scripts/project serve\n'
