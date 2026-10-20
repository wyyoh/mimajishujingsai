#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p third_party .build artifacts/probes
if [ ! -d third_party/mcl ]; then
  git clone --depth 1 --branch v3.08 https://github.com/herumi/mcl.git third_party/mcl
fi
if [ -d third_party/mcl/.git ]; then
  test "$(git -C third_party/mcl rev-parse HEAD)" = a8cad811f720264e6e140f54c66463be60189789
else
  test "$(cat third_party/mcl/PINNED_COMMIT)" = a8cad811f720264e6e140f54c66463be60189789
fi
make -C third_party/mcl -j4 lib/libmcl.so
python3 -m venv .venv
if [ -d .build/wheelhouse ]; then
  .venv/bin/python -m pip --isolated install --no-index --find-links .build/wheelhouse -r requirements.lock.txt
else
  .venv/bin/python -m pip install -r requirements.lock.txt
fi
g++ -std=c++17 -O2 -fPIC -shared native/grid_crypto.cpp native/agility.cpp -o .build/libgridcrypto.next.so -lssl -lcrypto -ldl -pthread
mv .build/libgridcrypto.next.so .build/libgridcrypto.so
.venv/bin/python scripts/doctor.py --output artifacts/probes/environment.json
