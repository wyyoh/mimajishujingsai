"""Version-bound fresh-key regression without changing the live runtime or old results."""
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
data_runtime = Path(os.environ.get('GRID_DATA_RUNTIME', os.environ.get('GRID_RUNTIME', str(Path.home()/'.local/share/grid-collaboration'/hashlib.sha256(str(root).encode()).hexdigest()[:12]))))
target = Path(tempfile.mkdtemp(prefix='grid-standards-regression-', dir=str(Path.home())))
os.environ['GRID_RUNTIME'] = str(target)
os.environ['GRID_CUSTODY_PASSPHRASE'] = secrets.token_urlsafe(32)
if (data_runtime/'datasets/uci321/week.json').exists():
    shutil.copytree(data_runtime/'datasets', target/'datasets', ignore=shutil.ignore_patterns('original.zip','*.part'))
from services.orchestrator import initialize
from services.native import utc, LIB
from services.versioning import source_version
from services.storage import write
started = utc()
family=os.environ.get('GRID_VALIDATION_FAMILY','standards')
assert family in ('standards','privacy','selfcheck','local-standards')
output = root/'artifacts/iterations'/family/'regressions'/started.replace(':','-')
os.environ['GRID_TEST_OUTPUT'] = str(output)
initialize()
before = source_version()
command = [sys.executable, '-m', 'pytest', *(sys.argv[1:] or ['tests','-q'])]
process = subprocess.run(command, cwd=root, env={**os.environ, 'GRID_LAB':'0'})
after = source_version()
changed = before != after
record = {'schema':'GRID_STANDARDS_FRESH_KEY_REGRESSION_V1', 'iteration_family':family,'started_at':started, 'finished_at':utc(), 'command':command,
          'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), **before, 'source_changed':changed,
          'versions':json.loads(LIB.grid_library_info()), 'private_runtime':str(target),
          'acceptance_record':str((output/'acceptance_results.json').relative_to(root)),
          'scope':'Fresh keys/trust/parameters and API state, existing venv and pre-staged public data on one WSL host; not a new physical host',
          'exit_code':process.returncode if not changed else 2}
write(output/'validation.json', record)
print(json.dumps({'record':str((output/'validation.json').relative_to(root)), 'exit_code':record['exit_code']}))
raise SystemExit(record['exit_code'])
