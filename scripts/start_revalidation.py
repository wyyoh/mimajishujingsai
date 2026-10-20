"""Preserve the preceding matrix before measuring changed implementation sources."""
import hashlib
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.initialization import ROOT
from services.storage import read, write
from services.versioning import source_version

current = source_version()
old_plan = read(ROOT / 'artifacts/benchmarks/plan.json')
assert old_plan['core_source_digest'] != current['core_source_digest'], 'Same source: do not archive a running/current series.'
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
source = (ROOT / 'artifacts/benchmarks').resolve()
destination = (ROOT / 'artifacts/benchmark_history' / (stamp + '-' + old_plan['core_source_digest'][:12])).resolve()
assert ROOT.resolve() in source.parents and ROOT.resolve() in destination.parents
assert source != ROOT.resolve() and not destination.exists()
destination.parent.mkdir(parents=True, exist_ok=True)
source.rename(destination)
source.mkdir()
shutil.copyfile(ROOT / 'docs/BENCHMARK_RESULTS.md', destination / 'BENCHMARK_RESULTS.md')
previous_build = read(ROOT / 'artifacts/probes/build_manifest.json')
assert previous_build['core_source_files']['native/grid_crypto.cpp'] == current['core_source_files']['native/grid_crypto.cpp']
assert previous_build['native_library_sha256'] == current['native_library_sha256']
write(destination / 'prior_build_manifest.json', previous_build)
write(ROOT / 'artifacts/probes/build_manifest.json', {
    **current, 'mcl_commit': 'a8cad811f720264e6e140f54c66463be60189789',
    'platform': 'WSL Ubuntu x86_64', 'dependency_lock': 'requirements.lock.txt',
    'frozen_at': datetime.now(timezone.utc).isoformat(),
    'native_inputs_unchanged_from_prior_build': True,
    'source_snapshot_reason': 'Public-export signed-metadata consistency, explicit unsigned scope and external expected-context checks; mathematical PFDAM and native adapter sources unchanged.',
})
write(destination / 'archive_record.json', {
    'previous_core_source_digest': old_plan['core_source_digest'],
    'next_core_source_digest': current['core_source_digest'],
    'reason': 'Preserve measured evidence before fresh measurements of changed source.',
    'command': ['.venv/bin/python', 'scripts/start_revalidation.py'],
    'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in destination.iterdir() if p.is_file()},
})
print({'archived': str(destination), 'frozen_core_source_digest': current['core_source_digest']})
