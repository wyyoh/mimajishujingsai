"""Record actual calls and public provenance; never serialize secret fixtures."""
import hashlib
import inspect
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from services.initialization import ROOT, RUNTIME
from services.native import utc
from services.storage import read, write
from services.versioning import source_version
from tests import provenance

RESULTS = {}
RECOVERY_RESULTS = {}
EXECUTIONS = []
STARTED_AT = None
COMMAND = []
BUILD = {}
GIT_COMMIT = None
TEST_OUTPUT = Path(os.environ.get('GRID_TEST_OUTPUT', str(ROOT/'artifacts/iterations/standards/test-records')))
CURRENT_EVIDENCE = ROOT/'artifacts/iterations/privacy/current'


def reference(path):
    path = Path(path)
    return {'path': str(path.relative_to(ROOT)),
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def pytest_sessionstart(session):
    global STARTED_AT, COMMAND, BUILD, GIT_COMMIT
    STARTED_AT = utc()
    COMMAND = [sys.executable, '-m', 'pytest', *map(str, session.config.invocation_params.args)]
    BUILD = source_version()
    BUILD['test_harness_files'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                   for p in sorted([* (ROOT / 'tests').rglob('*.py'), *(ROOT / 'tests').rglob('*.c'), ROOT / 'pytest.ini',
                                                    ROOT / 'contracts/v3_acceptance_cases.json',
                                                    ROOT / 'contracts/extra_acceptance_cases.json',
                                                    ROOT / 'contracts/recovery_acceptance_cases.json'])}
    BUILD['test_harness_digest'] = hashlib.sha256(json.dumps(BUILD['test_harness_files'], sort_keys=True).encode()).hexdigest()
    revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True)
    GIT_COMMIT = revision.stdout.strip() if revision.returncode == 0 else None


@pytest.fixture(autouse=True)
def record_cases(request):
    request.node._grid_run_ids = set()
    request.node._grid_observations = []
    provenance.begin(request.node._grid_run_ids, request.node._grid_observations)
    marker = request.node.get_closest_marker('acceptance')
    if marker:
        request.node.user_properties.append(('case_ids', list(marker.args)))
    recovery_marker = request.node.get_closest_marker('recovery')
    if recovery_marker:
        request.node.user_properties.append(('recovery_ids', list(recovery_marker.args)))
    yield
    provenance.end()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    item._grid_call_started = utc()
    yield
    item._grid_call_finished = utc()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when != 'call':
        return
    run_ids = sorted(getattr(item, '_grid_run_ids', set()))
    source_path = Path(str(item.path))
    evidence = [reference(source_path)]
    run_inputs = []
    for run_id in run_ids:
        directory = ROOT / 'artifacts/runs' / run_id
        manifest = read(directory / 'run_manifest.json')
        run_inputs.append({
            'run_id': run_id, 'param_id': manifest['param_id'],
            'dataset_digest': manifest['dataset_digest'],
            'execution_mode': manifest['execution_mode'],
            'security_profile': manifest['security_profile'],
            'nodes': manifest['node_count'], 'slots': manifest['slot_count'],
            'scenario': manifest['scenario'],
        })
        for name in ('run_manifest.json', 'recovery_evidence.json', 'oracle_summary.json', 'authorization_evidence.json',
                     'connection_evidence.json', 'signature_evidence.json', 'rejection_evidence.json',
                     'role_isolation.json', 'performance_raw.json', 'receipts.json', 'governance.json',
                     'snapshots.json', 'audit_checkpoints.json', 'accepted_manifests.json', 'resource_evidence.json', 'result_statements.json',
                     'release.json','release_statement.json','evaluation.json','evaluation_statement.json','evaluation_inputs.json'):
            path = directory / name
            if path.is_file():
                evidence.append(reference(path))
        for path in sorted((ROOT / 'artifacts/iterations/v41/attacks').glob(run_id + '-*.json')):
            evidence.append(reference(path))
    mode = 'REAL_CALL_ASSERTIONS'
    external = {
        'test_expansion_browser_record': ['artifacts/iterations/privacy/current/browser.json'],
        'test_expansion_offline_fresh_runtime_record': ['artifacts/iterations/privacy/current/v4-offline.json', 'artifacts/iterations/privacy/current/publication-offline.json', 'artifacts/iterations/privacy/current/offline-install.log', 'artifacts/iterations/privacy/current/offline-run.log'],
        'test_private_controls_and_availability_record':['artifacts/iterations/privacy/current/business.json','scripts/privacy_business_validation.py'],
        'test_original_signed_archive_history_record':['artifacts/iterations/privacy/current/history.json','scripts/privacy_history_validation.py'],
        'test_browser_state_and_failure_labels': ['artifacts/iterations/privacy/current/browser.json'],
        'test_independent_offline_reproduction_record': ['artifacts/iterations/privacy/current/legacy-offline.json',
                                                        'artifacts/iterations/privacy/current/offline-install.log',
                                                        'artifacts/iterations/privacy/current/offline-run.log', 'artifacts/iterations/privacy/current/v41-offline.json'],
        'test_policy_limitation_is_recorded': ['artifacts/probes/primitives.json',
                                               'artifacts/probes/policy_audit.json',
                                               'artifacts/probes/report_tag_audit.json',
                                               'docs/claims_registry.json'],
    }
    if item.name in external:
        mode = 'EXISTING_EXECUTION_EVIDENCE_REVIEW'
        evidence.extend(reference(ROOT / name) for name in external[item.name])
    public_path = RUNTIME / 'public/parameters.json'
    if public_path.exists():
        context = TEST_OUTPUT / 'acceptance_context' / STARTED_AT.replace(':', '-') / hashlib.sha256(report.nodeid.encode()).hexdigest()[:20]
        context.mkdir(parents=True, exist_ok=True)
        for name in ('parameters.json', 'key_registry.json', 'trust-registry.json'):
            source = RUNTIME / 'public' / name
            if source.is_file():
                target = context / name
                shutil.copyfile(source, target)
                evidence.append(reference(target))
    parameter_id = read(public_path)['param_id'] if public_path.exists() else None
    test_source = inspect.getsource(item.obj).encode('utf-8')
    row = {
        'test': report.nodeid,
        'status': 'PASS' if report.passed else 'NOT_RUN' if report.skipped else 'FAIL',
        'actual_result': 'assertions passed' if report.passed else str(report.longrepr),
        'started_at': item._grid_call_started, 'finished_at': item._grid_call_finished,
        'duration_ns': int(report.duration * 1e9),
        'exit_code': 0 if report.passed else 5 if report.skipped else 1,
        'command': COMMAND, 'git_commit': GIT_COMMIT,
        'core_source_digest': BUILD['core_source_digest'],
        'native_library_sha256': BUILD['native_library_sha256'],
        'test_harness_digest': BUILD['test_harness_digest'],
        'param_id': parameter_id, 'mode': mode,
        'test_definition_sha256': hashlib.sha256(test_source).hexdigest(),
        'input_provenance': run_inputs or [{
            'kind': 'assertion vectors and fixture construction in the hashed test definition',
            'population_dataset_digest': None,
            'reason': 'No population run was requested by this test; generated secret material is excluded.',
        }],
        'evidence': evidence,
        'observations': getattr(item, '_grid_observations', []),
    }
    execution_id = hashlib.sha256(report.nodeid.encode()).hexdigest()[:20]
    output_path = TEST_OUTPUT / 'acceptance_executions' / STARTED_AT.replace(':', '-') / f'{execution_id}.json'
    write(output_path, row)
    row['execution_record'] = reference(output_path)
    report.user_properties.append(('execution_record', row))


def pytest_runtest_logreport(report):
    if report.when != 'call':
        return
    properties = dict(report.user_properties)
    row = properties['execution_record']
    EXECUTIONS.append(row)
    for case_id in properties.get('case_ids', []):
        RESULTS.setdefault(case_id, []).append(row)
    for case_id in properties.get('recovery_ids', []):
        RECOVERY_RESULTS.setdefault(case_id, []).append(row)


def pytest_sessionfinish(session, exitstatus):
    original = json.loads((ROOT / 'contracts/v3_acceptance_cases.json').read_text(encoding='utf-8'))
    cases = []
    for case_id in [x['id'] for x in original['cases']] + [f'E{i:02d}' for i in range(1, 21)]:
        rows = RESULTS.get(case_id, [])
        state = 'NOT_RUN' if not rows else 'FAIL' if any(r['status'] == 'FAIL' for r in rows) else 'NOT_RUN' if any(r['status'] != 'PASS' for r in rows) else 'PASS'
        cases.append({
            'case_id': case_id, 'status': state,
            'test': rows[-1]['test'] if rows else None,
            'actual_result': 'all mapped assertions passed' if state == 'PASS' else None,
            'executions': rows,
            'scope': 'Actual mapped assertions; a PASS does not prove an untested cryptographic security property.',
        })
    mapped = {r['test'] for rows in RESULTS.values() for r in rows}
    recovery_cases = [{'case_id': case_id, 'status': 'PASS' if rows and all(r['status'] == 'PASS' for r in rows) else 'FAIL', 'executions': rows}
                      for case_id, rows in sorted(RECOVERY_RESULTS.items())]
    output = {
        'schema': 'GRID_ACCEPTANCE_EXECUTION_V2', 'command': COMMAND,
        'exit_code': int(exitstatus), 'started_at': STARTED_AT, 'finished_at': utc(),
        'cases': cases, 'test_execution_count': len(EXECUTIONS),
        'recovery_cases': recovery_cases,
        'unmapped_tests': [r for r in EXECUTIONS if r['test'] not in mapped],
        'counts': {state: sum(c['status'] == state for c in cases) for state in ('PASS', 'FAIL', 'BLOCKED', 'NOT_RUN')},
        'note': 'Test execution does not establish unsupported cryptographic security properties. Existing-evidence reviews preserve the original execution times.',
        'build': BUILD, 'git_commit': GIT_COMMIT,
        'revision_note': 'File hashes identify local source; no commit is fabricated.',
    }
    write(TEST_OUTPUT / 'acceptance_results.json', output)
    write(TEST_OUTPUT / 'history' / (output['finished_at'].replace(':', '-') + '.json'), output)
