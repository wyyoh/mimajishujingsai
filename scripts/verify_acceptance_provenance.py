"""Verify testcase source, consumed evidence and public packaging transformations."""
import argparse
import ast
import hashlib
import json
from datetime import datetime
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def executions(report):
    rows = [r for c in report['cases'] for r in c['executions']]
    rows += report.get('unmapped_tests', [])
    rows += [r for c in report.get('recovery_cases', []) for r in c['executions']]
    return {r['test']: r for r in rows}


def references(rows):
    refs = [ref for row in rows.values() for ref in [*row['evidence'], row['execution_record']]]
    return {(r['path'], r['sha256']): r for r in refs}


def safe(root, name):
    path = (root / name).resolve()
    if root.resolve() not in path.parents:
        raise ValueError('Reference escapes the allowed root')
    return path


def verify(root, packaged=False, results=None):
    software = root / 'software' if packaged else root
    report = json.loads((results or software / 'artifacts/tests/acceptance_results.json').read_text(encoding='utf-8'))
    assert report['exit_code'] == 0
    assert {c['case_id'] for c in report['cases']} == {f'T{i:02d}' for i in range(1, 41)} | {f'E{i:02d}' for i in range(1, 21)}
    assert all(c['status'] == 'PASS' and c['executions'] for c in report['cases'])
    assert {c['case_id'] for c in report['recovery_cases']} == {f'R{i:02d}' for i in range(1, 7)}
    assert all(c['status'] == 'PASS' for c in report['recovery_cases'])
    build = report['build']
    assert hashlib.sha256(json.dumps(build['core_source_files'], sort_keys=True).encode()).hexdigest() == build['core_source_digest']
    assert hashlib.sha256(json.dumps(build['test_harness_files'], sort_keys=True).encode()).hexdigest() == build['test_harness_digest']
    for name, expected in {**build['core_source_files'], **build['test_harness_files']}.items():
        assert sha(safe(software, name)) == expected, name
    assert sha(software / '.build/libgridcrypto.so') == build['native_library_sha256']
    rows = executions(report)
    assert len(rows) == report['test_execution_count']
    for test, row in rows.items():
        assert row['status'] == 'PASS' and row['exit_code'] == 0
        assert row['core_source_digest'] == build['core_source_digest']
        assert row['test_harness_digest'] == build['test_harness_digest']
        assert row['duration_ns'] >= 0 and datetime.fromisoformat(row['finished_at']) >= datetime.fromisoformat(row['started_at'])
        assert row['command'] and row['param_id'] and row['mode'] and row['input_provenance']
        filename, function = test.split('::')[:2]
        function = function.split('[')[0]
        text = safe(software, filename).read_text(encoding='utf-8')
        tree = ast.parse(text)
        node = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function)
        first = min([node.lineno, *(n.lineno for n in node.decorator_list)])
        definition = ''.join(text.splitlines(keepends=True)[first - 1:node.end_lineno]).encode('utf-8')
        assert hashlib.sha256(definition).hexdigest() == row['test_definition_sha256'], test
    refs = references(rows)
    if packaged:
        catalogue = json.loads((root / 'evidence/acceptance_provenance_catalogue.json').read_text(encoding='utf-8'))
        entries = {(e['original_path'], e['original_sha256']): e for e in catalogue['entries']}
        assert set(refs) == set(entries)
        for key, entry in entries.items():
            assert sha(safe(root, entry['public_copy'])) == entry['public_sha256'], key
    else:
        for (name, expected) in refs:
            assert sha(safe(root, name)) == expected, name
    return {'exit_code': 0, 'scope': 'integrity and traceability of actual assertion records; not independent proof of cryptographic security',
            'core_source_digest': build['core_source_digest'], 'test_harness_digest': build['test_harness_digest'],
            'base_cases': 60, 'recovery_cases': 6, 'test_executions': len(rows), 'evidence_references': len(refs),
            'packaged_public_copies': packaged}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--package-root', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--results', type=Path, help='Actual iteration matrix; omitted for historical packaging paths')
    args = parser.parse_args()
    if args.package_root and args.results:
        parser.error('--results is for local iteration evidence only')
    result = verify(args.package_root or Path(__file__).resolve().parents[1], bool(args.package_root), args.results)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
