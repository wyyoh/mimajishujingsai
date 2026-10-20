"""V3 coordinator; private source partitions never enter gateway files or public exports."""
import fcntl
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .encoding import Rejected, canonical, digest
from .expansion_data import select
from .expansion_governance import check_policy, partitions
from .initialization import ROOT, RUNTIME
from .native import utc
from .orchestrator import RUNS, initialize, free_port
from .storage import read, write
from .versioning import source_version

def execute(policy, *, run_id=None, lab=True, fault='normal', defer_publication=False, private_control=False):
    if fault not in ('normal', 'modified_report', 'missing', 'source_identity', 'snapshot_tamper', 'invalid_receipt', 'invalid_authorization') or fault != 'normal' and not lab:
        raise Rejected('BUSINESS_POLICY_FORBIDS_LAB')
    with (RUNTIME / 'execution.lock').open('a+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX)
        return _execute(policy, run_id=run_id, lab=lab, fault=fault, defer_publication=defer_publication, private_control=private_control)

def _execute(policy, *, run_id, lab, fault, defer_publication=False, private_control=False):
    public = initialize()
    policy = check_policy(policy, digest(policy), 'SAB')
    indices = policy['period_indices']
    protected = policy['policy_version'] == 'V5_RELEASE_POLICY_1'
    if protected:
        from .publication import selected_data
        dataset = selected_data(policy)
    else:
        dataset = select(policy['dataset_version'], policy['node_count'], indices[0]//96, [index%96 for index in indices])
    if dataset['dataset_digest'] != policy['dataset_digest'] or canonical(dataset['slots']) != canonical(policy['selected_slots']):
        raise Rejected('COORDINATOR_DATASET_BINDING_MISMATCH')
    if protected:
        from .publication import protected_partitions
        parts=protected_partitions(dataset,len(policy['sources']))
    else:
        parts = partitions(dataset, len(policy['sources']))
    if any(part['partition_digest'] != binding['partition_digest'] for part, binding in zip(parts, policy['sources'], strict=True)):
        raise Rejected('COORDINATOR_PARTITION_BINDING_MISMATCH')
    run_id = run_id or uuid.uuid4().hex
    if len(run_id) != 32 or any(char not in '0123456789abcdef' for char in run_id):
        raise Rejected('RUN_ID_INVALID')
    job, run = RUNTIME / 'runs' / run_id, RUNS / run_id
    if job.exists():
        raise Rejected('RUN_ALREADY_EXISTS')
    roles = ['utility', 'gateway', *[source['source_id'] for source in policy['sources']]]
    for role in roles:
        (job / role).mkdir(parents=True, mode=0o700)
    (job / 'events').mkdir(mode=0o700)
    run.mkdir(parents=True, exist_ok=True)
    chosen = [node['node_id'] for node in dataset['nodes'] if node['region'] == policy['region'] and node['resource_class'] in policy['resources']]
    injection = {'omitted': {}, 'modified': {}}
    if fault == 'missing':
        injection['omitted'] = {slot['slot_id']: chosen[:max(1, len(chosen)//5)] for slot in dataset['slots']}
    if fault == 'modified_report' and chosen:
        injection['modified'] = {'slot-0': [chosen[0]]}
    version = 5 if protected else 4
    context = {'object_type': f'GRID_PUBLIC_TASK_V{version}', 'schema_version': version, 'task_id': uuid.uuid4().hex, 'run_id': run_id,
               'task_nonce': policy['request_nonce'], 'metric_id': 'average_active_power_W', 'param_id': public['param_id'],
               'slots': dataset['slots'], 'governance': policy, 'policy_digest': digest(policy)}
    write(job / 'utility/context.json', context, True)
    write(job / 'utility/config.json', {'region': policy['region'], 'resources': policy['resources'], 'expected_target_count': len(chosen)}, True)
    for part in parts:
        write(job / part['source_id'] / 'dataset.json', part, True)
        write(job / part['source_id'] / 'injection.json', injection, True)
    if protected:
        plan = read(RUNTIME / 'utility/release-plans' / (policy['release_plan_id']+'.json'))
        write(job / 'utility/release-plan.json', plan, True)
        for part in parts:
            write(job / part['source_id'] / 'participation-roster.json', plan['rosters'][part['source_id']], True)
    write(run / 'governance.json', policy)
    provenance = {'dataset_id': dataset['dataset_id'], 'dataset_digest': dataset['dataset_digest'], 'parent_dataset_digest': dataset['parent_dataset_digest'],
                  'source': dataset['source'], 'period_indices': indices, 'selected_slots': dataset['slots'],
                  'reading_origin': dataset['reading_origin'], 'grouping_origin': dataset['grouping_origin'],
                  'data_values': 'excluded; private Source runtime only'}
    if dataset['source'] != 'SYNTHETIC':
        provenance['import'] = read(ROOT / 'references/datasets/uci321/import.json')
    if protected:
        provenance['input_binding_scheme']=policy['input_binding_scheme']
    write(run / 'data_provenance.json', provenance)
    manifest = {'run_id': run_id, 'task_id': context['task_id'], 'execution_mode': 'REAL', 'data_source': dataset['source'],
                'dataset_id': dataset['dataset_id'], 'dataset_digest': dataset['dataset_digest'], 'param_id': public['param_id'],
                'core_version': public['core_version'], 'core_audit_status': public['core_audit_status'], 'policy_hiding': 'DEMONSTRATED_LIMITATION',
                'security_profile': 'SAB', 'scenario': fault, 'scene_id': policy['scene_id'], 'node_count': dataset['node_count'], 'slot_count': dataset['slot_count'],
                'logical_source_process_count': len(parts), 'started_at': utc(), 'status': 'RUNNING', 'lab': lab, 'results': [],
                'protocol_version': version, 'algorithm_suite': policy['algorithm_suite'], 'policy_digest': digest(policy),
                'asset_id': policy['asset_id'], 'data_level': policy['data_level'], 'function': policy['function'], 'requester_id': policy['requester_id'],
                'classification_scope': 'SIMULATED_NOT_OFFICIAL', 'signature_evidence_refs': [], 'connection_evidence_refs': ['connection_evidence.json'],
                'benchmark_context': {'platform': 'WSL Ubuntu; independent Source processes on one physical host', 'clock': 'perf_counter_ns', 'unit': 'ns',
                                      'includes': 'role startup, serialization, real handshakes, crypto, PFDAM, recovery and public evidence collection', 'sample_count': 1}, **source_version()}
    if protected:
        manifest.update(parent_evaluation=policy['parent_evaluation'],runtime_instance=policy['runtime_instance'],input_binding_scheme=policy['input_binding_scheme'])
        from .publication import rules
        write(run/'publication_rules.json',rules())
    write(run/'run_manifest.json',manifest)
    used_ports = set()
    def unique_port():
        while True:
            value = free_port()
            if value not in used_ports:
                used_ports.add(value)
                return value
    ports, l2 = {source['source_id']: unique_port() for source in policy['sources']}, unique_port()
    processes, logs = {}, {}
    start, peak_rss, failure = time.perf_counter_ns(), 0, None
    def spawn(role):
        log = (job / role / 'process.log').open('wb')
        logs[role] = log
        command = [sys.executable, '-m', 'services.expansion_workers', '--runtime', str(RUNTIME), '--job', str(job), '--run-id', run_id,
                   '--role', role, '--suite', policy['algorithm_suite'], '--sources', json.dumps(ports), '--l2', str(l2), '--fault', fault]
        from .custody import worker_environment
        with worker_environment(RUNTIME, role) as (environment, inherited):
            processes[role] = subprocess.Popen(command, cwd=ROOT, env={**environment, 'PYTHONPATH': str(ROOT), 'GRID_RUNTIME': str(RUNTIME)},
                pass_fds=inherited, stdout=log, stderr=subprocess.STDOUT)
    def ready(role):
        until = time.monotonic()+60
        while time.monotonic() < until:
            if (job / 'cancel.request').exists() or (run / 'cancel.request').exists() or (protected and (RUNS / policy['parent_evaluation'] / 'cancel.request').exists()):
                raise Rejected('CANCELLED_BY_USER')
            if (job / role / 'ready.json').exists():
                return
            if processes[role].poll() is not None:
                raise Rejected('ROLE_STARTUP_FAILED')
            time.sleep(.05)
        raise Rejected('ROLE_STARTUP_TIMEOUT')
    try:
        spawn('utility'); ready('utility')
        spawn('gateway'); ready('gateway')
        for source in policy['sources']:
            spawn(source['source_id'])
        until = time.monotonic()+600
        while time.monotonic() < until:
            if (job / 'cancel.request').exists() or (run / 'cancel.request').exists() or (protected and (RUNS / policy['parent_evaluation'] / 'cancel.request').exists()):
                raise Rejected('CANCELLED_BY_USER')
            states = [process.poll() for process in processes.values()]
            if any(code is not None and code != 0 for code in states):
                raise Rejected('ROLE_PROCESS_FAILED')
            if all(code == 0 for code in states):
                break
            rss = 0
            for process in processes.values():
                try:
                    rss += next((int(line.split()[1]) for line in Path(f'/proc/{process.pid}/status').read_text().splitlines() if line.startswith('VmRSS:')), 0)
                except (FileNotFoundError, ProcessLookupError):
                    pass
            peak_rss = max(peak_rss, rss)
            time.sleep(.05)
        else:
            raise Rejected('TASK_EXECUTION_TIMEOUT')
    except Exception as exc:
        failure = getattr(exc, 'code', 'EXECUTION_FAILED')
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.terminate()
        for process in processes.values():
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        for log in logs.values():
            log.close()
    connections, timings, events, isolation, usage = [], [], [], {}, []
    for role in processes:
        for name, target in (('connections', connections), ('timings', timings)):
            if (job / role / f'{name}.json').exists():
                target.extend(read(job / role / f'{name}.json'))
        if (job / role / 'isolation.json').exists():
            isolation[role] = read(job / role / 'isolation.json')
        if (job / role / 'resources.json').exists():
            usage.append(read(job / role / 'resources.json'))
    for path in (job / 'events').glob('*.jsonl'):
        events.extend(json.loads(line) for line in path.read_text().splitlines() if line)
    events.sort(key=lambda event: event['at'])
    if protected:
        events = [{key: row[key] for key in ('run_id', 'role', 'stage', 'at', 'slot_id', 'code') if key in row} for row in events]
    for index, event in enumerate(events, 1):
        event['sequence'] = index
    for name, value in (('connection_evidence', connections), ('performance_raw', timings), ('events', events), ('role_isolation', isolation)):
        write(run / f'{name}.json', value)
    write(run / 'resource_evidence.json', {'roles': usage, 'cpu_role_total_ns': sum(row['cpu_user_ns']+row['cpu_system_ns'] for row in usage),
          'peak_sampled_role_rss_KiB': peak_rss, 'sampling_interval_ms': 50, 'scope': 'Sum of role RSS; shared pages may repeat. Same physical host.'})
    manifest['role_file_isolation'] = len(isolation) == len(processes) and all(all(check['read_denied'] for check in record['checks']) for record in isolation.values())
    if (job / 'gateway/authorization_evidence.json').exists():
        write(run / 'authorization_evidence.json', read(job / 'gateway/authorization_evidence.json'))
        manifest['signature_evidence_refs'].append('authorization_evidence.json')
    published_path = job / 'utility/published.json'
    published = {'results': [], 'receipts': [], 'signature_evidence': []}
    if published_path.exists():
        try:
            published = read(published_path)
        except (Rejected, OSError) as exc:
            failure = failure or getattr(exc, 'code', 'UC_PRIVATE_RESULT_READ_FAILED')
    if protected:
        from .publication_runtime import finish
        return finish(policy, context, manifest, published, dataset, parts, injection, failure,
                      elapsed_start=start, lab=lab, deferred=defer_publication, private_control=private_control)
    if published['results']:
        from .result_attestation import verify_statement
        try:
            if len(published.get('result_statements', [])) != len(published['results']):
                raise Rejected('UC_RESULT_STATEMENTS_MISSING')
            statement_checks = [verify_statement(statement, result, receipt['payload'], policy, RUNTIME, usage='current')
                for statement, result, receipt in zip(published['result_statements'], published['results'], published['receipts'], strict=True)]
            manifest['uc_result_signatures_verified'] = all(item['uc_statement_signature_valid'] for item in statement_checks)
        except (Rejected, KeyError, ValueError) as exc:
            failure = getattr(exc, 'code', 'UC_RESULT_STATEMENT_INVALID')
            published = {'results': [], 'receipts': [], 'signature_evidence': [], 'result_statements': []}
    manifest['results'] = published['results']
    for name in ('receipts', 'signature_evidence', 'snapshots', 'audit_checkpoints', 'accepted_manifests', 'result_statements'):
        if name in published:
            write(run / f'{name}.json', published[name])
    manifest['signature_evidence_refs'].append('signature_evidence.json')
    if failure:
        manifest['status'] = 'CANCELLED' if failure == 'CANCELLED_BY_USER' else 'REJECTED'
        manifest['errors'] = [read(job / role / 'error.json') for role in processes if (job / role / 'error.json').exists()] or [{'code': failure}]
    else:
        manifest['status'] = 'PARTIAL' if any(row['counts']['accepted'] < len(chosen) for row in published['results']) else 'COMPLETED'
        if lab:
            from tests.oracle.reference import expected, compare
            accepted = read(job / 'gateway/accepted.json')
            mappings = {slot['slot_id']: {} for slot in dataset['slots']}
            for part in parts:
                for slot, mapping in read(job / part['source_id'] / 'oracle_mapping.json').items():
                    mappings[slot].update(mapping)
            checks = []
            for index, row in enumerate(published['results']):
                slot = row['slot_id']
                reference = expected(dataset, policy['region'], policy['resources'], index, injection['omitted'].get(slot, []), injection['modified'].get(slot, []))
                checks.append({'slot_id': slot, **compare(reference, accepted[slot], mappings[slot], row['value_W'])})
            write(run / 'oracle_summary.json', checks)
            manifest['oracle_match'] = len(checks) == policy['slot_count'] and all(check['set_match'] and check['value_match'] for check in checks)
            if not manifest['oracle_match']:
                manifest['status'] = 'FAILED'
    manifest.update(finished_at=utc(), elapsed_ns=time.perf_counter_ns()-start)
    write(run / 'run_manifest.json', manifest)
    return manifest
