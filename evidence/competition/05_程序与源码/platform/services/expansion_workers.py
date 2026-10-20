"""Independent V3 Source processes; every business byte crosses verified native mTLS."""
import argparse
import copy
import json
import resource
import sys
import time
import uuid
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import pfdam
from .agility import provider
from .audit import checkpoint
from .encoding import Rejected, canonical, decimal, digest
from .expansion_evidence import verify_links
from .expansion_governance import check_policy, certificate_hash
from .expansion_schemas import PublicTaskContextV3, ReportEnvelopeV3
from .security_schemas import PublicTaskContextV4
from .publication_schemas import PublicTaskV5
from .governance import aggregation_digest, present_value
from .merkle import accepted_digest, snapshot
from .native import TLS, Listener, sandbox, utc, credentials
from .signatures import check_authorization, sign_object, verify_object, validate
from .storage import read, write, event

def message(kind, run_id, **values):
    return {'type': kind, 'run_id': run_id, 'request_id': uuid.uuid4().hex, **values}

def checked_context(value):
    return validate(PublicTaskV5 if value.get('schema_version') == 5 else PublicTaskContextV4, value)

class Worker:
    def __init__(self, args):
        self.args, self.role = args, args.role
        self.runtime, self.job = Path(args.runtime), Path(args.job)
        self.private = self.job / self.role
        from .custody import activate_worker
        activate_worker(self.runtime, self.role)
        self.public = read(self.runtime / 'public/parameters.json')
        self.sources = json.loads(args.sources)
        self.selected = provider(args.suite)
        self.perf, self.connections = [], []
        targets = [self.runtime / 'ta/ca.key', self.runtime / 'datasets/uci321/week.json', self.runtime / 'datasets/uci321/original.zip']
        targets.extend((self.runtime / 'datasets').glob('synthetic-*-v42.json'))
        for role in ('source', 'utility', 'gateway', 'source-1', 'source-2', 'source-3'):
            if role != self.role:
                targets.extend((self.runtime / role / 'tls.key', self.runtime / role / 'pfdam.json', self.job / role / 'dataset.json', self.job / role / 'participation-roster.json', self.job / role / 'release-plan.json'))
        targets = [target for target in targets if target.is_file()]
        abi = sandbox(self.runtime, self.job, self.role)
        checks = []
        for target in targets:
            try:
                target.read_bytes()
            except PermissionError:
                checks.append({'resource': f'{target.parent.name}/{target.name}', 'read_denied': True})
            else:
                raise Rejected('ROLE_FILE_ISOLATION_FAILED')
        write(self.private / 'isolation.json', {'abi': abi, 'mechanism': 'Landlock + non-dumpable process', 'checks': checks}, True)

    def emit(self, stage, **values):
        event(self.job / 'events' / f'{self.role}.jsonl', self.args.run_id, self.role, stage, **values)

    def timed(self, operation, start, slot=None):
        self.perf.append({'role': self.role, 'operation': operation, 'slot_id': slot, 'elapsed_ns': time.perf_counter_ns()-start})

    def save(self):
        write(self.private / 'connections.json', self.connections, True)
        write(self.private / 'timings.json', self.perf, True)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        write(self.private / 'resources.json', {'role': self.role, 'cpu_user_ns': round(usage.ru_utime*1e9), 'cpu_system_ns': round(usage.ru_stime*1e9), 'peak_rss_KiB': usage.ru_maxrss}, True)

    def utility(self):
        secret = read(self.runtime / 'utility/pfdam.json')
        context = checked_context(read(self.private / 'context.json'))
        policy = check_policy(context['governance'], context['policy_digest'], 'SAB')
        started = time.perf_counter_ns()
        tokens = {slot['slot_id']: pfdam.authorize(self.public, secret, [pfdam.tag(context, slot['slot_id'], policy['region'], resource) for resource in policy['resources']]) for slot in context['slots']}
        self.timed('authorize_tokens', started)
        payload = {'object_type': f"GRID_TASK_AUTH_V{context['schema_version']}", 'schema_version': context['schema_version'], 'task_id': context['task_id'], 'run_id': context['run_id'],
                   'issuer_role': 'utility', 'target_gw': 'gateway', 'slots': context['slots'], 'issued_at': policy['issued_at'],
                   'not_before': policy['issued_at'], 'expires_at': policy['expires_at'], 'metric_id': context['metric_id'], 'param_id': context['param_id'],
                   'policy_ref': uuid.uuid4().hex, 'token_bundle': tokens, 'security_profile': 'SAB', 'key_epoch': policy['key_epoch'], 'trust_registry_digest': policy['trust_registry_digest'],
                   'governance': policy, 'policy_digest': context['policy_digest'], 'task_nonce': context['task_nonce']}
        authorization, timing = sign_object(payload, self.runtime)
        self.perf.extend(timing)
        write(self.private / 'authorization.json', authorization, True)
        sent = copy.deepcopy(authorization)
        if self.args.fault == 'invalid_authorization':
            sent['payload']['governance']['dataset_digest'] = '0'*96
        listener = Listener(self.args.l2, 'utility', 'gateway', self.selected.group, self.runtime, 'L2', self.selected.sm4_channel)
        self.emit('AUTH_READY')
        write(self.private / 'ready.json', {'ready': True})
        published = {'run_id': self.args.run_id, 'governance': policy, 'results': [], 'receipts': [], 'signature_evidence': [], 'snapshots': {}, 'audit_checkpoints': {}, 'accepted_manifests': {}, 'result_statements': []}
        try:
            with listener.accept() as connection:
                self.connections.append(connection.evidence)
                for expected in ('pull_authorization', *['submit_receipt']*len(context['slots']), 'finish'):
                    msg = connection.receive()
                    if msg.get('run_id') != self.args.run_id or msg.get('type') != expected:
                        raise Rejected('REQUEST_CONTEXT_OR_ORDER_INVALID')
                    if expected == 'pull_authorization':
                        connection.send({'request_id': msg['request_id'], 'authorization': sent, 'context': context})
                    elif expected == 'finish':
                        connection.send({'request_id': msg['request_id'], 'finished': True})
                    else:
                        receipt, evidence = verify_object(msg['receipt'], f"GRID_AGG_RECEIPT_V{context['schema_version']}", 'SAB', self.runtime)
                        evidence['v42_links'] = verify_links(receipt, msg['snapshot'], msg['audit'], msg['accepted_ids'], policy)
                        check_authorization(payload, context, 'SAB')
                        slot = receipt['slot_id']
                        if (any(receipt[key] != context[key] for key in ('task_id', 'run_id', 'param_id')) or receipt['authorization_digest'] != digest(payload)
                                or slot != context['slots'][len(published['results'])]['slot_id']):
                            raise Rejected('RECEIPT_CONTEXT_MISMATCH')
                        started = time.perf_counter_ns()
                        value = pfdam.verify_recover(self.public, secret, receipt['aggregate_ciphertext'], receipt['native_timestamp'], receipt['native_signature'], receipt['counts']['accepted'])
                        self.timed('native_verify_recover', started, slot)
                        self.perf.extend(evidence['timings'])
                        target_count = read(self.private / 'config.json')['expected_target_count']
                        result = {'slot_id': slot, 'value_W': value, 'unit': 'W', 'counts': receipt['counts'], 'receipt_digest': digest(receipt), 'status': 'PUBLISHED' if value is not None else 'NO_VALID_DATA',
                                  'coverage_basis_points': receipt['counts']['accepted']*10000//target_count if target_count else None, 'expected_target_count': target_count,
                                  'published_value': present_value(policy['function'], value, receipt['counts']['accepted']),
                                  **{key: receipt[key] for key in ('snapshot_root', 'policy_digest', 'aggregation_digest', 'audit_root')}}
                        from .result_attestation import attest
                        if context['schema_version'] == 5:
                            result['status'] = 'INTERNAL_READY'
                            statement, result_timing = None, []
                        else:
                            statement, result_timing = attest(result, receipt, policy, context, self.runtime)
                        self.perf.extend(result_timing)
                        if statement is not None:
                            published['result_statements'].append(statement)
                        published['results'].append(result)
                        published['receipts'].append(msg['receipt'])
                        published['signature_evidence'].append(evidence)
                        published['snapshots'][slot], published['audit_checkpoints'][slot], published['accepted_manifests'][slot] = msg['snapshot'], msg['audit'], msg['accepted_ids']
                        write(self.private / 'published.json', published, True)
                        if context['schema_version'] == 5:
                            self.emit('COMPUTED_PRIVATE', slot_id=slot)
                        else:
                            self.emit('PUBLISHED', slot_id=slot, accepted_count=receipt['counts']['accepted'])
                        connection.send({'request_id': msg['request_id'], 'accepted': True})
        finally:
            listener.close()

    def gateway(self):
        secret = read(self.runtime / 'gateway/pfdam.json')
        with ExitStack() as stack:
            connection = stack.enter_context(TLS.connect(self.args.l2, 'gateway', 'utility', self.selected.group, self.runtime, 'L2', self.selected.sm4_channel))
            self.connections.append(connection.evidence)
            connection.send(message('pull_authorization', self.args.run_id))
            response = connection.receive()
            context = checked_context(response['context'])
            authorization, evidence = verify_object(response['authorization'], f"GRID_TASK_AUTH_V{context['schema_version']}", 'SAB', self.runtime)
            check_authorization(authorization, context, 'SAB')
            policy = context['governance']
            if policy['algorithm_suite'] != self.args.suite:
                raise Rejected('AUTH_CRYPTO_SUITE_MISMATCH')
            self.perf.extend(evidence['timings'])
            evidence['context_valid'] = True
            write(self.private / 'authorization_evidence.json', evidence, True)
            listeners = []
            for source in policy['sources']:
                name = source['source_id']
                listener = Listener(self.sources[name], 'gateway', name, self.selected.group, self.runtime, 'L1-'+name, self.selected.sm4_channel)
                stack.callback(listener.close)
                listeners.append((source, listener))
            write(self.private / 'ready.json', {'ready': True})
            links = []
            for source, listener in listeners:
                client = stack.enter_context(listener.accept())
                self.connections.append(client.evidence)
                if client.evidence.get('peer_certificate_sha256') != source['certificate_sha256']:
                    raise Rejected('SOURCE_CERTIFICATE_BINDING_MISMATCH')
                request = client.receive()
                if request.get('type') != 'pull_context' or request.get('run_id') != self.args.run_id:
                    raise Rejected('SOURCE_CONTEXT_REQUEST_INVALID')
                client.send({'request_id': request['request_id'], 'context': context})
                links.append((source, client))
            accepted_by_slot = {}
            for slot in context['slots']:
                reports, source_roots, pending = [], [], []
                for source, client in links:
                    batch = client.receive()
                    if batch.get('type') != 'report_batch' or batch.get('run_id') != self.args.run_id or batch.get('slot_id') != slot['slot_id'] or len(batch.get('reports', [])) > source['node_count']:
                        raise Rejected('SOURCE_BATCH_CONTEXT_INVALID')
                    records = [validate(ReportEnvelopeV3, record) for record in batch['reports']]
                    for record in records:
                        if any(record[key] != context[key] for key in ('task_id', 'run_id', 'param_id')) or record['slot_id'] != slot['slot_id'] or record['source_id'] != source['source_id']:
                            raise Rejected('SOURCE_REPORT_IDENTITY_OR_CONTEXT_MISMATCH')
                    sealed = snapshot(records, policy['dataset_version'], slot['slot_id'])
                    if batch['source_snapshot_root'] != sealed['merkle_root'] or batch['partition_digest'] != source['partition_digest']:
                        raise Rejected('SOURCE_SNAPSHOT_OR_PARTITION_MISMATCH')
                    source_roots.append({'source_id': source['source_id'], 'root': sealed['merkle_root'], 'count': len(records),
                                         'partition_digest': source['partition_digest'], 'certificate_sha256': source['certificate_sha256']})
                    reports.extend(records)
                    pending.append((batch, client))
                started = time.perf_counter_ns()
                aggregate, accepted, rejected = pfdam.match_and_aggregate(self.public, secret, authorization['token_bundle'][slot['slot_id']], reports)
                self.timed('match_and_aggregate', started, slot['slot_id'])
                union = snapshot(reports, policy['dataset_version'], slot['slot_id'])
                stamp = utc()
                native_signature = pfdam.native_sign(secret, aggregate, stamp)
                audit = checkpoint(context, slot['slot_id'], union, len(accepted), stamp)
                codes = [record['code'] for record in rejected]
                payload = {'object_type': f"GRID_AGG_RECEIPT_V{context['schema_version']}", 'schema_version': context['schema_version'], 'task_id': context['task_id'], 'run_id': self.args.run_id,
                           'authorization_digest': digest(authorization), 'snapshot_id': uuid.uuid4().hex, 'slot_id': slot['slot_id'], 'param_id': context['param_id'],
                           'aggregate_ciphertext': str(aggregate), 'native_signature': native_signature, 'native_timestamp': stamp,
                           'counts': {'received': len(reports), 'accepted': len(accepted), 'joint_check_failed': codes.count('REPORT_JOINT_CHECK_FAILED'), 'invalid': sum(code not in ('REPORT_JOINT_CHECK_FAILED', 'REPORT_DUPLICATE') for code in codes), 'duplicate': codes.count('REPORT_DUPLICATE'), 'late': 0},
                           'status': 'AGGREGATED' if accepted else 'NO_VALID_DATA', 'issued_at': stamp, 'input_digest': digest(sorted(record['report_id'] for record in reports)),
                           'key_epoch': policy['key_epoch'], 'trust_registry_digest': policy['trust_registry_digest'], 'security_profile': 'SAB', 'policy_digest': context['policy_digest'], 'algorithm_suite': self.args.suite,
                           'dataset_version': policy['dataset_version'], 'dataset_digest': policy['dataset_digest'], 'snapshot_root': union['merkle_root'], 'snapshot_count': len(reports),
                           'snapshot_hash': 'SM3', 'accepted_set_digest': accepted_digest(accepted), 'audit_root': audit['root'], 'source_snapshots': source_roots}
                payload['aggregation_digest'] = aggregation_digest(payload)
                if context['schema_version'] == 5:
                    payload.update(release_rules_digest=policy['release_rules_digest'], release_plan_id=policy['release_plan_id'])
                signed, timing = sign_object(payload, self.runtime)
                self.perf.extend(timing)
                if self.args.fault == 'invalid_receipt':
                    signed['payload']['dataset_digest'] = '0'*96
                connection.send(message('submit_receipt', self.args.run_id, receipt=signed, snapshot=union, audit=audit, accepted_ids=accepted))
                if not connection.receive().get('accepted'):
                    raise Rejected('RECEIPT_REJECTED')
                accepted_by_slot[slot['slot_id']] = accepted
                write(self.private / 'accepted.json', accepted_by_slot, True)
                self.emit('AGGREGATED', slot_id=slot['slot_id'], accepted_count=len(accepted))
                for batch, client in pending:
                    client.send({'request_id': batch['request_id'], 'received': True})
            for source, client in links:
                request = client.receive()
                if request.get('type') != 'finish' or request.get('run_id') != self.args.run_id:
                    raise Rejected('SOURCE_FINISH_CONTEXT_INVALID')
                client.send({'request_id': request['request_id'], 'finished': True})
            connection.send(message('finish', self.args.run_id))
            connection.receive()

    def source(self):
        data = read(self.private / 'dataset.json')
        with TLS.connect(self.sources[self.role], self.role, 'gateway', self.selected.group, self.runtime, 'L1-'+self.role, self.selected.sm4_channel) as connection:
            self.connections.append(connection.evidence)
            connection.send(message('pull_context', self.args.run_id))
            context = checked_context(connection.receive()['context'])
            policy = check_policy(context['governance'], context['policy_digest'], 'SAB')
            binding = next(source for source in policy['sources'] if source['source_id'] == self.role)
            body={key:value for key,value in data.items() if key!='partition_digest'}
            if context['schema_version']==5:
                from .publication import input_binding
                actual_binding=input_binding(self.role,'source-partition',body,runtime=self.runtime)
            else:
                actual_binding=digest(body)
            if (actual_binding != binding['partition_digest']
                    or data['parent_dataset_digest'] != policy['dataset_digest'] or canonical(data['slots']) != canonical(context['slots'])
                    or certificate_hash(credentials(self.runtime, self.role)[1]) != binding['certificate_sha256']):
                raise Rejected('SOURCE_PRIVATE_DATA_BINDING_MISMATCH')
            injection = read(self.private / 'injection.json')
            mappings = {}
            operational = {'source_id': self.role, 'run_id': self.args.run_id, 'plan_id': policy.get('release_plan_id'),
                           'partition_digest': data['partition_digest'], 'slots': {}}
            roster = read(self.private / 'participation-roster.json') if context['schema_version'] == 5 else {}
            for index, slot in enumerate(context['slots']):
                started = time.perf_counter_ns()
                reports, mapping = [], {}
                for node in data['nodes']:
                    if node['node_id'] in injection['omitted'].get(slot['slot_id'], []):
                        continue
                    label = pfdam.tag(context, slot['slot_id'], node['region'], node['resource_class'])
                    report = pfdam.report(self.public, node['values_W'][index], label, utc())
                    if node['node_id'] in injection['modified'].get(slot['slot_id'], []):
                        n = decimal(self.public['N'])
                        report['CT'] = str(decimal(report['CT'])*(1+n) % (n*n))
                    record = {'task_id': context['task_id'], 'run_id': self.args.run_id, 'slot_id': slot['slot_id'], 'param_id': context['param_id'], 'report': report, 'source_id': self.role}
                    if self.args.fault == 'source_identity' and self.role == 'source-1':
                        record['source_id'] = 'source-2'
                    record['report_id'] = digest(record)
                    reports.append(record)
                    mapping[record['report_id']] = node['node_id']
                sealed = snapshot(reports, policy['dataset_version'], slot['slot_id'])
                if self.args.fault == 'snapshot_tamper' and self.role == 'source-1':
                    sealed['merkle_root'] = '0'*64
                mappings[slot['slot_id']] = mapping
                write(self.private / 'oracle_mapping.json', mappings, True)
                if context['schema_version'] == 5:
                    operational['slots'][slot['slot_id']] = {rid: roster[node_id] for rid, node_id in mapping.items()}
                    write(self.private / 'participation.json', operational, True)
                self.timed('generate_reports', started, slot['slot_id'])
                connection.send(message('report_batch', self.args.run_id, slot_id=slot['slot_id'], reports=reports, source_snapshot_root=sealed['merkle_root'], partition_digest=data['partition_digest']))
                if not connection.receive().get('received'):
                    raise Rejected('REPORT_BATCH_REJECTED')
                self.emit('REPORTS_READY', slot_id=slot['slot_id'], report_count=len(reports))
            connection.send(message('finish', self.args.run_id))
            connection.receive()

def main():
    parser = argparse.ArgumentParser()
    for name in ('role', 'runtime', 'job', 'run-id', 'suite', 'sources'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--l2', type=int, required=True)
    parser.add_argument('--fault', default='normal')
    args = parser.parse_args()
    worker = Worker(args)
    try:
        getattr(worker, 'source' if args.role.startswith('source-') else args.role)()
        worker.emit('COMPLETED')
        return 0
    except Exception as exc:
        code = getattr(exc, 'code', 'CORE_OPERATION_FAILED')
        write(worker.private / 'error.json', {'code': code, 'message': str(exc), 'role': worker.role}, True)
        worker.emit('FAILED', code=code)
        return 1
    finally:
        worker.save()

if __name__ == '__main__':
    sys.exit(main())
