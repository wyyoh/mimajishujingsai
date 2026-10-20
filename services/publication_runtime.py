"""UC finalization and safe public artifacts for V5 tasks."""
import time
from .encoding import Rejected, digest
from .initialization import RUNTIME, ROOT
from .storage import read, write
from .native import utc
from .publication import release_task, verify_statement


def install_package(manifest, computed, package):
    """Install the authorized projection; callers persist the final manifest.

    In particular, response evaluations must collect all child link/isolation
    evidence before a polling client can observe a terminal status.
    """
    run = ROOT / 'artifacts/runs' / manifest['run_id']
    decision = package['release']['decision']
    if decision == 'EXPERIMENT_NOT_RELEASED' or package.get('private_measurement'):
        manifest.update(results=[],publication_status='NOT_PUBLISHED',status='EXPERIMENT_ONLY',private_experiment=True)
        return manifest
    manifest.update(results=package['results'], publication_status=decision,
                    status='COMPLETED' if decision == 'PUBLISHED' else 'WITHHELD' if decision == 'WITHHELD' else 'EXPERIMENT_ONLY',
                    uc_result_signatures_verified=True, release_rules_digest=package['release']['rules_digest'])
    write(run / 'release.json', package['release'])
    write(run / 'release_statement.json', package['release_statement'])
    write(run / 'result_statements.json', package['result_statements'])
    if decision == 'PUBLISHED':
        for name in ('receipts', 'signature_evidence', 'snapshots', 'audit_checkpoints', 'accepted_manifests'):
            if name in computed:
                write(run / f'{name}.json', computed[name])
    return manifest


def finish(policy, context, manifest, computed, dataset, parts, injection, failure, *, elapsed_start, lab, deferred, private_control):
    run_id = manifest['run_id']
    run, job = ROOT / 'artifacts/runs' / run_id, RUNTIME / 'runs' / run_id
    write(job / 'utility/computed.json', computed, True)
    write(job / 'utility/task-context.json', context, True)
    if failure:
        manifest.update(status='CANCELLED' if failure == 'CANCELLED_BY_USER' else 'REJECTED', results=[],
                        errors=[{'code': failure}], publication_status='NOT_PUBLISHED')
    else:
        try:
            participation = {part['source_id']: read(job / part['source_id'] / 'participation.json') for part in parts}
            write(job / 'utility/participation.json', participation, True)
            if lab:
                from tests.oracle.reference import expected, compare
                mappings = {slot['slot_id']: {} for slot in dataset['slots']}
                for part in parts:
                    for slot, mapping in read(job / part['source_id'] / 'oracle_mapping.json').items():
                        mappings[slot].update(mapping)
                checks = []
                for index, row in enumerate(computed['results']):
                    slot = row['slot_id']
                    reference = expected(dataset, policy['region'], policy['resources'], index,
                                         injection['omitted'].get(slot, []), injection['modified'].get(slot, []))
                    checks.append({'slot_id': slot, **compare(reference, computed['accepted_manifests'][slot], mappings[slot], row['value_W'])})
                write(job / 'utility/oracle-summary.json', checks, True)
                manifest['oracle_match'] = len(checks) == policy['slot_count'] and all(row['set_match'] and row['value_match'] for row in checks)
                if not manifest['oracle_match']:
                    raise Rejected('INDEPENDENT_ORACLE_MISMATCH')
            if deferred:
                manifest.update(status='COMPUTED', results=[], publication_status='WAITING_FOR_EVALUATION')
            else:
                plan = read(job / 'utility/release-plan.json')
                package = release_task(policy, computed, participation, plan, context, private_control=private_control)
                verify_statement(package['release_statement'], package['release'], expected={'run_id': run_id}, usage='current')
                install_package(manifest, computed, package)
        except (Rejected, KeyError, ValueError, FileNotFoundError) as exc:
            write(job / 'utility/release-error.json', {'code': getattr(exc, 'code', 'RELEASE_FINALIZATION_FAILED'), 'message': str(exc)}, True)
            manifest.update(status='REJECTED', results=[], publication_status='NOT_PUBLISHED',
                            errors=[{'code': getattr(exc, 'code', 'RELEASE_FINALIZATION_FAILED')}])
    manifest.update(finished_at=utc(), elapsed_ns=time.perf_counter_ns()-elapsed_start)
    write(run / 'run_manifest.json', manifest)
    return manifest


def recover(manifest):
    """Never recover the unfiltered UC computed/published file as a public view."""
    from .custody import load_root
    run_id=manifest['run_id']
    job=RUNTIME/'runs'/run_id/'utility'
    state=load_root(RUNTIME).get('publication_state',{})
    committed=state.get('commits',{}).get(run_id)
    stage=job/'release-ready.json'
    try:
        if not committed or not stage.is_file():
            raise Rejected('RESTARTED_WITHOUT_COMMITTED_PUBLICATION')
        package=read(stage)
        if digest(package)!=committed:
            raise Rejected('PUBLICATION_STAGED_CONTENT_CHANGED')
        verify_statement(package['release_statement'],package['release'],expected={'run_id':run_id})
        computed=read(job/'computed.json') if (job/'computed.json').is_file() else {}
        if manifest.get('evaluation_id') and package['release']['decision']=='PUBLISHED' and not package.get('private_measurement'):
            from .response import verify_evaluation
            verify_evaluation(package['evaluation'],package['evaluation_statement'],package['evaluation_inputs'],
                              expected={'run_id':run_id},parent_policy=read(ROOT/'artifacts/runs'/run_id/'governance.json'))
            for name in ('evaluation','evaluation_statement','evaluation_inputs'):
                write(ROOT/'artifacts/runs'/run_id/f'{name}.json',package[name])
        install_package(manifest,computed,package)
        if manifest.get('evaluation_id'):
            from .response import collect_child_evidence
            collect_child_evidence(manifest,ROOT/'artifacts/runs'/run_id)
    except (Rejected,KeyError,ValueError,FileNotFoundError) as exc:
        manifest.update(status='CANCELLED',results=[],publication_status='NOT_PUBLISHED',
                        errors=[{'code':getattr(exc,'code','PUBLICATION_RECOVERY_FAILED')}])
    manifest.update(recovered_after_restart=True,finished_at=utc())
    write(ROOT/'artifacts/runs'/run_id/'run_manifest.json',manifest)
    return manifest
