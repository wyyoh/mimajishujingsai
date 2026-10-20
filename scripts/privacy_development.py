"""Explicit local development probe; never prints or exports account secrets."""
import json
import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault('GRID_RUNTIME', str(Path.home()/'.local/share/grid-privacy-development-v1'))


def approve_current_program():
    from services.initialization import RUNTIME
    from services.custody import enabled, load_root
    if not enabled(RUNTIME):
        return
    from services import management
    if load_root(RUNTIME)['program_pin'] in (None, management.program_fingerprint()):
        return
    from services.sessions import initialize_access, ACCESS_PATH
    from services.storage import read
    initialize_access()
    accounts = read(ACCESS_PATH)['accounts']
    request = management.request('approve-program', management.program_fingerprint(), 'User-authorized privacy/scenario implementation validation',
                                 'grid_key_manager', accounts['grid_key_manager'])
    management.approve(request['request_id'], 'grid_security_approver', accounts['grid_security_approver'])
    management.execute(request['request_id'], 'grid_key_manager', accounts['grid_key_manager'])


def main():
    approve_current_program()
    from services.orchestrator import initialize
    initialize()
    from services.sessions import initialize_access
    initialize_access()
    if len(sys.argv) > 1 and sys.argv[1] == 'init':
        print(json.dumps({'initialized': True}))
        return
    if len(sys.argv)>1 and sys.argv[1]=='test':
        import subprocess
        from services.native import utc
        output=ROOT/'artifacts/iterations/privacy/test-records'/utc().replace(':','-')
        command=[sys.executable,'-m','pytest',*(sys.argv[2:] or ['tests/test_publication.py','-q'])]
        process=subprocess.run(command,cwd=ROOT,env={**os.environ,'GRID_TEST_OUTPUT':str(output),'GRID_LAB':'0'})
        print(json.dumps({'exit_code':process.returncode,'evidence_directory':str(output.relative_to(ROOT))}))
        raise SystemExit(process.returncode)
    if len(sys.argv)>1 and sys.argv[1]=='evaluation':
        from services.response import execute,EvaluationRequest
        result=execute(EvaluationRequest(nodes=300,source_count=3,request_nonce=uuid.uuid4().hex),'grid_operator_A',lab=True)
        print(json.dumps({key:result.get(key) for key in ('run_id','status','publication_status','errors','children','elapsed_ns')}))
        if result['status']=='REJECTED':
            from services.initialization import RUNTIME
            from services.storage import read
            print(json.dumps(read(RUNTIME/'runs'/result['run_id']/'utility/evaluation-error.json')))
            raise SystemExit(1)
        if result['publication_status']=='PUBLISHED':
            from services.evidence import export_public,verify_export
            verified=verify_export(export_public(result['run_id']),expected_context={'run_id':result['run_id']})
            print(json.dumps({'archive_verified':verified['release_decision_verified']}))
        return
    from services.publication import prepare
    from services.expansion_schemas import ExpansionRequest
    from services.expansion_orchestrator import execute
    request = ExpansionRequest(nodes=300, periods=[68], scene_id='park', source_count=3, request_nonce=uuid.uuid4().hex)
    policy, _, _ = prepare(request, 'grid_operator_A')
    value = execute(policy, lab=True)
    print(json.dumps({key: value.get(key) for key in ('run_id','protocol_version','status','publication_status','errors','oracle_match','role_file_isolation')}))
    if value['status'] != 'COMPLETED':
        from services.initialization import RUNTIME
        from services.storage import read
        job = RUNTIME/'runs'/value['run_id']
        for path in job.glob('*/error.json'):
            print(json.dumps(read(path)))
        if (job/'utility/release-error.json').exists():
            print(json.dumps(read(job/'utility/release-error.json')))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
