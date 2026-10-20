"""Actual mother-task crash/cancel; no half comparison becomes public."""
import uuid
from services.evidence import verify_export
from services.initialization import ROOT
from services.storage import read
from tests.provenance import record_run,observe
from tests.test_recovery import isolated_runtime,start_server,stop_group,wait_commit_barrier,wait_private_computed,wait_terminal,assert_no_public_export


def test_expansion_api_crash_stops_sources_and_retains_verified_receipts():
    runtime=isolated_runtime();server,log,request=start_server(runtime,pause_after_commit=True);second=None
    payload={'nodes':300,'source_count':3,'request_nonce':uuid.uuid4().hex};key=uuid.uuid4().hex
    try:
        identifier=request('/api/response/evaluations',payload,key)['run_id'];record_run(identifier)
        wait_commit_barrier(runtime,identifier)
        assert request('/api/runs/'+identifier)['results']==[]
        server.kill();server.wait(timeout=5)
        second,second_log,next_request=start_server(runtime)
        assert next_request('/api/response/evaluations',payload,key)['idempotent']
        restored=next_request('/api/runs/'+identifier)
        assert restored['status']=='COMPLETED' and restored['publication_status']=='PUBLISHED'
        archive=runtime/'recovered-evaluation.zip';archive.write_bytes(next_request('/api/runs/'+identifier+'/export',raw=True))
        result=verify_export(archive,runtime,expected_context={'run_id':identifier})
        assert result['release_decision_verified'] and result['business_metrics_recomputed'] and len(result['receipt_checks'])==16
        observe('mother_recovery_after_commit',{'run_id':identifier,'complete_inputs':16,'release_verified':True})
    finally:
        if second is not None:stop_group(second,second_log)
        stop_group(server,log)


def test_expansion_cancel_keeps_only_verified_multi_source_snapshots():
    import time
    runtime=isolated_runtime();server,log,request=start_server(runtime)
    try:
        identifier=request('/api/response/evaluations',{'nodes':300,'source_count':3,'request_nonce':uuid.uuid4().hex},uuid.uuid4().hex)['run_id'];record_run(identifier)
        deadline=time.monotonic()+60;child_id=None
        while time.monotonic()<deadline:
            for path in (ROOT/'artifacts/runs').glob('*/run_manifest.json'):
                child=read(path)
                if child.get('parent_evaluation')==identifier:child_id=child['run_id'];break
            if child_id:break
            time.sleep(.05)
        assert child_id and wait_private_computed(runtime,child_id)['results']
        assert request('/api/runs/'+identifier+'/cancel',{})['cancel_requested']
        state=wait_terminal(request,identifier)
        assert state['status']=='CANCELLED' and state['results']==[]
        assert request('/api/runs/'+identifier+'/evaluation')['evaluation'] is None
        assert_no_public_export(request,identifier)
        observe('mother_cancel_before_commit',{'run_id':identifier,'public_results':0,'private_child_was_ready':True})
    finally:stop_group(server,log)
