"""Real V5 restart/cancel boundaries with private computation and atomic publication."""
import concurrent.futures
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import select
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import pytest
from services.initialization import ROOT,RUNTIME
from services.orchestrator import free_port,initialize
from services.storage import read,write
from services.evidence import verify_export
from tests.provenance import record_run,observe


def isolated_runtime():
    initialize()
    target=Path(tempfile.mkdtemp(prefix='grid-recovery-private-',dir='/tmp'))
    for name in ('public','ta','utility','gateway','source','source-1','source-2','source-3'):
        if (RUNTIME/name).exists():shutil.copytree(RUNTIME/name,target/name)
    if (RUNTIME/'datasets').exists():
        shutil.copytree(RUNTIME/'datasets',target/'datasets',ignore=shutil.ignore_patterns('original.zip','*.part'))
    shutil.copyfile(RUNTIME/'credentials.json',target/'credentials.json')
    from services.custody import load_root,save_root,atomic
    from services.encoding import canonical
    root=load_root(RUNTIME)
    root.update(runtime_id=hashlib.sha256(str(target.resolve()).encode()).hexdigest(),audit_head='0'*64,audit_count=0)
    root.pop('audit_gap',None)
    save_root(target,root)
    atomic(target/'security/custody.json',canonical({'schema':'GRID_CUSTODY_STATE_V1','ready':True}))
    return target


def start_server(runtime,*,pause_after_commit=False):
    port=free_port();log=(runtime/('server-'+uuid.uuid4().hex+'.log')).open('wb')
    process=subprocess.Popen([sys.executable,'-m','tests.server_harness'],cwd=ROOT,
        env={**os.environ,'GRID_RUNTIME':str(runtime),'GRID_LAB':'0','GRID_TEST_SERVER_PORT':str(port),
             'GRID_TEST_PAUSE_AFTER_COMMIT':'1' if pause_after_commit else '0'},
        stdout=log,stderr=log,start_new_session=True)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    base='http://127.0.0.1:'+str(port)
    def request(path,data=None,key=None,raw=False):
        headers={'Content-Type':'application/json'}
        if key is not None:headers['Idempotency-Key']=key
        query=urllib.request.Request(base+path,data=None if data is None else json.dumps(data).encode(),headers=headers)
        with opener.open(query,timeout=30) as response:return response.read() if raw else json.load(response)
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        if process.poll() is not None:
            log.flush();detail=Path(log.name).read_text()[-1500:];log.close()
            raise AssertionError('API startup failed: '+detail)
        try:
            request('/api/config')
            access=read(runtime/'operator-access.json',runtime=runtime)
            request('/api/session',{'subject':'grid_operator_A','password':access['accounts']['grid_operator_A']})
            return process,log,request
        except OSError:time.sleep(.05)
    stop_group(process,log)
    raise AssertionError('API startup timed out')


def stop_group(process,log):
    try:os.killpg(process.pid,signal.SIGTERM)
    except ProcessLookupError:pass
    try:process.wait(timeout=10)
    except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
    log.close()


def wait_private_computed(runtime,run_id):
    path=runtime/'runs'/run_id/'utility/published.json'
    deadline=time.monotonic()+90
    while time.monotonic()<deadline:
        if path.exists() and read(path,runtime=runtime)['results']:return read(path,runtime=runtime)
        time.sleep(.02)
    raise AssertionError('No actual private UC computation before timeout')


def wait_commit_barrier(runtime,run_id):
    path=runtime/'runs'/run_id/'utility/test-after-commit.json'
    deadline=time.monotonic()+240
    while time.monotonic()<deadline:
        if path.exists():return
        time.sleep(.05)
    raise AssertionError('No actual post-commit barrier before timeout')


def wait_terminal(request,run_id):
    deadline=time.monotonic()+120
    while time.monotonic()<deadline:
        state=request('/api/runs/'+run_id)
        if state['status']!='RUNNING':return state
        time.sleep(.05)
    raise AssertionError('Run remained RUNNING')


def body():
    return {'nodes':300,'source_count':3,'scene_id':'park','periods':[68,69,70,71],'request_nonce':uuid.uuid4().hex}


def role_handles(runtime,run_id):
    handles=[]
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():continue
        try:
            args=(entry/'cmdline').read_bytes().split(bytes([0]))
            if b'services.expansion_workers' in args and run_id.encode() in args and str(runtime).encode() in args:
                handles.append(os.pidfd_open(int(entry.name)))
        except (OSError,ProcessLookupError):pass
    return handles


def assert_no_public_export(request,run_id):
    with pytest.raises(urllib.error.HTTPError) as error:request('/api/runs/'+run_id+'/export',raw=True)
    assert error.value.code==409


@pytest.mark.recovery('R05')
def test_crashed_service_replay_is_terminal_and_keeps_published_snapshot():
    runtime=isolated_runtime();server,log,request=start_server(runtime);second=None;handles=[]
    key=uuid.uuid4().hex;payload=body()
    try:
        identifier=request('/api/expansion/collaborations',payload,key)['run_id'];record_run(identifier)
        private=wait_private_computed(runtime,identifier);assert private['results']
        assert request('/api/runs/'+identifier)['results']==[]
        handles=role_handles(runtime,identifier);assert handles
        server.kill();server.wait(timeout=5)
        second,second_log,next_request=start_server(runtime)
        assert next_request('/api/expansion/collaborations',payload,key)=={'run_id':identifier,'idempotent':True}
        state=next_request('/api/runs/'+identifier)
        assert state['status']=='CANCELLED' and state['results']==[]
        assert state['errors'][0]['code']=='RESTARTED_WITHOUT_COMMITTED_PUBLICATION'
        for handle in handles:
            poll=select.poll();poll.register(handle,select.POLLIN);assert poll.poll(1000)
        assert_no_public_export(next_request,identifier)
        observe('crash_before_commit',{'run_id':identifier,'status':state['status'],'stopped_role_handles':len(handles),'public_results':0})
    finally:
        for handle in handles:os.close(handle)
        if second is not None:stop_group(second,second_log)
        stop_group(server,log)


@pytest.mark.recovery('R03')
def test_cancel_during_calculation_retains_verified_publication():
    runtime=isolated_runtime();server,log,request=start_server(runtime)
    try:
        identifier=request('/api/expansion/collaborations',body(),uuid.uuid4().hex)['run_id'];record_run(identifier)
        assert wait_private_computed(runtime,identifier)['results']
        assert request('/api/runs/'+identifier+'/cancel',{})['cancel_requested']
        state=wait_terminal(request,identifier)
        assert state['status']=='CANCELLED' and state['results']==[]
        assert_no_public_export(request,identifier)
        observe('cancel_before_commit',{'run_id':identifier,'status':state['status'],'private_computation_was_ready':True,'public_results':0})
    finally:stop_group(server,log)


@pytest.mark.recovery('R04')
def test_concurrent_api_retry_and_completed_replay_survive_process_restart():
    from services.expansion_data import select as select_data
    runtime=isolated_runtime();server,log,request=start_server(runtime)
    key=uuid.uuid4().hex;payload=body()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            replies=list(pool.map(lambda _:request('/api/expansion/collaborations',payload,key),range(2)))
        assert len({row['run_id'] for row in replies})==1 and sorted(row['idempotent'] for row in replies)==[False,True]
        identifier=replies[0]['run_id'];record_run(identifier);state=wait_terminal(request,identifier)
        assert state['status']=='COMPLETED'
        original=select_data('SYN-WEEK-V42',300,0,payload['periods'])
        expected=[sum(node['values_W'][i] for node in original['nodes'] if node['region']=='A') for i in range(4)]
        assert [row['value_W'] for row in state['results']]==expected
        release=ROOT/'artifacts/runs'/identifier/'release.json';before=hashlib.sha256(release.read_bytes()).hexdigest()
        with pytest.raises(AssertionError,match='API_ALREADY_RUNNING_FOR_RUNTIME'):start_server(runtime)
        stop_group(server,log);server,log,request=start_server(runtime)
        assert request('/api/expansion/collaborations',payload,key)=={'run_id':identifier,'idempotent':True}
        replay=request('/api/runs/'+identifier)
        assert replay['status']=='COMPLETED' and replay['results']==state['results']
        assert hashlib.sha256(release.read_bytes()).hexdigest()==before
        with sqlite3.connect(runtime/'api.sqlite') as database:assert database.execute('SELECT count(*) FROM submissions').fetchone()[0]==1
        observe('restart_replay',{'run_id':identifier,'status':replay['status'],'release_sha256':before,'submission_rows':1})
    finally:stop_group(server,log)


@pytest.mark.recovery('R06')
@pytest.mark.parametrize('mutation',['receipt','result_count_type'])
def test_corrupted_durable_receipt_is_quarantined_on_restart(mutation):
    runtime=isolated_runtime();server,log,request=start_server(runtime,pause_after_commit=True);second=None
    try:
        identifier=request('/api/expansion/collaborations',body(),uuid.uuid4().hex)['run_id'];record_run(identifier)
        wait_commit_barrier(runtime,identifier)
        server.kill();server.wait(timeout=5)
        path=runtime/'runs'/identifier/'utility/release-ready.json';package=read(path,runtime=runtime)
        if mutation=='receipt':package['release_statement']['signatures'][0]['value']='AA=='
        else:package['results'][0]['counts']['accepted']=True
        write(path,package,True,runtime=runtime)
        second,second_log,next_request=start_server(runtime)
        state=next_request('/api/runs/'+identifier)
        assert state['status']=='CANCELLED' and state['results']==[]
        assert state['errors'][0]['code']=='PUBLICATION_STAGED_CONTENT_CHANGED'
        assert_no_public_export(next_request,identifier)
        observe('corrupt_committed_stage',{'run_id':identifier,'mutation':mutation,'status':state['status'],'public_results':0})
    finally:
        if second is not None:stop_group(second,second_log)
        stop_group(server,log)
