"""Verify the generated ZIP, install without network, and run a fresh ordinary SAB task."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path,PurePosixPath

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services.initialization import ROOT
from services.storage import read,write
from scripts.verify_acceptance_provenance import verify as verify_provenance

record=read(ROOT/'artifacts/tests/package_result.json')
archive=Path(record['archive'])
assert hashlib.sha256(archive.read_bytes()).hexdigest()==record['sha256']
base=Path(tempfile.mkdtemp(prefix='grid-delivery-verification-',dir='/tmp'))
with zipfile.ZipFile(archive) as z:
    assert len(z.infolist())<20000 and sum(f.file_size for f in z.infolist())<1024**3
    for item in z.infolist():
        p=PurePosixPath(item.filename)
        assert not p.is_absolute() and '..' not in p.parts and '\\' not in item.filename
    z.extractall(base)
manifest=json.loads((base/'delivery_manifest.json').read_text(encoding='utf-8'))
for name,sha in manifest['files'].items():assert hashlib.sha256((base/name).read_bytes()).hexdigest()==sha,name
public_provenance=verify_provenance(base,packaged=True)
code=r'''
import json,os,subprocess,sys,time,urllib.request,uuid
from pathlib import Path
from services.initialization import ROOT,RUNTIME
from services.dataset import generate
from services.storage import read
from services.evidence import verify_export
routes=subprocess.check_output(['ip','route','show'],text=True)
assert not routes.strip()
log=(ROOT.parent/'server.log').open('w')
server=subprocess.Popen([sys.executable,'-m','services.cli','serve'],cwd=ROOT,env={**os.environ,'GRID_LAB':'0'},stdout=log,stderr=subprocess.STDOUT)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
config=None
try:
    for attempt in range(100):
        if server.poll() is not None:
            log.flush();raise RuntimeError((ROOT.parent/'server.log').read_text()[-3000:])
        try:
            config=json.load(opener.open('http://127.0.0.1:8580/api/config',timeout=1));break
        except OSError:time.sleep(.1)
    assert config is not None, 'Local server readiness timed out'
    assert config['lab_enabled'] is False and config['default_profile']=='SAB'
    html=opener.open('http://127.0.0.1:8580/',timeout=3).read()
    assert b'<div id="root">' in html
    req=urllib.request.Request('http://127.0.0.1:8580/api/runs',data=json.dumps({'region':'A','resources':['residential','charging']}).encode(),headers={'Content-Type':'application/json','Idempotency-Key':uuid.uuid4().hex})
    run_id=json.load(opener.open(req))['run_id']
    for attempt in range(600):
        value=json.load(opener.open('http://127.0.0.1:8580/api/runs/'+run_id))
        if value['status']!='RUNNING':break
        time.sleep(.1)
    assert value['status']=='COMPLETED' and value['security_profile']=='SAB' and 'oracle_match' not in value
    fixture=generate();expected=[sum(n['values_W'][i] for n in fixture['nodes'] if n['region']=='A' and n['resource_class'] in ('residential','charging')) for i in range(4)]
    assert [r['value_W'] for r in value['results']]==expected
    evidence=json.load(opener.open('http://127.0.0.1:8580/api/runs/'+run_id+'/evidence'))
    assert len(evidence['connection_evidence'])==4 and all(c['actual_group']=='X25519MLKEM768' and c['peer_verified'] for c in evidence['connection_evidence'])
    output=ROOT.parent/'fresh-public-export.zip'
    output.write_bytes(opener.open('http://127.0.0.1:8580/api/runs/'+run_id+'/export').read())
    fresh=verify_export(output)
    assert all(c['signature_valid'] for c in fresh['receipt_checks'])
    old=next((ROOT.parent/'evidence/exports').glob('*.zip'))
    old_check=verify_export(old,ROOT.parent/'evidence/trusted-role-keys')
    assert all(c['signature_valid'] for c in old_check['receipt_checks'])
    result={'network_disabled':True,'routes':routes,'fresh_runtime':True,'fresh_virtual_environment':True,'static_ui_served':True,'ordinary_business_profile':'SAB','nodes':120,'slots':4,'independent_value_match':True,'actual_hybrid_both_links':True,'new_export_verified':True,'historical_export_verified_with_external_trust':True,'run_id':run_id,'param_id':value['param_id'],'core_source_digest':value['core_source_digest'],'role_file_isolation':value['role_file_isolation'],'scope':'exact locally generated ZIP in fresh directory and network namespace on same WSL host'}
    (ROOT.parent/'verification_result.json').write_text(json.dumps(result),encoding='utf-8')
    print(json.dumps(result))
finally:
    server.terminate();server.wait(timeout=10);log.close()
'''
command=['unshare','--user','--map-root-user','--net','bash','-c',
         'set -e; ip link set lo up; cd "$1"; bash scripts/install_offline.sh; exec .venv/bin/python -c "$2";',
         'delivery-test',str(base/'software'),code]
env={**os.environ,'GRID_RUNTIME':str(base/'private-runtime'),'PYTHONPATH':str(base/'software')}
process=subprocess.run(command,env=env,capture_output=True,text=True,timeout=240)
(ROOT/'artifacts/tests/package_install.log').write_text(process.stdout+process.stderr,encoding='utf-8')
history=ROOT/'artifacts/tests/history';history.mkdir(parents=True,exist_ok=True)
(history/(base.name+'.log')).write_text(process.stdout+process.stderr,encoding='utf-8')
write(history/(base.name+'.json'),{'zip_sha256':record['sha256'],'exit_code':process.returncode,'directory':str(base)})
assert process.returncode==0,process.stdout[-3000:]+process.stderr[-3000:]
result=json.loads((base/'verification_result.json').read_text(encoding='utf-8'))
result.update(zip_sha256=record['sha256'],zip_path=str(archive),exit_code=process.returncode,reproduction_directory=str(base))
result['acceptance_provenance_verified']=public_provenance
assert result['core_source_digest']==manifest['core_source_digest']
write(ROOT/'artifacts/tests/package_verification.json',result)
print(json.dumps(result))
