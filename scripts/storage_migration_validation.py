"""Interrupted legacy storage migration with disposable, private test fixtures."""
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
runtime=Path(tempfile.mkdtemp(prefix='grid-storage-migration-',dir=str(Path.home())))
os.environ['GRID_RUNTIME']=str(runtime)
os.environ['GRID_CUSTODY_PASSPHRASE']=secrets.token_urlsafe(32)
from services import custody
from services.agility import sm4_gcm
from services.encoding import Rejected, canonical
from services.native import LIB, utc
from services.storage import read, write
from services.versioning import source_version


def main():
    started,frozen=utc(),source_version()
    for role in ('utility','source'): (runtime/role).mkdir(mode=0o700)
    key=runtime/'source/tls.key'
    mask=os.umask(0o077)
    try:
        # New unmanaged fixture emulates legacy input; no real role key is exported.
        subprocess.run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:prime256v1','-out',str(key)],capture_output=True,check=True)
    finally: os.umask(mask)
    public_before=subprocess.check_output(['openssl','pkey','-in',str(key),'-pubout','-outform','DER'])
    expected={'source':{'fixture':'synthetic legacy readings','values':[1,2,3]},'utility':{'fixture':'synthetic legacy secret','value':'private-fixture-only'}}
    for role,value in expected.items(): custody.atomic(runtime/role/'fixture.json',canonical(value))
    original_atomic=custody.atomic
    def interrupted(path,data):
        if Path(path)==runtime/'source/fixture.json': raise OSError('INJECTED_LEGACY_MIGRATION_WRITE_FAILURE')
        return original_atomic(path,data)
    custody.atomic=interrupted
    try:
        try: custody.enable(runtime)
        except OSError as exc: assert str(exc)=='INJECTED_LEGACY_MIGRATION_WRITE_FAILURE'
        else: raise AssertionError('Fault was not injected')
    finally: custody.atomic=original_atomic
    assert not read(runtime/'security/custody.json')['ready']
    assert key.read_bytes().startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----')
    custody.enable(runtime)
    assert read(runtime/'security/custody.json')['ready']
    for role,value in expected.items():
        path=runtime/role/'fixture.json'
        assert json.loads(path.read_text())['object_type']=='GRID_PRIVATE_JSON_V1'
        assert read(path)==value
    public_after=custody.openssl_with_key(['pkey','-in',str(key),'-pubout','-outform','DER'],key)
    assert public_before==public_after
    path=runtime/'source/fixture.json'
    envelope=json.loads(path.read_text())
    body={k:v for k,v in envelope.items() if k not in ('ciphertext','tag')}
    import base64
    storage_key=custody._derive(custody.role_key(runtime,'source'),bytes.fromhex(envelope['salt']),canonical({'domain':'GRID-STORAGE-V1','role':'source','path':'source/fixture.json'}))
    failures=[]
    for label,candidate_key,candidate_aad in [('wrong-key',bytes([storage_key[0]^1])+storage_key[1:],canonical(body)),('changed-AAD',storage_key,canonical({**body,'kdf':'changed'}))]:
        try: sm4_gcm(candidate_key,bytes.fromhex(envelope['nonce']),base64.b64decode(envelope['ciphertext']),candidate_aad,bytes.fromhex(envelope['tag']))
        except Rejected as exc: assert exc.code=='SM4_AUTHENTICATION_FAILED';failures.append(label)
        else: raise AssertionError(label+' accepted')
    assert source_version()==frozen
    record={'schema':'GRID_INTERRUPTED_SECRET_MIGRATION_VALIDATION_V1','started_at':started,'finished_at':utc(),**frozen,
            'command':[sys.executable,'scripts/storage_migration_validation.py'],'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'versions':json.loads(LIB.grid_library_info()),'private_runtime':str(runtime),'inputs':'Disposable legacy plaintext JSON and newly generated unmanaged EC private-key fixture, no existing production secrets exported',
            'interruption_detected':True,'ready_remained_false_on_interruption':True,'retry_completed':True,'private_public_key_correspondence_preserved':True,
            'authenticated_decryption_negatives_rejected':failures,'exit_code':0,'scope':'Per-file atomic migration/retry and real AEAD; not whole-history rewriting, full disk failure testing or secret erasure proof'}
    destination=root/'artifacts/iterations/standards/migration'/(started.replace(':','-')+'.json')
    write(destination,record)
    print(json.dumps({'record':str(destination.relative_to(root)),'exit_code':0}))

if __name__=='__main__':main()
