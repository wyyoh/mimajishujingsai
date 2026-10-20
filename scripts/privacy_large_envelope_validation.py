"""Read the original failed warmup's UC file without altering that evidence."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    from services.storage import read,write
    from services.encoding import MAX_OBJECT_BYTES,canonical
    from services.versioning import source_version
    from services.expansion_data import select
    from services.native import utc
    from tests.oracle.reference import expected,compare
    original=ROOT/'artifacts/iterations/privacy/benchmarks/release-protection-20261017-v1/900'
    plan=read(original/'plan.json');runtime=Path(plan['runtime'])
    parent=read(original/'raw.json')[0]['run_id']
    paths=[ROOT/'artifacts/runs'/directory.name/'run_manifest.json' for directory in (runtime/'runs').iterdir()]
    children=[path for path in paths if path.is_file() and read(path).get('parent_evaluation')==parent]
    assert len(children)==1
    child=read(children[0])['run_id'];job=runtime/'runs'/child
    path=job/'utility/published.json';before=hashlib.sha256(path.read_bytes()).hexdigest()
    computed=read(path,runtime=runtime)
    data=select('SYN-WEEK-V42',900,1,[68,69,70,71])
    maps={slot['slot_id']:{} for slot in data['slots']}
    for source in ('source-1','source-2','source-3'):
        for slot,mapping in read(job/source/'oracle_mapping.json',runtime=runtime).items():maps[slot].update(mapping)
    checks=[]
    for index,row in enumerate(computed['results']):
        reference=expected(data,'A',['residential','commercial','charging'],index)
        check=compare(reference,computed['accepted_manifests'][row['slot_id']],maps[row['slot_id']],row['value_W'])
        assert check['set_match'] and check['value_match'];checks.append(check)
    assert len(checks)==4 and path.stat().st_size>MAX_OBJECT_BYTES and len(canonical(computed))<=MAX_OBJECT_BYTES
    assert hashlib.sha256(path.read_bytes()).hexdigest()==before
    record={'status':'PASS','checked_at':utc(),**source_version(),'original_core_source_digest':plan['core_source_digest'],
            'original_failed_warmup_run_id':parent,'original_child_run_id':child,
            'original_private_file_ciphertext_sha256':before,'encrypted_outer_bytes':path.stat().st_size,
            'decrypted_json_bytes':len(canonical(computed)),'plaintext_limit_bytes':MAX_OBJECT_BYTES,
            'independent_windows':4,'sets_and_integer_sums_match':True,'original_bytes_unchanged':True,
            'command':[sys.executable,*sys.argv],'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'scope':'Read-only repair diagnostic, not a successful measured execution or replacement of the failed warmup.'}
    destination=ROOT/'artifacts/iterations/privacy/storage-boundary'/('verification-'+utc().replace(':','-')+'.json')
    write(destination,record)
    print(json.dumps({'record':str(destination.relative_to(ROOT)),'status':'PASS'}))


if __name__=='__main__':main()
