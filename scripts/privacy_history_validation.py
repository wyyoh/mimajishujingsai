"""Read original V1--V4 archives against independently retained local trust."""
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    from services.initialization import RUNTIME
    from services.storage import read,write
    from services.evidence import verify_export
    from services.versioning import source_version
    from services.native import utc
    from services.custody import trust_pin
    parameter=read(RUNTIME/'public/parameters.json')['param_id'];selected={}
    for path in sorted((ROOT/'artifacts/exports').glob('*.zip')):
        try:
            with zipfile.ZipFile(path) as archive:manifest=json.loads(archive.read('run_manifest.json'))
        except (KeyError,zipfile.BadZipFile):continue
        version=manifest.get('protocol_version',1)
        if version not in (1,2,3,4) or version in selected or manifest.get('param_id')!=parameter or manifest['status']!='COMPLETED' or manifest['security_profile']!='SAB':continue
        before=hashlib.sha256(path.read_bytes()).hexdigest()
        checked=verify_export(path,expected_context={'run_id':manifest['run_id'],'param_id':parameter,'security_profile':'SAB'})
        assert checked['receipt_authenticity_verified'] and bool(checked.get('uc_result_origin_and_integrity_verified'))==(version==4)
        assert hashlib.sha256(path.read_bytes()).hexdigest()==before
        selected[version]={'path':str(path.relative_to(ROOT)),'sha256':before,'run_id':manifest['run_id'],'protocol_version':version,
                           'original_source_digest':manifest['core_source_digest'],'receipt_authenticity_verified':True,'uc_result_statement_present':version==4}
        if len(selected)==4:break
    assert set(selected)=={1,2,3,4}
    report={'schema':'GRID_PRIVACY_ORIGINAL_HISTORY_CHECK_V1','exit_code':0,'checked_at':utc(),**source_version(),
            'command':[sys.executable,*sys.argv],'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'archives':list(selected.values()),'independently_retained_registry_pin':trust_pin(RUNTIME)['registry_pin'],
            'scope':'Original bytes unchanged. V1--V3 authenticate receipt metadata, never infer unsigned UC plaintext authentication. V4 requires UC_RESULT_V1. No trusted historical signing-time inference.'}
    destination=ROOT/'artifacts/iterations/privacy/history'/('verification-'+utc().replace(':','-')+'.json')
    write(destination,report);write(ROOT/'artifacts/iterations/privacy/current/history.json',report)
    print(json.dumps({'record':str(destination.relative_to(ROOT)),'original_versions_verified':sorted(selected)}))


if __name__=='__main__':main()
