"""Register the storage-boundary revision before a new 900-point attempt."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    from services.storage import read,write
    from services.versioning import source_version
    from services.native import utc
    original=ROOT/'artifacts/iterations/privacy/benchmarks/release-protection-20261017-v1'
    previous=original/('readiness-amendment.json' if (original/'readiness-amendment.json').exists() else 'storage-boundary-amendment.json')
    destination=original/('history-amendment.json' if previous.name=='readiness-amendment.json' else 'readiness-amendment.json' if previous.exists() else 'storage-boundary-amendment.json')
    if destination.exists():raise RuntimeError('Preserve the registered amendment')
    failed=read(original/'900/raw.json')
    assert len(failed)==1 and failed[0]['phase']=='warmup' and not failed[0]['success']
    plan=read(original/'900/plan.json')
    runtime=Path(plan['runtime'])
    error=runtime/'runs'/failed[0]['run_id']/'utility/evaluation-error.json'
    assert read(error,runtime=runtime)['code']=='OBJECT_TOO_LARGE'
    references=[]
    for size in (120,300):
        assert read(original/str(size)/'summary.json')['status']=='COMPLETED'
        for name in ('plan.json','raw.json','pairs.json','summary.json'):
            path=original/str(size)/name
            references.append({'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    for name in ('plan.json','raw.json','summary.json'):
        path=original/'900'/name
        references.append({'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    current=source_version()
    assert current['core_source_digest']!=plan['core_source_digest']
    record={'schema':'GRID_MEASUREMENT_STORAGE_AMENDMENT_V1','status':'REGISTERED','registered_at':utc(),
            'original_series':original.name,'original_core_source_digest':plan['core_source_digest'],**current,
            'new_series':'release-protection-20261017-storage-v2','remaining_size':900,'formal_pairs':5,'warmup_pairs':2,
            'prior_failed_warmup_attempts':1,'prior_failed_formal_attempts':0,'original_failed_run_id':failed[0]['run_id'],
            'recorded_secondary_failure_code':failed[0]['failure_code'],'diagnosed_primary_failure_code':'OBJECT_TOO_LARGE',
            'cause':'Base64 private envelope exceeded the unchanged 16 MiB generic JSON cap; private plaintext remained within that cap.',
            'change':'Bounded private envelope parsing only; public/API/wire and decrypted plaintext limits unchanged. UC read failure now records a terminal rejected child.',
            'unchanged':'PFDAM mathematics, native library, rules version 2, source count, fixed response, timing boundaries, sample counts and ordering seed.',
            'retained_successful_runs':38,'retained_failures':1,'references':references,
            'command':[sys.executable,*sys.argv],'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'run_command':[sys.executable,'scripts/privacy_matched_benchmark.py','--nodes','900','--series','release-protection-20261017-storage-v2'],
            'interpretation':'Each C0/C1 pair has identical code and parameters. 120/300 and 900 use different recorded builds; no uniform-current-version scaling claim. The failed warmup is retained, not replaced in its original series.'}
    if previous.exists():
        browser=ROOT/'artifacts/iterations/privacy/browser'/('2026-10-17T16-07-01.830Z' if previous.name=='readiness-amendment.json' else '2026-10-17T16-01-25.774Z')/'validation.json'
        assert read(browser)['exit_code']==1 and read(previous)['core_source_digest']!=current['core_source_digest']
        assert not (original.parent/record['new_series']/'900').exists()
        record['supersedes_unexecuted_registration']={'path':str(previous.relative_to(ROOT)),'sha256':hashlib.sha256(previous.read_bytes()).hexdigest()}
        record['additional_readiness_fix']='Persist terminal task status only after child evidence has been collected; recovery also recollects committed child evidence.'
        if previous.name=='readiness-amendment.json':
            record['additional_history_fix']='Recent tasks read the existing runtime/subject submission index, preserving per-record authorization; no global scan over private experiments. Browser checks await explicit UI states instead of global network-idle.'
        record['premeasurement_browser_failure']={'path':str(browser.relative_to(ROOT)),'sha256':hashlib.sha256(browser.read_bytes()).hexdigest()}
    write(destination,record)
    print(json.dumps({'record':str(destination.relative_to(ROOT)),'new_core_source_digest':current['core_source_digest']}))


if __name__=='__main__':main()
