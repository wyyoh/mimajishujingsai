"""Recheck all private measured packages before exposing descriptive summaries."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--series',required=True);args=parser.parse_args()
    from services.storage import read,write
    from services.versioning import source_version
    from services.response import verify_evaluation
    from services.expansion_data import select
    from services.encoding import digest
    from services.custody import load_root
    from services.native import utc
    from tests.oracle.reference import expected,compare
    frozen=source_version();base=ROOT/'artifacts/iterations/privacy/benchmarks'/args.series
    amendment_path=next((base/name for name in ('history-amendment.json','readiness-amendment.json','storage-boundary-amendment.json') if (base/name).exists()),base/'storage-boundary-amendment.json')
    amendment=read(amendment_path) if amendment_path.exists() else None
    if amendment:
        assert amendment['status']=='REGISTERED' and amendment['core_source_digest']==frozen['core_source_digest']
        assert amendment['prior_failed_warmup_attempts']==1 and amendment['prior_failed_formal_attempts']==0
        for ref in amendment['references']:assert hashlib.sha256((ROOT/ref['path']).read_bytes()).hexdigest()==ref['sha256']
    summaries=[];references=[];checks=[]
    for nodes,pairs in [(120,5),(300,10),(900,5)]:
        directory=(base.parent/amendment['new_series'] if amendment and nodes==900 else base)/str(nodes)
        plan=read(directory/'plan.json');raw=read(directory/'raw.json');summary=read(directory/'summary.json')
        expected_version=amendment['original_core_source_digest'] if amendment and nodes!=900 else frozen['core_source_digest']
        assert summary['status']=='COMPLETED' and plan['core_source_digest']==expected_version
        assert summary['core_source_digest']==expected_version and plan['formal_pairs']==pairs and plan['warmup_pairs']==2
        assert len(raw)==2*(pairs+2) and all(row['success'] and not row['public_numeric_output'] for row in raw)
        assert len({row['run_id'] for row in raw})==len(raw)
        candidates=[ROOT/'scripts/privacy_matched_benchmark.py',base/'measurement-driver-before-summary-format-fix.py',base/'measurement-driver-before-primary-error-fix.py']
        assert any(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==plan['driver_sha256'] for path in candidates)
        for name,value in summary['inputs'].items():assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==value
        runtime=Path(plan['runtime']);anchor=load_root(runtime)['publication_state']
        cohort=select('SYN-WEEK-V42',nodes,4,[68,69,70,71])
        registered=sum(node['region']=='A' and node['resource_class'] in ('residential','commercial','charging') for node in cohort['nodes'])
        assert len(anchor['commits'])==pairs+2 and anchor['sequence']==pairs+2 and len(anchor['views'])==16
        by_pair={}
        for row in raw:
            assert row['core_source_digest']==expected_version
            assert row['param_id']==plan['param_id'] and row['actual_link_count']==16
            assert row['independent_sets_and_integer_sums_match']
            for ref in row['public_evidence']:assert hashlib.sha256((ROOT/ref['path']).read_bytes()).hexdigest()==ref['sha256']
            stage=Path(row['private_stage_path'])
            assert hashlib.sha256(stage.read_bytes()).hexdigest()==row['private_stage_ciphertext_sha256']
            package=read(stage,runtime=runtime);identifier=row['run_id'];policy=read(ROOT/'artifacts/runs'/identifier/'governance.json')
            assert package['evaluation']['metrics']['registered_metering_points']==registered
            if row['arm']=='C1':assert anchor['commits'][identifier]==digest(package)
            else:assert identifier not in anchor['commits'] and package['release']['decision']=='EXPERIMENT_NOT_RELEASED'
            verified=verify_evaluation(package['evaluation'],package['evaluation_statement'],package['evaluation_inputs'],
                                       runtime=runtime,expected={'run_id':identifier,'param_id':plan['param_id']},parent_policy=policy)
            assert verified['business_metrics_recomputed'] and len(verified['child_receipt_checks'])==16
            for day,item in enumerate(package['evaluation_inputs'],1):
                original=select('SYN-WEEK-V42',nodes,day,[68,69,70,71])
                if day==4:
                    for node in original['nodes']:
                        if node['region']=='A':node['values_W']=[value*9000//10000 for value in node['values_W']]
                child_id=item['context']['run_id'];job=runtime/'runs'/child_id
                computed=read(job/'utility/computed.json',runtime=runtime)
                maps={slot['slot_id']:{} for slot in original['slots']}
                for source in ('source-1','source-2','source-3'):
                    for slot,mapping in read(job/source/'oracle_mapping.json',runtime=runtime).items():maps[slot].update(mapping)
                for index,value in enumerate(item['results']):
                    reference=expected(original,'A',['residential','commercial','charging'],index)
                    check=compare(reference,computed['accepted_manifests'][value['slot_id']],maps[value['slot_id']],value['value_W'])
                    assert check['set_match'] and check['value_match']
            key=(row['phase'],row['pair']);by_pair.setdefault(key,{})[row['arm']]=package['evaluation']['metrics']
            checks.append({'run_id':identifier,'arm':row['arm'],'signed_inputs':16,'independent_windows':16,'private_package_verified':True})
        assert all(pair['C0']==pair['C1'] for pair in by_pair.values())
        formal=[row for row in raw if row['phase']=='formal'];differences=[];ratios=[]
        for index in range(pairs):
            pair={row['arm']:row for row in formal if row['pair']==index};delta=pair['C1']['elapsed_ns']-pair['C0']['elapsed_ns']
            differences.append(delta);ratios.append(delta/pair['C0']['elapsed_ns'])
        assert str(statistics.median(differences))==summary['median_paired_difference_ns']
        assert str(statistics.median(ratios))==summary['median_paired_overhead_ratio']
        summaries.append({**summary,'registered_metering_points':registered,'evidence_directory':str(directory.relative_to(ROOT))})
        references.extend({'path':str((directory/name).relative_to(ROOT)),'sha256':hashlib.sha256((directory/name).read_bytes()).hexdigest()} for name in ('plan.json','raw.json','pairs.json','summary.json'))
        print(json.dumps({'nodes':nodes,'private_runs_rechecked':len(raw)}),flush=True)
    assert source_version()==frozen
    validation={'schema':'GRID_PRIVATE_MATCHED_RECHECK_V1','status':'PASS','finished_at':utc(),**frozen,
                'command':[sys.executable,*sys.argv],'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'checks':checks,'references':references,'scope':'Private trusted-UC statement/receipt verification plus independent expected sets and integer sums for every measured window; not a cryptographic security proof'}
    write(base/'verification.json',validation)
    index={'status':'COMPLETED','series':args.series,'core_source_digest':frozen['core_source_digest'],'configurations':summaries,
           'verification':{'path':str((base/'verification.json').relative_to(ROOT)),'sha256':hashlib.sha256((base/'verification.json').read_bytes()).hexdigest()},
           'formal_pairs':20,'warmup_pairs':6,'actual_runs':52,'independently_checked_windows':len(checks)*16,
           'uniform_source_version':len({item['core_source_digest'] for item in summaries})==1,
           'measurement_core_source_digests':sorted({item['core_source_digest'] for item in summaries}),
           'prior_failed_warmup_attempts':amendment['prior_failed_warmup_attempts'] if amendment else 0,
           'total_observed_attempts':52+(amendment['prior_failed_warmup_attempts'] if amendment else 0),
           'scope':'One host, fresh private identity/parameter set per configuration; identical code, inputs and keys within each pair. Configuration builds are individually recorded. Descriptive only; no p95, uniform-current-build scaling or production throughput claim.'}
    if amendment:
        index['measurement_amendment_note']='900点首轮预热失败1次，修复私有文件读取边界后重新登记测量。120、300点保留修复前记录。各配置的组内版本一致，跨规模耗时仅作观察。'
        index['amendment']={'path':str(amendment_path.relative_to(ROOT)),
                            'sha256':hashlib.sha256(amendment_path.read_bytes()).hexdigest()}
    write(ROOT/'artifacts/iterations/privacy/benchmarks/current.json',index)
    print(json.dumps({'index':'artifacts/iterations/privacy/benchmarks/current.json','status':'PASS'}))


if __name__=='__main__':main()
