"""Recompute actual scale statistics and verify all task signatures and private oracles."""
import hashlib
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services.encoding import digest
from services.evidence import export_public,verify_export
from services.expansion_data import select,SYNTHETIC_ID
from services.initialization import ROOT,RUNTIME
from services.storage import read,write
from services.versioning import source_version
from tests.oracle.reference import expected,compare

def main():
    summary=read(ROOT/'artifacts/iterations/v42/benchmarks/summary.json')
    directory=ROOT/summary['series']
    plan,raw,warmups=(read(directory/name) for name in ('plan.json','raw.json','warmups.json'))
    current=source_version()
    assert summary['core_source_digest']==plan['core_source_digest']==current['core_source_digest']
    assert summary['native_library_sha256']==plan['native_library_sha256']==current['native_library_sha256']
    for name,sha in summary['inputs'].items():
        assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==sha
    assert hashlib.sha256((directory/'admission.json').read_bytes()).hexdigest()==plan['regression_admission_sha256']
    assert hashlib.sha256((ROOT/'third_party/mcl/lib/libmcl.so').read_bytes()).hexdigest()==plan['mcl_library_sha256']
    assert len(raw)==30 and len({row['run_id'] for row in raw})==30 and len(warmups)==6
    checks=[]
    for row in raw:
        run=ROOT/'artifacts/runs'/row['run_id']
        for name,sha in row['evidence'].items():
            assert hashlib.sha256((run/name).read_bytes()).hexdigest()==sha
        manifest=read(run/'run_manifest.json')
        policy=read(run/'governance.json')
        fixture=select(SYNTHETIC_ID,row['nodes'],0,[68,69,70,71])
        assert fixture['dataset_digest']==row['dataset_digest']==policy['dataset_digest']
        assert fixture['parent_dataset_digest']==plan['dataset_parent_digests'][str(row['nodes'])]
        assert manifest['status']=='COMPLETED' and manifest['oracle_match'] and manifest['node_count']==row['nodes']
        assert manifest['logical_source_process_count']==row['source_count'] and manifest['elapsed_ns']==row['elapsed_ns']
        assert policy['algorithm_suite']=='V41_HYBRID_SM' and manifest['security_profile']=='SAB'
        accepted=read(RUNTIME/'runs'/row['run_id']/'gateway/accepted.json')
        maps={f'slot-{i}':{} for i in range(4)}
        for source in policy['sources']:
            for slot,mapping in read(RUNTIME/'runs'/row['run_id']/source['source_id']/'oracle_mapping.json').items():
                maps[slot].update(mapping)
        for i,result in enumerate(manifest['results']):
            slot=result['slot_id']
            reference=expected(fixture,'A',['residential','commercial','charging'],i)
            comparison=compare(reference,accepted[slot],maps[slot],result['value_W'])
            assert comparison['set_match'] and comparison['value_match']
            assert result['counts']['received']==row['nodes'] and result['counts']['accepted']==row['nodes']//2
        verified=verify_export(export_public(row['run_id']),expected_context={'run_id':row['run_id'],'dataset_digest':row['dataset_digest'],
                              'param_id':plan['param_id'],'slot_count':4,'algorithm_suite':'V41_HYBRID_SM','logical_source_process_count':row['source_count']})
        assert verified['data_provenance_binding_verified'] and all(item['source_bindings_verified'] for item in verified['v41_checks'])
        connections=read(run/'connection_evidence.json')
        selected=[item for item in connections if item['peer_role']=='gateway']
        assert len(selected)==row['source_count']+1 and all(item['actual_group']=='X25519MLKEM768' and item['application_cipher']=='SM4-GCM' for item in connections)
        assert sum(item['tls_record_bytes_sent']+item['tls_record_bytes_received'] for item in selected)==row['tls_bytes']
        resources=read(run/'resource_evidence.json')
        assert resources['cpu_role_total_ns']==row['cpu_role_total_ns'] and resources['peak_sampled_role_rss_KiB']==row['peak_sampled_role_rss_KiB']
        checks.append({'run_id':row['run_id'],'set_and_value_recomputed':True,'receipt_source_and_provenance_links_verified':True})
    for view in summary['rows']:
        group=[row for row in raw if row['nodes']==view['nodes'] and row['source_count']==view['source_count']]
        assert len(group)==view['samples']==5 and view['failures']==0
        for destination,source in [('median_elapsed_ns','elapsed_ns'),('median_cpu_ns','cpu_role_total_ns'),('median_rss_KiB','peak_sampled_role_rss_KiB'),('median_tls_bytes','tls_bytes')]:
            assert sorted(row[source] for row in group)[2]==view[destination]
        assert min(row['elapsed_ns'] for row in group)==view['min_elapsed_ns'] and max(row['elapsed_ns'] for row in group)==view['max_elapsed_ns']
    result={'schema':'GRID_V42_SCALE_RECOMPUTATION','exit_code':0,'core_source_digest':current['core_source_digest'],'series':summary['series'],
            'formal_samples':30,'warmups_excluded':6,'summary_rows':7,'all_signature_links_verified':True,'independent_sets_and_sums_recomputed':True,
            'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'checks':checks,
            'scope':'Private fixture review by trusted validator, public signed-object verification and descriptive statistics; not independent UC plaintext proof or production scalability certification.'}
    write(ROOT/'artifacts/iterations/v42/benchmarks/verification.json',result)
    print(json.dumps({key:value for key,value in result.items() if key!='checks'}))

if __name__=='__main__':
    main()
