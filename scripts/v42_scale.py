"""Preregistered same-host V3 scale study; one endpoint per actual TLS link."""
import hashlib
import json
import random
import statistics
import platform
import gmpy2
import sys
import uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services.expansion_data import SYNTHETIC_ID, load
from services.expansion_governance import prepare
from services.expansion_schemas import ExpansionRequest
from services.expansion_orchestrator import execute
from services.initialization import ROOT, RUNTIME
from services.native import LIB, utc
from services.storage import read, write
from services.versioning import source_version

def main():
    repetitions=5
    configurations=[(nodes,3) for nodes in (120,300,600,900)]+[(120,1),(120,2)]
    stamp=utc().replace(':','-')
    directory=ROOT/'artifacts/iterations/v42/benchmarks'/stamp
    directory.mkdir(parents=True,exist_ok=False)
    frozen=source_version()
    admission_path=ROOT/'artifacts/tests/acceptance_results.json'
    admission=read(admission_path)
    assert admission['exit_code']==0 and admission['build']['core_source_digest']==frozen['core_source_digest'],'Current-source full regression must pass before measurement'
    assert admission['test_execution_count']>=77 and admission['counts']['PASS']==60 and all(row['status']=='PASS' for row in admission['recovery_cases']),'Targeted tests cannot admit a formal series'
    (directory/'admission.json').write_bytes(admission_path.read_bytes())
    datasets={str(nodes):load(SYNTHETIC_ID,nodes)['dataset_digest'] for nodes in (120,300,600,900)}
    plan={'schema':'GRID_V42_SCALE_PLAN','registered_at':utc(),**frozen,'command':[sys.executable,'scripts/v42_scale.py'],
          'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'configurations':[{'nodes':n,'source_count':s} for n,s in configurations],
          'repeats_per_configuration':repetitions,'warmups_per_configuration':1,'unique_formal_samples':30,
          'regression_admission_sha256':hashlib.sha256((directory/'admission.json').read_bytes()).hexdigest(),
          'test_harness_digest':admission['build']['test_harness_digest'],'admitted_test_executions':admission['test_execution_count'],
          'python':sys.version,'platform':platform.platform(),'gmpy2':gmpy2.version(),
          'mcl_library_sha256':hashlib.sha256((ROOT/'third_party/mcl/lib/libmcl.so').read_bytes()).hexdigest(),
          'param_id':read(RUNTIME/'public/parameters.json')['param_id'],
          'source_identity_registry_sha256':hashlib.sha256((RUNTIME/'public/source-registry-v42.json').read_bytes()).hexdigest(),
          'slots':4,'periods':[68,69,70,71],'day':0,'scene':'park','function':'SUM','algorithm_suite':'V41_HYBRID_SM','dataset_parent_digests':datasets,
          'library_info':json.loads(LIB.grid_library_info()),'ordering_seed':42016,'cryptographic_randomness_seeded':False,
          'scope':'Same Windows/WSL host, separate Source processes, serial tasks, no CPU pinning. Descriptive n=5 per configuration; no throughput or equivalence claim.',
          'axes':'Node axis fixes 3 Source processes. Source axis fixes 120 nodes. The 120-node/3-Source samples are shared by both views, not extra independent samples.',
          'tls_bytes':'Sum one observed endpoint per link: L1 Source client and L2 UC server. Includes full TLS handshakes and JSON/SM4 frames; excludes TCP/IP headers and duplicate peer perspective.',
          'elapsed':'Role startup through process exit and evidence collection; excludes dataset preparation, TA/key initialization and execution-lock queue time.'}
    write(directory/'plan.json',plan)
    raw,warmups=[],[]
    def sample(nodes,sources,index,warmup):
        assert source_version()==frozen,'Source changed before a sample'
        policy,_,_=prepare(ExpansionRequest(nodes=nodes,source_count=sources,scene_id='park',periods=[68,69,70,71],request_nonce=uuid.uuid4().hex), 'grid_operator_A')
        assert policy['parent_dataset_digest']==datasets[str(nodes)],'Dataset changed after registration'
        assert hashlib.sha256((RUNTIME/'public/source-registry-v42.json').read_bytes()).hexdigest()==plan['source_identity_registry_sha256'],'Source trust changed after registration'
        result=execute(policy)
        assert result['param_id']==plan['param_id'],'Parameters changed after registration'
        run=ROOT/'artifacts/runs'/result['run_id']
        connections=read(run/'connection_evidence.json')
        unique=[row for row in connections if row['peer_role']=='gateway']
        resources=read(run/'resource_evidence.json')
        row={'sample':index,'nodes':nodes,'source_count':sources,'slots':4,'warmup':warmup,'run_id':result['run_id'],
             'status':result['status'],'oracle_match':result.get('oracle_match'),'role_file_isolation':result['role_file_isolation'],
             'dataset_digest':result['dataset_digest'],'core_source_digest':result['core_source_digest'],'param_id':result['param_id'],
             'elapsed_ns':result['elapsed_ns'],'cpu_role_total_ns':resources['cpu_role_total_ns'],'peak_sampled_role_rss_KiB':resources['peak_sampled_role_rss_KiB'],
             'tls_bytes':sum(row['tls_record_bytes_sent']+row['tls_record_bytes_received'] for row in unique),'link_count':len(unique),
             'evidence':{name:hashlib.sha256((run/name).read_bytes()).hexdigest() for name in ('run_manifest.json','oracle_summary.json','connection_evidence.json','resource_evidence.json','receipts.json')}}
        row['success']=(result['status']=='COMPLETED' and result.get('oracle_match') is True and result['role_file_isolation'] and len(unique)==sources+1
                        and all(item['actual_group']=='X25519MLKEM768' and item.get('application_cipher')=='SM4-GCM' for item in connections))
        assert source_version()==frozen,'Source changed during a sample'
        (warmups if warmup else raw).append(row)
        write(directory/('warmups.json' if warmup else 'raw.json'),warmups if warmup else raw)
        print(json.dumps({'nodes':nodes,'sources':sources,'warmup':warmup,'sample':index,'success':row['success'],'elapsed_ms':row['elapsed_ns']//1000000}),flush=True)
        assert row['success'],'Actual scale sample failed; preserve raw record and do not publish success summary'
    rng=random.Random(42016)
    order=list(configurations);rng.shuffle(order)
    for nodes,sources in order:
        sample(nodes,sources,0,True)
    for index in range(repetitions):
        order=list(configurations);rng.shuffle(order)
        for nodes,sources in order:
            sample(nodes,sources,index,False)
    rows=[]
    for axis,points in [('nodes',[(n,3) for n in (120,300,600,900)]),('sources',[(120,s) for s in (1,2,3)])]:
        for nodes,sources in points:
            group=[row for row in raw if row['nodes']==nodes and row['source_count']==sources]
            median=lambda name:round(statistics.median(row[name] for row in group))
            rows.append({'axis':axis,'nodes':nodes,'source_count':sources,'slots':4,'samples':len(group),'failures':sum(not row['success'] for row in group),
                         'median_elapsed_ns':median('elapsed_ns'),'min_elapsed_ns':min(row['elapsed_ns'] for row in group),'max_elapsed_ns':max(row['elapsed_ns'] for row in group),
                         'median_cpu_ns':median('cpu_role_total_ns'),'median_rss_KiB':median('peak_sampled_role_rss_KiB'),'median_tls_bytes':median('tls_bytes')})
    result={'schema':'GRID_V42_SCALE_SUMMARY','status':'COMPLETED','finished_at':utc(),**frozen,'series':str(directory.relative_to(ROOT)),
            'unique_formal_samples':len(raw),'warmup_samples':len(warmups),'rows':rows,'scope':plan['scope'],'axes':plan['axes'],
            'inputs':{name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in ('plan.json','raw.json','warmups.json')}}
    write(directory/'summary.json',result)
    write(ROOT/'artifacts/iterations/v42/benchmarks/summary.json',result)
    print('Scale series complete: '+str(directory.relative_to(ROOT)),flush=True)

if __name__=='__main__':
    main()
