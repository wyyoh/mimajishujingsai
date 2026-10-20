"""Pre-registered paired REAL measurements; numeric controls remain UC-private."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import platform
import ssl
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--nodes',type=int,choices=[120,300,900],required=True)
    parser.add_argument('--series',required=True)
    args=parser.parse_args()
    os.environ['GRID_RUNTIME']=tempfile.mkdtemp(prefix=f'grid-private-paired-{args.nodes}-',dir=str(Path.home()))
    # Retain the same OS-bound custody as the supported workstation. The private
    # evidence must remain inspectable by its owner after this process exits.
    os.environ.pop('GRID_CUSTODY_PASSPHRASE',None)
    from services.initialization import RUNTIME
    from services.orchestrator import initialize
    from services.expansion_governance import initialize_sources
    from services.expansion_data import load
    from services.native import utc,LIB
    from services.encoding import Rejected
    from services.storage import read,write
    from services.versioning import source_version
    from services.response import execute,EvaluationRequest
    initialize();initialize_sources()
    frozen=source_version()
    directory=ROOT/'artifacts/iterations/privacy/benchmarks'/args.series/str(args.nodes)
    if directory.exists():raise RuntimeError('Preserve existing measurement series; choose a new name')
    directory.mkdir(parents=True)
    formal=10 if args.nodes==300 else 5
    data=load('SYN-WEEK-V42',args.nodes)
    rng=random.Random(42016+args.nodes)
    orders=[]
    for phase,count in [('warmup',2),('formal',formal)]:
        for pair in range(count):
            order=['C0','C1'];rng.shuffle(order)
            orders.append({'phase':phase,'pair':pair,'order':order})
    plan={'schema':'GRID_PRIVATE_MATCHED_PLAN_V1','registered_at':utc(),**frozen,
          'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'command':[sys.executable,*sys.argv],'runtime':str(RUNTIME),'nodes':args.nodes,'source_count':3,
          'dataset_digest':data['dataset_digest'],'rules':read(ROOT/'contracts/privacy_release.json'),
          'param_id':read(RUNTIME/'public/parameters.json')['param_id'],'versions':json.loads(LIB.grid_library_info()),
          'host':{'system':platform.system(),'release':platform.release(),'machine':platform.machine(),'python':sys.version,
                  'openssl':ssl.OPENSSL_VERSION,'logical_cpus':os.cpu_count(),
                  'cpu_model':next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')),'unknown')},
          'ordering':orders,'formal_pairs':formal,'warmup_pairs':2,
          'latency_goal':{'main_input_nodes':300,'seconds':180,'required_successes':9,'formal_attempts':10,'preregistered':True},
          'scope':'One WSL host, serial paired evaluations, same encrypted inputs/profile, no CPU pinning. Both arms keep numerical outputs UC-private.',
          'timing':'Primary elapsed_ns: accepted private coordinator task through signed evaluation and evidence availability, including internal verification. wall_ns additionally includes preparation before acceptance. No API queue or browser rendering. Both arms use the same boundary.',
          'difference':'C0 skips release rule/history enforcement; C1 enforces it. Both use real cryptography and matched signing/verification.'}
    write(directory/'plan.json',plan)
    rows=[];pairs=[]
    for registered in orders:
        pair_packages={}
        for arm in registered['order']:
            if source_version()!=frozen:raise RuntimeError('Source changed; do not relabel measurements')
            before=utc();started=time.perf_counter_ns();result={}
            valid=False
            try:
                result=execute(EvaluationRequest(nodes=args.nodes,source_count=3,request_nonce=uuid.uuid4().hex),
                               'grid_operator_A',lab=True,private_control=arm=='C0',private_measurement=True)
                wall=time.perf_counter_ns()-started
                if result.get('status')!='EXPERIMENT_ONLY':
                    error=RUNTIME/'runs'/result['run_id']/'utility/evaluation-error.json'
                    code=read(error).get('code') if error.exists() else None
                    raise Rejected(code or 'MEASURED_EVALUATION_NOT_COMPLETED')
                stage=RUNTIME/'runs'/result['run_id']/'utility/release-ready.json'
                package=read(stage)
                private_decision=package['release']['decision']
                expected='EXPERIMENT_NOT_RELEASED' if arm=='C0' else 'PUBLISHED'
                checks=[];connections=[];resources=[];public_refs=[]
                for child in result['children']:
                    child_id=child['run_id'];child_dir=ROOT/'artifacts/runs'/child_id
                    oracle=read(RUNTIME/'runs'/child_id/'utility/oracle-summary.json')
                    child_manifest=read(child_dir/'run_manifest.json')
                    checks.append(len(oracle)==4 and all(row['set_match'] and row['value_match'] for row in oracle)
                                  and child_manifest['role_file_isolation'])
                    connections.extend(read(child_dir/'connection_evidence.json'))
                    resources.append(read(child_dir/'resource_evidence.json'))
                    public_refs.append({'path':str((child_dir/'run_manifest.json').relative_to(ROOT)),
                                        'sha256':hashlib.sha256((child_dir/'run_manifest.json').read_bytes()).hexdigest()})
                one_side=[row for row in connections if row['peer_role']=='gateway']
                valid=(result['status']=='EXPERIMENT_ONLY' and not result['results'] and len(checks)==4 and all(checks)
                       and private_decision==expected and len(one_side)==16
                       and all(row['actual_group']=='X25519MLKEM768' and row.get('application_cipher')=='SM4-GCM' for row in connections))
                row={'phase':registered['phase'],'pair':registered['pair'],'arm':arm,'started_at':before,'finished_at':utc(),
                     'run_id':result['run_id'],'nodes':args.nodes,'source_count':3,'computed_intervals':16,
                     'elapsed_ns':result['elapsed_ns'],'wall_ns':wall,'success':valid,'public_numeric_output':False,
                     'phase_timings':result['phase_timings'],'coordinator_cpu_ns':result['coordinator_cpu_ns'],
                     'independent_sets_and_integer_sums_match':all(checks),'actual_link_count':len(one_side),
                     'cpu_role_total_ns':sum(item['cpu_role_total_ns'] for item in resources),
                     'peak_sampled_role_rss_KiB':max(item['peak_sampled_role_rss_KiB'] for item in resources),
                     'tls_bytes':sum(row['tls_record_bytes_sent']+row['tls_record_bytes_received'] for row in one_side),
                     'public_evidence':public_refs,
                     'private_stage_ciphertext_sha256':hashlib.sha256(stage.read_bytes()).hexdigest(),
                     'private_stage_path':str(stage),'core_source_digest':frozen['core_source_digest'],'param_id':plan['param_id']}
            except Exception as exc:
                row={'phase':registered['phase'],'pair':registered['pair'],'arm':arm,'started_at':before,'finished_at':utc(),
                     'nodes':args.nodes,'source_count':3,'success':False,'wall_ns':time.perf_counter_ns()-started,
                     'failure_code':getattr(exc,'code',type(exc).__name__),'run_id':locals().get('result',{}).get('run_id'),
                     'core_source_digest':frozen['core_source_digest'],'param_id':plan['param_id'],'public_numeric_output':False}
                valid=False
            rows.append(row);write(directory/'raw.json',rows)
            print(json.dumps({key:row.get(key) for key in ('phase','pair','arm','nodes','success','elapsed_ns')}),flush=True)
            if not valid:
                write(directory/'summary.json',{'schema':'GRID_PRIVATE_MATCHED_SUMMARY_V1','status':'FAILED',
                    **frozen,'nodes':args.nodes,'failures':1,'observed_runs':len(rows),'failure':row,
                    'scope':'Incomplete series retained; no automatic replacement or successful-series inference'})
                raise RuntimeError('Measured execution failed; retained without automatic replacement')
            pair_packages[arm]=package['evaluation']['metrics']
        matched=pair_packages['C0']==pair_packages['C1']
        pairs.append({'phase':registered['phase'],'pair':registered['pair'],'business_metrics_equal':matched})
        write(directory/'pairs.json',pairs)
        if not matched:raise RuntimeError('Matched business metrics differ')
    formal_rows=[row for row in rows if row['phase']=='formal']
    differences=[];ratios=[]
    for pair in range(formal):
        samples={row['arm']:row for row in formal_rows if row['pair']==pair}
        difference=samples['C1']['elapsed_ns']-samples['C0']['elapsed_ns']
        differences.append(difference);ratios.append(difference/samples['C0']['elapsed_ns'])
    summary={'schema':'GRID_PRIVATE_MATCHED_SUMMARY_V1','status':'COMPLETED','finished_at':utc(),**frozen,
             'nodes':args.nodes,'source_count':3,'formal_pairs':formal,'warmup_pairs':2,'failures':0,
             'median_paired_difference_ns':statistics.median(differences),'median_paired_overhead_ratio':statistics.median(ratios),
             'arms':{arm:{'samples':formal,'median_elapsed_ns':statistics.median(row['elapsed_ns'] for row in formal_rows if row['arm']==arm),
                            'min_elapsed_ns':min(row['elapsed_ns'] for row in formal_rows if row['arm']==arm),
                            'max_elapsed_ns':max(row['elapsed_ns'] for row in formal_rows if row['arm']==arm)} for arm in ('C0','C1')},
             'main_latency_goal_observed':sum(row['elapsed_ns']<=180_000_000_000 for row in formal_rows if row['arm']=='C1') if args.nodes==300 else None,
             'scope':plan['scope'],'claims':'Descriptive only; no p95, significance, production throughput or security-equivalence inference',
             'inputs':{name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in ('plan.json','raw.json','pairs.json')}}
    if source_version()!=frozen:raise RuntimeError('Source changed during series')
    # The protocol store intentionally rejects JSON floats. Descriptive ratios
    # and half-nanosecond medians are metadata, encoded as decimal text.
    for field in ('median_paired_difference_ns','median_paired_overhead_ratio'):
        summary[field]=str(summary[field])
    for arm in summary['arms'].values():arm['median_elapsed_ns']=str(arm['median_elapsed_ns'])
    summary['summary_numeric_encoding']='DECIMAL_TEXT_WITH_INTEGER_RAW_TIMINGS'
    write(directory/'summary.json',summary)
    print(json.dumps({'summary':str((directory/'summary.json').relative_to(ROOT))}),flush=True)


if __name__=='__main__':main()
