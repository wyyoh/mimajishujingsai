"""Repair summary serialization from intact samples; resume unmeasured sizes."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--series',required=True);args=parser.parse_args()
    from services.storage import read,write
    from services.versioning import source_version
    from services.native import utc
    base=ROOT/'artifacts/iterations/privacy/benchmarks'/args.series
    directory=base/'300';plan=read(directory/'plan.json');raw=read(directory/'raw.json');pairs=read(directory/'pairs.json')
    old=base/'measurement-driver-before-summary-format-fix.py';current=ROOT/'scripts/privacy_matched_benchmark.py'
    assert hashlib.sha256(old.read_bytes()).hexdigest()==plan['driver_sha256']
    assert old.read_text().split("    write(directory/'summary.json',summary)")[0]==current.read_text().split('    # The protocol store intentionally')[0]
    assert len(raw)==24 and all(row['success'] for row in raw) and len(pairs)==12 and all(row['business_metrics_equal'] for row in pairs)
    frozen=source_version();assert frozen['core_source_digest']==plan['core_source_digest']
    if (directory/'summary.json').exists():raise RuntimeError('Preserve existing summary')
    rows=[row for row in raw if row['phase']=='formal'];differences=[];ratios=[]
    for index in range(10):
        pair={row['arm']:row for row in rows if row['pair']==index}
        difference=pair['C1']['elapsed_ns']-pair['C0']['elapsed_ns']
        differences.append(difference);ratios.append(difference/pair['C0']['elapsed_ns'])
    summary={'schema':'GRID_PRIVATE_MATCHED_SUMMARY_V1','status':'COMPLETED','finished_at':utc(),**frozen,
             'nodes':300,'source_count':3,'formal_pairs':10,'warmup_pairs':2,'failures':0,
             'median_paired_difference_ns':str(statistics.median(differences)),
             'median_paired_overhead_ratio':str(statistics.median(ratios)),
             'arms':{arm:{'samples':10,'median_elapsed_ns':str(statistics.median(row['elapsed_ns'] for row in rows if row['arm']==arm)),
                     'min_elapsed_ns':min(row['elapsed_ns'] for row in rows if row['arm']==arm),
                     'max_elapsed_ns':max(row['elapsed_ns'] for row in rows if row['arm']==arm)} for arm in ('C0','C1')},
             'main_latency_goal_observed':sum(row['elapsed_ns']<=180_000_000_000 for row in rows if row['arm']=='C1'),
             'scope':plan['scope'],'claims':'Descriptive only; no p95, significance, production throughput or security-equivalence inference',
             'summary_numeric_encoding':'DECIMAL_TEXT_WITH_INTEGER_RAW_TIMINGS','postprocessing_repaired_without_resampling':True,
             'inputs':{name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in ('plan.json','raw.json','pairs.json')}}
    write(directory/'summary.json',summary)
    resume={'registered_at':utc(),'command':[sys.executable,*sys.argv],**frozen,'reason':'FLOAT_NOT_ALLOWED in summary metadata only',
            'old_driver_sha256':hashlib.sha256(old.read_bytes()).hexdigest(),'new_driver_sha256':hashlib.sha256(current.read_bytes()).hexdigest(),
            'measurement_and_timing_prefix_identical':True,'retained_300_runs':24,'native_run_failures':0,
            'summary_error_count':1,'remaining_configuration_order':[120,900],
            'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    write(base/'resume-plan.json',resume)
    print(json.dumps({'nodes':300,'summary_recovered':True,'retained_runs':24}),flush=True)
    for nodes in [120,900]:
        assert source_version()==frozen
        command=[sys.executable,str(current),'--nodes',str(nodes),'--series',args.series]
        with (base/f'{nodes}.log').open('w') as log:
            process=subprocess.Popen(command,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
            for line in process.stdout:log.write(line);log.flush();print(line,end='',flush=True)
            process.wait()
        if process.returncode:raise SystemExit(process.returncode)
    subprocess.run([sys.executable,str(ROOT/'scripts/privacy_benchmark_summary.py'),'--series',args.series],cwd=ROOT,check=True)


if __name__=='__main__':main()
