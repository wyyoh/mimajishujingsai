"""Run the frozen measurement configurations serially, without replacing failures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--series',required=True);args=parser.parse_args()
    from services.versioning import source_version
    from services.storage import write
    from services.native import utc
    version=source_version();directory=ROOT/'artifacts/iterations/privacy/benchmarks'/args.series
    directory.mkdir(parents=True,exist_ok=False)
    plan={'schema':'GRID_MATCHED_SERIES_PLAN_V1','registered_at':utc(),**version,
          'command':[sys.executable,*sys.argv],'configuration_order':[300,120,900],
          'formal_pairs':{'300':10,'120':5,'900':5},'warmup_pairs_per_configuration':2,
          'benchmark_driver_sha256':hashlib.sha256((ROOT/'scripts/privacy_matched_benchmark.py').read_bytes()).hexdigest(),
          'scope':'Serial REAL evaluations on one physical host. No other automated native test jobs run concurrently. Fixed seeds order the arms, never seed crypto randomness.'}
    write(directory/'series-plan.json',plan)
    for nodes in plan['configuration_order']:
        assert source_version()==version
        command=[sys.executable,str(ROOT/'scripts/privacy_matched_benchmark.py'),'--nodes',str(nodes),'--series',args.series]
        with (directory/f'{nodes}.log').open('w') as log:
            process=subprocess.Popen(command,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
            for line in process.stdout:
                log.write(line);log.flush();print(line,end='',flush=True)
            process.wait()
        if process.returncode:raise SystemExit(process.returncode)
    assert source_version()==version
    subprocess.run([sys.executable,str(ROOT/'scripts/privacy_benchmark_summary.py'),'--series',args.series],cwd=ROOT,check=True)


if __name__=='__main__':main()
