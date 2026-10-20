"""Exploratory scale and policy scans, separated from the 30-sample main matrix."""
import argparse
import random
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services import pfdam
from services.dataset import windows
from services.encoding import digest
from services.initialization import ROOT, RUNTIME
from services.native import utc
from services.orchestrator import execute, initialize
from services.storage import read, write
from services.versioning import source_version

out = ROOT / "artifacts/benchmarks"


def main(repeats=3):
    public = initialize()
    frozen = source_version()
    for name in ("nodes_raw.json", "policies_raw.json"):
        if (out/name).exists():
            raise RuntimeError("Existing exploratory scan records are preserved")
    rng = random.Random(20261016)
    rows = []
    for sample in range(repeats):
        order = [100,300,600,900]
        rng.shuffle(order)
        for nodes in order:
            assert source_version() == frozen
            result = execute(nodes=nodes, slots=1, profile="SAB")
            rows.append({"sample":sample, "nodes":nodes, "slots":1,
                         "run_id":result["run_id"], "elapsed_ns":result["elapsed_ns"],
                         "success":result["status"]=="COMPLETED" and result.get("oracle_match") is True,
                         "param_id":result["param_id"], "dataset_digest":result["dataset_digest"]})
            write(out/"nodes_raw.json",rows)
            print(f"scale sample={sample+1} nodes={nodes} {result['status']}",flush=True)
    uc = read(RUNTIME/"utility/pfdam.json")
    gw = read(RUNTIME/"gateway/pfdam.json")
    policy_rows = []
    for sample in range(repeats):
        order=[1,2,5,10,15]
        rng.shuffle(order)
        for count in order:
            assert source_version() == frozen
            context={"task_id":uuid.uuid4().hex,"task_nonce":uuid.uuid4().hex,
                     "run_id":uuid.uuid4().hex,"metric_id":"average_active_power_W",
                     "param_id":public["param_id"],"slots":windows(1)}
            # Fifteen distinct experimental contracts; never repeat tags to invent degree.
            tags=[pfdam.tag(context,"slot-0",f"EXP-{i:02d}",f"contract-{i:02d}") for i in range(15)]
            t=time.perf_counter_ns()
            token=pfdam.authorize(public,uc,tags[:count])
            authorize_ns=time.perf_counter_ns()-t
            reports=[]
            expected_ids=[]
            expected_sum=0
            t=time.perf_counter_ns()
            for i in range(60):
                envelope={"task_id":context["task_id"],"run_id":context["run_id"],
                          "slot_id":"slot-0","param_id":public["param_id"],
                          "report":pfdam.report(public,1000+i,tags[i%15],utc())}
                envelope['report_id']=digest(envelope)
                reports.append(envelope)
                if i%15 < count:
                    expected_ids.append(envelope['report_id'])
                    expected_sum += 1000+i
            generation_ns=time.perf_counter_ns()-t
            t=time.perf_counter_ns()
            aggregate,accepted,rejected=pfdam.match_and_aggregate(public,gw,token,reports)
            gateway_ns=time.perf_counter_ns()-t
            stamp=utc()
            signature=pfdam.native_sign(gw,aggregate,stamp)
            actual=pfdam.verify_recover(public,uc,aggregate,stamp,signature,len(accepted))
            policy_rows.append({"sample":sample,"policies":count,"reports":60,
                                "max_degree":public["max_degree"],"param_id":public["param_id"],
                                "authorization_ns":authorize_ns,"report_generation_ns":generation_ns,
                                "gateway_match_and_aggregate_ns":gateway_ns,
                                "accepted_count":len(accepted),"expected_count":4*count,
                                "set_match":set(accepted)==set(expected_ids),
                                "value_match":actual==expected_sum,
                                "success":set(accepted)==set(expected_ids) and actual==expected_sum})
            write(out/"policies_raw.json",policy_rows)
            print(f"policy sample={sample+1} distinct={count} accepted={len(accepted)}",flush=True)
    write(out/"scan_plan.json",{"repeats":repeats,"node_slots":1,"profile":"SAB",
        "policy_scope":"in-process gateway core only; 60 reports over 15 distinct experimental region/contract tags; no TLS/object-signing cost",
        "max_degree":public['max_degree'],"param_id":public['param_id'],
        "scope":"exploratory small-sample scans; not a replacement for the representative 30-sample end-to-end matrix",
        **frozen})


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--repeats",type=int,default=3)
    main(parser.parse_args().repeats)
