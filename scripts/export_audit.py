"""Repackage public evidence as an attacker; signatures stay unchanged except one negative control."""
import copy
import hashlib
import json
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.encoding import Rejected, canonical, loads
from services.evidence import export_public, verify_export
from services.initialization import ROOT
from services.native import utc
from services.storage import read, write
from services.versioning import source_version


def main():
    started = utc()
    frozen = source_version()
    run_id = read(ROOT / "artifacts/tests/crypto_conformance.json")["real_run_id"]
    archive = export_public(run_id)
    with zipfile.ZipFile(archive) as z:
        original = {name: z.read(name) for name in z.namelist()}
    run = loads(original["run_manifest.json"])
    expected = {k: run[k] for k in ("run_id", "task_id", "param_id", "security_profile", "slot_count")}
    assert verify_export(archive, expected_context=expected)["receipt_authenticity_verified"]
    rows = []

    def change(entries, filename, operation):
        obj = loads(entries[filename]); operation(obj); entries[filename] = canonical(obj)

    attacks = {
        "count": lambda e: change(e, "run_manifest.json", lambda m: m["results"][0]["counts"].update(accepted=m["results"][0]["counts"]["accepted"]+1)),
        "count_type": lambda e: change(e, "run_manifest.json", lambda m: m["results"][0]["counts"].update(invalid=False)),
        "receipt_digest": lambda e: change(e, "run_manifest.json", lambda m: m["results"][0].update(receipt_digest="0"*96)),
        "omitted_receipts": lambda e: e.update({"receipts.json": canonical([])}),
        "duplicate_receipt": lambda e: change(e, "receipts.json", lambda m: m.append(m[0])),
        "duplicate_slot": lambda e: change(e, "receipts.json", lambda m: m.__setitem__(1,m[0])),
        "outer_run": lambda e: change(e,"export_manifest.json",lambda m:m.update(run_id="0"*32)),
        "parameter_content": lambda e: change(e,"parameter_manifest.json",lambda m:m.update(h="1")),
        "security_profile": lambda e: change(e,"run_manifest.json",lambda m:m.update(security_profile="S0")),
        "result_status": lambda e: change(e,"run_manifest.json",lambda m:m["results"][0].update(status="NO_VALID_DATA")),
        "missing_completed_window": lambda e: (change(e,"run_manifest.json",lambda m:m["results"].pop()),change(e,"receipts.json",lambda m:m.pop())),
        "unapproved_file": lambda e: e.update({"untrusted.json":b"{}"}),
        "unlisted_file": lambda e: None,
    }
    with tempfile.TemporaryDirectory(prefix="export-audit-",dir=ROOT/".build") as directory:
        for name, mutate in attacks.items():
            entries=copy.deepcopy(original);mutate(entries)
            manifest=loads(entries["export_manifest.json"])
            manifest["files"]={n:hashlib.sha256(data).hexdigest() for n,data in entries.items() if n!="export_manifest.json"}
            entries["export_manifest.json"]=canonical(manifest)
            if name=="unlisted_file":entries["untrusted.json"]=b"{}"
            path=Path(directory)/(name+".zip")
            with zipfile.ZipFile(path,"w") as z:
                for n,data in entries.items():z.writestr(n,data)
            try:
                verify_export(path)
            except Rejected as exc:
                rows.append({"case":name,"accepted":False,"rejection_code":exc.code})
            else:
                raise AssertionError("Repackaged evidence accepted: "+name)
    for field, wrong in (("run_id","0"*32),("task_id","0"*32),("param_id","0"*96),
                         ("security_profile","S0"),("slot_count",4)):
        try:
            verify_export(archive,expected_context={**expected,field:wrong})
        except Rejected as exc:
            assert exc.code=="EXPORT_EXPECTED_CONTEXT_MISMATCH"
            rows.append({"case":"wrong_external_"+field,"accepted":False,"rejection_code":exc.code})
        else:
            raise AssertionError("Incorrect expected context accepted")
    assert source_version()==frozen
    result={"schema":"GRID_EXPORT_POSTPATCH_AUDIT_V1","started_at":started,"finished_at":utc(),
            "command":[".venv/bin/python","scripts/export_audit.py"],**frozen,
            "probe_script_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "run_id":run_id,"unchanged_archive_positive_control":True,
            "signature_payloads_unchanged":True,"archive_checksums_recomputed":True,
            "cases":rows,"rejected":len(rows),
            "plaintext_correspondence":"REQUIRES_TRUSTED_UC_OR_PRIVATE_ORACLE",
            "scope":"Signed receipt metadata association and external task pinning. Does not authenticate unsigned plaintext, run status, timing, connection logs, or prove source completeness.","exit_code":0}
    write(ROOT/"artifacts/tests/export_postpatch_audit.json",result)
    print(json.dumps({"rejected":len(rows),"run_id":run_id,"exit_code":0}))


if __name__=="__main__":
    main()
