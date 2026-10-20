"""Repack a temporary copy, preserving original historical evidence."""
import copy
import hashlib
import io
import tempfile
import zipfile
import uuid

from .encoding import canonical, loads, Rejected
from .evidence import export_public, verify_export
from .initialization import ROOT
from .storage import read, write
from .versioning import source_version
from .native import utc

KINDS = ("snapshot_record", "snapshot_root", "policy", "aggregation_digest", "audit_event", "audit_drop", "audit_reorder", "accepted_set", "signature", "epoch_type", "replay_context")


def attack(run_id, kind):
    if kind not in KINDS:
        raise Rejected("ATTACK_KIND_INVALID")
    archive = ROOT / "artifacts/exports" / (run_id + ".zip")
    if not archive.exists():
        archive = export_public(run_id)
    original = archive.read_bytes()
    run = read(ROOT / "artifacts/runs" / run_id / "run_manifest.json")
    expected = {key: run[key] for key in ("run_id", "task_id", "param_id", "security_profile", "slot_count", "algorithm_suite", "policy_digest")}
    with zipfile.ZipFile(io.BytesIO(original)) as reader:
        files = {name: reader.read(name) for name in reader.namelist()}
    baseline = verify_export(archive, expected_context=expected)
    slot = sorted(loads(files["snapshots.json"]))[0]
    if kind == "snapshot_record":
        value = loads(files["snapshots.json"])
        value[slot]["records"][0]["report"]["CT"] = str(int(value[slot]["records"][0]["report"]["CT"]) + 1)
        files["snapshots.json"] = canonical(value)
    elif kind in ("snapshot_root", "aggregation_digest", "signature", "epoch_type"):
        value = loads(files["receipts.json"])
        if kind == "epoch_type":
            value[0]["payload"]["key_epoch"] = True
        elif kind == "signature":
            signature = value[0]["signatures"][-1]["value"]
            value[0]["signatures"][-1]["value"] = ("A" if signature[0] != "A" else "B") + signature[1:]
        else:
            value[0]["payload"][kind] = "0" * (64 if kind == "snapshot_root" else 96)
        files["receipts.json"] = canonical(value)
    elif kind == "policy":
        value = loads(files["governance.json"])
        value["region"] = "B" if value["region"] == "A" else "A"
        files["governance.json"] = canonical(value)
    elif kind.startswith("audit_"):
        value = loads(files["audit_checkpoints.json"])
        if kind == "audit_drop":
            value[slot]["records"].pop()
        elif kind == "audit_reorder":
            value[slot]["records"].reverse()
        else:
            value[slot]["records"][0]["result"] = "CHANGED"
        files["audit_checkpoints.json"] = canonical(value)
    elif kind == "accepted_set":
        value = loads(files["accepted_manifests.json"])
        value[slot].append("f" * 96)
        files["accepted_manifests.json"] = canonical(value)
    else:
        expected["task_id"] = "wrong-requested-task"
    # Recompute all ordinary file hashes so detection depends on signed bindings.
    manifest = loads(files["export_manifest.json"])
    manifest["files"] = {name: hashlib.sha256(data).hexdigest() for name, data in files.items() if name != "export_manifest.json"}
    files["export_manifest.json"] = canonical(manifest)
    with tempfile.TemporaryDirectory(prefix="grid-v41-attack-") as directory:
        from pathlib import Path
        target = Path(directory) / "modified.zip"
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as writer:
            for name, data in files.items():
                writer.writestr(name, data)
        try:
            verify_export(target, expected_context=expected)
            rejected, code = False, "UNEXPECTED_ACCEPTANCE"
        except Rejected as exc:
            rejected, code = True, exc.code
        modified_sha = hashlib.sha256(target.read_bytes()).hexdigest()
    restored = verify_export(archive, expected_context={key: run[key] for key in ("run_id", "task_id", "param_id", "security_profile", "slot_count")})
    if archive.read_bytes() != original:
        raise Rejected("ATTACK_CHANGED_ORIGINAL_ARCHIVE")
    result = {"schema": "GRID_V41_ARCHIVE_COPY_ATTACK", "run_id": run_id, "kind": kind, "at": utc(),
              "baseline_verified": baseline["receipt_authenticity_verified"], "attack_rejected": rejected, "rejection_code": code,
              "ordinary_hashes_recomputed": True, "original_unchanged": True, "restored_verified": restored["receipt_authenticity_verified"],
              "original_sha256": hashlib.sha256(original).hexdigest(), "modified_sha256": modified_sha,
              "run_source_digest": run.get("core_source_digest"),
              "scope": "Temporary public archive-copy attack; does not modify live source data or history", **source_version()}
    report = ROOT / "artifacts/iterations/v41/attacks" / f"{run_id}-{kind}-{uuid.uuid4().hex}.json"
    result["report_path"] = str(report.relative_to(ROOT))
    write(report, result)
    return result
