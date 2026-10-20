"""Structured SM3 audit checkpoints, anchored by the V2 gateway receipt."""
from .agility import sm3
from .encoding import canonical, Rejected


def checkpoint(context, slot, snapshot, accepted_count, timestamp):
    policy = context["governance"]
    records, previous = [], "0" * 64
    actions = [("source", "RECEIVED_CIPHERTEXT", snapshot["record_count"]),
               ("gateway", "SNAPSHOT_SEALED", snapshot["record_count"]),
               ("gateway", "AGGREGATED", accepted_count)]
    for subject, action, count in actions:
        record = {"sequence": len(records) + 1, "timestamp": timestamp, "subject": subject,
                  "task_id": context["task_id"], "run_id": context["run_id"], "slot_id": slot,
                  "action": action, "data_scope": policy["asset_id"], "policy_version": policy["policy_version"],
                  "policy_digest": context["policy_digest"], "algorithm_suite": policy["algorithm_suite"],
                  "result": "SUCCESS", "record_count": count, "evidence_id": snapshot["merkle_root"], "previous_hash": previous}
        record["event_hash"] = sm3(b"GRID-V41-AUDIT\x00" + canonical(record))
        records.append(record)
        previous = record["event_hash"]
    return {"schema": "GRID_AUDIT_CHECKPOINT_V2", "records": records, "root": previous,
            "attestation_scope": "Gateway-signed checkpoint assertions; not an independent log of every process or administrator action"}


def verify_checkpoint(value, root, context):
    try:
        if value["schema"] != "GRID_AUDIT_CHECKPOINT_V2" or len(value["records"]) != 3:
            raise Rejected("AUDIT_SHAPE_INVALID")
        previous = "0" * 64
        expected_actions = [("source", "RECEIVED_CIPHERTEXT"), ("gateway", "SNAPSHOT_SEALED"), ("gateway", "AGGREGATED")]
        for sequence, record in enumerate(value["records"], 1):
            if (type(record["sequence"]) is not int or record["sequence"] != sequence or record["previous_hash"] != previous
                    or (record["subject"], record["action"]) != expected_actions[sequence - 1]
                    or any(record[key] != context[key] for key in ("task_id", "run_id", "slot_id", "policy_digest", "algorithm_suite"))):
                raise Rejected("AUDIT_CONTEXT_OR_ORDER_MISMATCH")
            calculated = sm3(b"GRID-V41-AUDIT\x00" + canonical({key: item for key, item in record.items() if key != "event_hash"}))
            if calculated != record["event_hash"]:
                raise Rejected("AUDIT_HASH_MISMATCH")
            previous = calculated
        if previous != root or value["root"] != root:
            raise Rejected("AUDIT_ANCHOR_MISMATCH")
        return True
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        if isinstance(exc, Rejected):
            raise
        raise Rejected("AUDIT_STRUCTURE_INVALID") from exc
