"""SM3 Merkle snapshots over encrypted report envelopes, with domain separation."""
from .agility import sm3
from .encoding import Rejected, canonical, digest


def leaf(record):
    return sm3(b"GRID-V41-LEAF\x00" + canonical(record))


def branch(left, right):
    return sm3(b"GRID-V41-NODE\x00" + bytes.fromhex(left) + bytes.fromhex(right))


def snapshot(records, dataset_version, slot_id):
    ordered = sorted(records, key=lambda record: record["report_id"])
    levels = [[leaf(record) for record in ordered]]
    if not ordered:
        levels = [[sm3(b"GRID-V41-EMPTY\x00")]]
    while len(levels[-1]) > 1:
        row = levels[-1]
        levels.append([branch(row[i], row[i + 1] if i + 1 < len(row) else row[i]) for i in range(0, len(row), 2)])
    proofs = []
    for index in range(min(3, len(ordered))):
        cursor, path = index, []
        for row in levels[:-1]:
            sibling = cursor ^ 1
            path.append({"side": "left" if cursor % 2 else "right", "hash": row[sibling] if sibling < len(row) else row[cursor]})
            cursor //= 2
        proofs.append({"index": index, "record": ordered[index], "path": path})
    return {"schema": "GRID_CIPHERTEXT_SNAPSHOT_V2", "hash_algorithm": "SM3", "dataset_version": dataset_version,
            "slot_id": slot_id, "record_count": len(ordered), "merkle_root": levels[-1][0], "records": ordered, "proofs": proofs}


def verify_proof(proof, root, count):
    if type(count) is not int or count < 1 or type(proof.get("index")) is not int or not 0 <= proof["index"] < count:
        raise Rejected("MERKLE_PROOF_INDEX_INVALID")
    value, cursor, width = leaf(proof["record"]), proof["index"], count
    for item in proof["path"]:
        if width <= 1 or item["side"] != ("left" if cursor % 2 else "right"):
            raise Rejected("MERKLE_PROOF_SHAPE_INVALID")
        sibling = item["hash"]
        if len(sibling) != 64 or any(c not in "0123456789abcdef" for c in sibling):
            raise Rejected("MERKLE_PROOF_HASH_INVALID")
        if cursor % 2 == 0 and cursor + 1 == width and sibling != value:
            raise Rejected("MERKLE_ODD_NODE_INVALID")
        value = branch(sibling, value) if cursor % 2 else branch(value, sibling)
        cursor, width = cursor // 2, (width + 1) // 2
    if width != 1 or value != root:
        raise Rejected("MERKLE_PROOF_MISMATCH")
    return True


def verify_snapshot(value, root, count, slot, version):
    try:
        if (value["schema"] != "GRID_CIPHERTEXT_SNAPSHOT_V2" or value["hash_algorithm"] != "SM3"
                or value["slot_id"] != slot or value["dataset_version"] != version or value["record_count"] != count
                or type(value["record_count"]) is not int or len(value["records"]) != count):
            raise Rejected("SNAPSHOT_CONTEXT_MISMATCH")
        rebuilt = snapshot(value["records"], version, slot)
        if value["records"] != rebuilt["records"] or value["merkle_root"] != root or rebuilt["merkle_root"] != root:
            raise Rejected("SNAPSHOT_ROOT_MISMATCH")
        for proof in value["proofs"]:
            verify_proof(proof, root, count)
            if canonical(proof["record"]) != canonical(value["records"][proof["index"]]):
                raise Rejected("SNAPSHOT_PROOF_RECORD_MISMATCH")
        return True
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        if isinstance(exc, Rejected):
            raise
        raise Rejected("SNAPSHOT_STRUCTURE_INVALID") from exc


def accepted_digest(report_ids):
    return digest(sorted(report_ids))
