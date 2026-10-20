"""Verify the exact assertions made by a V2 receipt, with explicit limits."""
from .encoding import canonical, digest, Rejected
from .governance import aggregation_digest
from .merkle import verify_snapshot, accepted_digest
from .audit import verify_checkpoint
from .schemas import GovernancePolicy
from .signatures import validate, time_value


def verify_links(receipt, snapshot, audit, accepted, policy):
    try:
        policy_model = GovernancePolicy
        if receipt.get('schema_version') == 3:
            from .expansion_schemas import ExpansionPolicy
            policy_model = ExpansionPolicy
        elif receipt.get('schema_version') == 4:
            from .security_schemas import ExpansionPolicyV4
            policy_model = ExpansionPolicyV4
        elif receipt.get('schema_version') == 5:
            from .publication_schemas import PublicationPolicy
            policy_model = PublicationPolicy
        policy = validate(policy_model, policy)
        if (receipt["policy_digest"] != digest(policy) or receipt["algorithm_suite"] != policy["algorithm_suite"]
                or receipt["security_profile"] != policy["security_profile"] or receipt["dataset_version"] != policy["dataset_version"]):
            raise Rejected("RECEIPT_POLICY_MISMATCH")
        if not time_value(policy["issued_at"]) <= time_value(receipt["issued_at"]) < time_value(policy["expires_at"]):
            raise Rejected("RECEIPT_OUTSIDE_POLICY_VALIDITY")
        if receipt["snapshot_count"] != receipt["counts"]["received"]:
            raise Rejected("RECEIPT_SNAPSHOT_COUNT_MISMATCH")
        verify_snapshot(snapshot, receipt["snapshot_root"], receipt["snapshot_count"], receipt["slot_id"], policy["dataset_version"])
        identifiers = {item["report_id"] for item in snapshot["records"]}
        if digest(sorted(item["report_id"] for item in snapshot["records"])) != receipt["input_digest"]:
            raise Rejected("SNAPSHOT_INPUT_DIGEST_MISMATCH")
        if (not isinstance(accepted, list) or any(not isinstance(item, str) for item in accepted)
                or len(accepted) != len(set(accepted)) or not set(accepted) <= identifiers
                or len(accepted) != receipt["counts"]["accepted"] or accepted_digest(accepted) != receipt["accepted_set_digest"]):
            raise Rejected("ACCEPTED_SET_DIGEST_MISMATCH")
        if aggregation_digest(receipt) != receipt["aggregation_digest"]:
            raise Rejected("AGGREGATION_DIGEST_MISMATCH")
        verify_checkpoint(audit, receipt["audit_root"], receipt)
        if (any(item["evidence_id"] != receipt["snapshot_root"] for item in audit["records"])
                or [item["record_count"] for item in audit["records"]] != [receipt["snapshot_count"], receipt["snapshot_count"], len(accepted)]):
            raise Rejected("AUDIT_SNAPSHOT_COUNT_MISMATCH")
        return {"slot_id": receipt["slot_id"], "snapshot_verified": True, "policy_link_verified": True,
                "accepted_set_link_verified": True, "aggregation_digest_verified": True, "audit_checkpoint_verified": True,
                "source_completeness": "NOT_INDEPENDENTLY_PROVEN", "plaintext_correspondence": "TRUSTED_UC_OR_PRIVATE_ORACLE_REQUIRED",
                "audit_scope": "Gateway-signed checkpoint; later process events are not independently authenticated"}
    except (KeyError, TypeError, IndexError, ValueError) as exc:
        if isinstance(exc, Rejected):
            raise
        raise Rejected("V41_EVIDENCE_STRUCTURE_INVALID") from exc
