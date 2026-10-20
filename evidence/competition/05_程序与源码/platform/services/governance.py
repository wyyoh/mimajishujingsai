"""Server-owned simulated asset classification and least-authority policies."""
from datetime import datetime, timedelta, timezone

from .agility import provider
from .encoding import Rejected, digest, canonical
from .schemas import GovernancePolicy
from .signatures import validate, time_value

ASSETS = {
    "public-load-demo": {"name": "公开合成负荷样例", "contains_individual": False, "business_sensitive": False, "critical_scenario": False},
    "household-load-demo": {"name": "用户侧负荷协同样例", "contains_individual": True, "business_sensitive": True, "critical_scenario": False},
    "critical-load-demo": {"name": "重要数据模拟场景", "contains_individual": True, "business_sensitive": True, "critical_scenario": True},
}
SUBJECTS = {
    "grid_operator_A": {"name": "A区协同运营方", "regions": ["A"], "levels": ["general", "sensitive", "important_simulated"], "functions": ["SUM", "AVG", "COUNT"]},
    "grid_operator_B": {"name": "B区协同运营方", "regions": ["B"], "levels": ["general", "sensitive", "important_simulated"], "functions": ["SUM", "AVG", "COUNT"]},
    "grid_analyst_A": {"name": "A区公开数据分析方", "regions": ["A"], "levels": ["general"], "functions": ["SUM", "COUNT"]},
}


def classify(asset_id):
    if asset_id not in ASSETS:
        raise Rejected("ASSET_UNKNOWN")
    asset = ASSETS[asset_id]
    score = 20 + 30 * asset["contains_individual"] + 30 * asset["business_sensitive"] + 20 * asset["critical_scenario"]
    level = "important_simulated" if asset["critical_scenario"] else "sensitive" if score >= 50 else "general"
    return {"asset_id": asset_id, **asset, "risk_score": score, "data_level": level,
            "classification_scope": "SIMULATED_NOT_OFFICIAL", "dataset_version": "SYN-120-V3",
            "record_count": 480, "node_count": 120, "metric": "average_active_power_W",
            "required_suite": "V41_HYBRID_SM" if level == "important_simulated" else "V41_HYBRID",
            "available_operations": ["SUM", "AVG", "COUNT"], "data_source": "SYNTHETIC"}


def decide(request, subject, *, experimental=False, nodes=120, slots=4):
    request = request.model_dump() if hasattr(request, "model_dump") else request
    if subject not in SUBJECTS:
        raise Rejected("POLICY_SUBJECT_UNKNOWN")
    asset, grant = classify(request["asset_id"]), SUBJECTS[subject]
    if request["region"] not in grant["regions"]:
        raise Rejected("POLICY_REGION_DENIED")
    if asset["data_level"] not in grant["levels"]:
        raise Rejected("POLICY_DATA_LEVEL_DENIED")
    if request["function"] not in grant["functions"]:
        raise Rejected("POLICY_FUNCTION_DENIED")
    if (not request["resources"] or len(set(request["resources"])) != len(request["resources"])
            or not set(request["resources"]) <= {"residential", "commercial", "charging"}):
        raise Rejected("POLICY_RESOURCE_INVALID")
    selected = provider(request["algorithm_suite"])
    if not experimental and (not selected.business_allowed or (asset["data_level"] == "important_simulated" and not selected.sm4_channel)):
        raise Rejected("POLICY_CRYPTO_DOWNGRADE")
    minutes = request.get("validity_minutes", 10)
    if type(minutes) is not int or not 1 <= minutes <= 15:
        raise Rejected("POLICY_VALIDITY_INVALID")
    now = datetime.now(timezone.utc)
    timestamp = lambda value: value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    policy = validate(GovernancePolicy, {
        "policy_version": "V41_POLICY_1", "requester_id": subject, "asset_id": request["asset_id"],
        "dataset_version": asset["dataset_version"] if nodes == 120 and slots == 4 else f"SYN-{nodes}-{slots}-PROBE", "data_level": asset["data_level"],
        "classification_scope": "SIMULATED_NOT_OFFICIAL", "operation": "aggregate", "function": request["function"],
        "region": request["region"], "resources": sorted(request["resources"]), "algorithm_suite": selected.suite,
        "security_profile": selected.profile, "node_count": nodes, "slot_count": slots,
        "issued_at": timestamp(now), "expires_at": timestamp(now + timedelta(minutes=minutes)),
        "request_nonce": request["request_nonce"], "audit": "FULL", "key_epoch": 1,
    })
    return policy


def check_policy(policy, expected_digest, profile, *, business=False):
    policy = validate(GovernancePolicy, policy)
    if digest(policy) != expected_digest:
        raise Rejected("POLICY_DIGEST_MISMATCH")
    if time_value(policy["expires_at"]) <= datetime.now(timezone.utc):
        raise Rejected("POLICY_EXPIRED")
    if time_value(policy["issued_at"]) > datetime.now(timezone.utc) or time_value(policy["expires_at"]) <= time_value(policy["issued_at"]):
        raise Rejected("POLICY_TIME_INVALID")
    selected = provider(policy["algorithm_suite"])
    if selected.profile != profile or policy["security_profile"] != profile:
        raise Rejected("POLICY_CRYPTO_PROFILE_MISMATCH")
    if business and not selected.business_allowed:
        raise Rejected("POLICY_CRYPTO_DOWNGRADE")
    # Re-run grants from the trusted local registry, never from supplied role claims.
    grant = SUBJECTS.get(policy["requester_id"])
    asset = classify(policy["asset_id"])
    if (not grant or policy["region"] not in grant["regions"] or policy["data_level"] not in grant["levels"]
            or policy["function"] not in grant["functions"] or policy["data_level"] != asset["data_level"]
            or policy["dataset_version"] != (asset["dataset_version"] if policy["node_count"] == 120 and policy["slot_count"] == 4 else f"SYN-{policy['node_count']}-{policy['slot_count']}-PROBE")):
        raise Rejected("POLICY_GRANT_MISMATCH")
    if business and asset["data_level"] == "important_simulated" and not selected.sm4_channel:
        raise Rejected("POLICY_CRYPTO_DOWNGRADE")
    return policy


def aggregation_digest(receipt):
    keys = ("task_id", "run_id", "slot_id", "param_id", "aggregate_ciphertext", "native_signature", "native_timestamp", "counts", "snapshot_root", "accepted_set_digest", "policy_digest")
    if receipt.get('schema_version', 1) >= 3:
        keys += ('dataset_digest', 'source_snapshots')
    return digest({key: receipt[key] for key in keys})


def present_value(function, total, count):
    if total is None or count == 0:
        return {"function": function, "value": None, "unit": "reports" if function == "COUNT" else "W"}
    if function == "COUNT":
        return {"function": function, "value": str(count), "unit": "reports", "basis": "accepted signed report count"}
    if function == "AVG":
        return {"function": function, "value": f"{total}/{count}", "numerator": total, "denominator": count, "unit": "W"}
    return {"function": function, "value": str(total), "unit": "W"}
