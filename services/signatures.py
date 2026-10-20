import time
from datetime import datetime, timezone

from pydantic import ValidationError

from . import native
from .encoding import Rejected, canonical, b64, unb64, loads
from .schemas import (
    SignedAuthorization,
    SignedReceipt,
    TaskAuthorization,
    AggregationReceipt,
    TaskAuthorizationV2,
    SignedAuthorizationV2,
    AggregationReceiptV2,
    SignedReceiptV2,
)
from .expansion_schemas import TaskAuthorizationV3, SignedAuthorizationV3, AggregationReceiptV3, SignedReceiptV3
from .security_schemas import TaskAuthorizationV4, SignedAuthorizationV4, AggregationReceiptV4, SignedReceiptV4, UCResultV1, SignedUCResultV1
from .publication_schemas import AuthorizationV5, SignedAuthorizationV5, ReceiptV5, SignedReceiptV5, UCResultV2, SignedUCResultV2, ReleaseDecisionV1, SignedReleaseDecisionV1, EvaluationV1, SignedEvaluationV1

CONTEXTS = {
    "GRID_TASK_AUTH_V1": "GRID-TASK-AUTH-V1",
    "GRID_AGG_RECEIPT_V1": "GRID-AGG-RECEIPT-V1",
    "GRID_TASK_AUTH_V2": "GRID-TASK-AUTH-V2",
    "GRID_AGG_RECEIPT_V2": "GRID-AGG-RECEIPT-V2",
    "GRID_TASK_AUTH_V3": "GRID-TASK-AUTH-V3",
    "GRID_AGG_RECEIPT_V3": "GRID-AGG-RECEIPT-V3",
    "GRID_TASK_AUTH_V4": "GRID-TASK-AUTH-V4",
    "GRID_AGG_RECEIPT_V4": "GRID-AGG-RECEIPT-V4",
    "GRID_UC_RESULT_V1": "GRID-UC-RESULT-V1",
}
MODEL = {
    "GRID_TASK_AUTH_V1": (TaskAuthorization, SignedAuthorization, "utility"),
    "GRID_AGG_RECEIPT_V1": (AggregationReceipt, SignedReceipt, "gateway"),
    "GRID_TASK_AUTH_V2": (TaskAuthorizationV2, SignedAuthorizationV2, "utility"),
    "GRID_AGG_RECEIPT_V2": (AggregationReceiptV2, SignedReceiptV2, "gateway"),
    "GRID_TASK_AUTH_V3": (TaskAuthorizationV3, SignedAuthorizationV3, "utility"),
    "GRID_AGG_RECEIPT_V3": (AggregationReceiptV3, SignedReceiptV3, "gateway"),
    "GRID_TASK_AUTH_V4": (TaskAuthorizationV4, SignedAuthorizationV4, "utility"),
    "GRID_AGG_RECEIPT_V4": (AggregationReceiptV4, SignedReceiptV4, "gateway"),
    "GRID_UC_RESULT_V1": (UCResultV1, SignedUCResultV1, "utility"),
}
ALGORITHMS = (("ECDSA-P256-SHA256", "ecdsa", False), ("ML-DSA-65", "mldsa", True))
MODEL.update({'GRID_TASK_AUTH_V5': (AuthorizationV5, SignedAuthorizationV5, 'utility'),
              'GRID_AGG_RECEIPT_V5': (ReceiptV5, SignedReceiptV5, 'gateway')})
MODEL.update({'GRID_UC_RESULT_V2':(UCResultV2,SignedUCResultV2,'utility'),
              'GRID_RELEASE_DECISION_V1':(ReleaseDecisionV1,SignedReleaseDecisionV1,'utility'),
              'GRID_RESPONSE_EVALUATION_V1':(EvaluationV1,SignedEvaluationV1,'utility')})
for _kind in MODEL:
    CONTEXTS.setdefault(_kind, _kind.replace('_', '-'))


def algorithms_for(payload):
    if payload["schema_version"] == 1 and payload['object_type'] not in ('GRID_UC_RESULT_V1','GRID_RELEASE_DECISION_V1','GRID_RESPONSE_EVALUATION_V1'):
        return tuple(item for item in ALGORITHMS if not item[2] or payload["security_profile"] in ("SA", "SAB"))
    from .agility import provider
    suite = payload.get("algorithm_suite") or payload["governance"]["algorithm_suite"]
    selected = provider(suite)
    if selected.profile != payload["security_profile"]:
        raise Rejected("POLICY_CRYPTO_PROFILE_MISMATCH")
    options = {name: (name, algorithm, pq) for name, algorithm, pq in (*ALGORITHMS, ("SM2-SM3", "sm2", False))}
    return tuple(options[name] for name in selected.algorithms)


def trusted_registry(runtime, role, algorithm):
    from .custody import enabled
    if enabled(runtime) and (runtime / 'public/trust-registry.json').is_file():
        from .trust import lookup
        return lookup(runtime, role, algorithm)
    entry = loads((runtime / "public/key_registry.json").read_bytes())[role][algorithm]
    filename = entry["public_key"]
    if (
        entry["epoch"] != 1
        or "/" in filename
        or "\\" in filename
        or filename.startswith(".")
    ):
        raise Rejected("TRUSTED_REGISTRY_INVALID")
    return entry, runtime / "public" / filename


def validate(model, obj):
    try:
        normalized = model.model_validate(obj).model_dump()
    except ValidationError as exc:
        raise Rejected("OBJECT_SCHEMA_INVALID", str(exc)) from exc
    # Literal[1] can accept True even in strict Pydantic models. Protocol
    # validation must never rewrite the bytes whose signature we verify.
    if canonical(normalized) != canonical(obj):
        raise Rejected("OBJECT_SCHEMA_INVALID", "Protocol validation must preserve canonical input exactly")
    return normalized


def sign_object(payload, runtime):
    kind = payload.get("object_type")
    if kind not in MODEL:
        raise Rejected("OBJECT_TYPE_INVALID")
    model, _, role = MODEL[kind]
    payload = validate(model, payload)
    from .custody import enabled
    if enabled(runtime):
        from .trust import current_binding
        binding = current_binding(runtime)
        if payload['key_epoch'] != binding['key_epoch']:
            raise Rejected('SIGNING_KEY_EPOCH_MISMATCH')
        if payload.get('trust_registry_digest', binding['trust_registry_digest']) != binding['trust_registry_digest']:
            raise Rejected('TRUST_REGISTRY_CHANGED')
    data = canonical(payload)
    signatures = []
    timings = []
    for name, alg, pq in algorithms_for(payload):
        started = time.perf_counter_ns()
        if alg == "sm2":
            from .agility import sm2_sign
            entry, _ = trusted_registry(runtime, role, alg)
            signature = sm2_sign(runtime / role / entry.get('private_key', 'sm2.key'), data, CONTEXTS[kind])
        else:
            entry, _ = trusted_registry(runtime, role, alg)
            signature = native.sign(runtime / role / entry.get('private_key', f'{alg}.key'), data, CONTEXTS[kind], pq)
        entry, _ = trusted_registry(runtime, role, alg)
        signatures.append(
            {"algorithm": name, "key_id": entry["key_id"], "value": b64(signature)}
        )
        timings.append(
            {
                "operation": "sign",
                "algorithm": name,
                "elapsed_ns": time.perf_counter_ns() - started,
                "signature_bytes": len(signature),
                "payload_bytes": len(data),
            }
        )
    return {"payload": payload, "signatures": signatures}, timings


def verify_object(envelope, kind, profile, runtime, *, usage='current'):
    if kind not in MODEL:
        raise Rejected("OBJECT_TYPE_INVALID")
    _, model, role = MODEL[kind]
    envelope = validate(model, envelope)
    payload = envelope["payload"]
    if payload['object_type'] != kind:
        raise Rejected('OBJECT_TYPE_INVALID')
    if payload["security_profile"] != profile:
        raise Rejected("LOCAL_SECURITY_PROFILE_MISMATCH")
    data = canonical(payload)
    if usage == 'current' and 'trust_registry_digest' in payload:
        from .trust import registry
        from .encoding import digest
        if payload['trust_registry_digest'] != digest(registry(runtime)):
            raise Rejected('TRUST_REGISTRY_CHANGED')
    supplied = {}
    for sig in envelope["signatures"]:
        if sig["algorithm"] in supplied:
            raise Rejected("DUPLICATE_SIGNATURE_ALGORITHM")
        supplied[sig["algorithm"]] = sig
    evidence = {
        "object_type": kind,
        "signature_valid": False,
        "ecdsa_valid": None,
        "mldsa_valid": None,
        "sm2_valid": None,
        "timings": [],
    }
    required_algorithms = algorithms_for(payload)
    if (payload["schema_version"] >= 2 or kind in ('GRID_UC_RESULT_V1','GRID_RELEASE_DECISION_V1','GRID_RESPONSE_EVALUATION_V1')) and set(supplied) - {item[0] for item in required_algorithms}:
        raise Rejected("UNEXPECTED_SIGNATURE_ALGORITHM")
    # V1 accepts an additional ML-DSA signature in a classical experiment, as before.
    verify_algorithms = required_algorithms
    if payload["schema_version"] == 1 and "ML-DSA-65" in supplied and not any(item[2] for item in verify_algorithms):
        verify_algorithms = ALGORITHMS
    for name, alg, pq in verify_algorithms:
        if name not in supplied:
            raise Rejected("REQUIRED_SIGNATURE_MISSING")
        signature = supplied[name]
        from .custody import enabled
        if enabled(runtime) and (runtime / 'public/trust-registry.json').is_file():
            from .trust import lookup
            entry, public_key = lookup(runtime, role, alg, key_id=signature['key_id'], epoch=payload['key_epoch'], usage=usage,
                                       registry_digest=payload.get('trust_registry_digest'))
            evidence.setdefault('key_trust', []).append({'key_id': entry['key_id'], 'current_status': entry['current_status'],
                'historical_time_trust': entry['historical_time_trust']})
        else:
            entry, public_key = trusted_registry(runtime, role, alg)
        if signature["key_id"] != entry["key_id"]:
            raise Rejected("UNTRUSTED_SIGNATURE_KEY")
        started = time.perf_counter_ns()
        if alg == "sm2":
            from .agility import sm2_verify
            valid = sm2_verify(public_key, data, CONTEXTS[kind], unb64(signature["value"]))
        else:
            valid = native.verify(public_key, data, CONTEXTS[kind], unb64(signature["value"]), pq)
        evidence["sm2_valid" if alg == "sm2" else "mldsa_valid" if pq else "ecdsa_valid"] = valid
        evidence["timings"].append(
            {
                "operation": "verify",
                "algorithm": name,
                "elapsed_ns": time.perf_counter_ns() - started,
            }
        )
        if not valid:
            exc = Rejected("OBJECT_SIGNATURE_INVALID")
            exc.evidence = evidence
            raise exc
    evidence["signature_valid"] = True
    return payload, evidence


def time_value(value):
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo != timezone.utc:
            raise ValueError()
        return dt
    except ValueError as exc:
        raise Rejected("TIMESTAMP_INVALID") from exc


def check_authorization(payload, context, profile):
    now = datetime.now(timezone.utc)
    if payload["target_gw"] != "gateway":
        raise Rejected("AUTH_WRONG_AUDIENCE")
    if payload["issuer_role"] != "utility":
        raise Rejected("AUTH_WRONG_ISSUER")
    if (
        time_value(payload["not_before"]) > now
        or time_value(payload["issued_at"]) > now
    ):
        raise Rejected("AUTH_NOT_YET_VALID")
    if time_value(payload["expires_at"]) <= now:
        raise Rejected("AUTH_EXPIRED")
    for field in ("task_id", "run_id", "param_id", "metric_id", "slots"):
        if payload[field] != context[field]:
            raise Rejected("AUTH_CONTEXT_MISMATCH")
    if payload["security_profile"] != profile:
        raise Rejected("LOCAL_SECURITY_PROFILE_MISMATCH")
    if set(payload["token_bundle"]) != {s["slot_id"] for s in context["slots"]}:
        raise Rejected("AUTH_SLOT_TOKEN_MISMATCH")
    if payload["schema_version"] >= 2:
        from .encoding import digest
        from .governance import check_policy
        if (payload["task_nonce"] != context["task_nonce"] or payload["policy_digest"] != context["policy_digest"]
                or canonical(payload["governance"]) != canonical(context["governance"])):
            raise Rejected("AUTH_POLICY_CONTEXT_MISMATCH")
        if payload["schema_version"] >= 3:
            from .expansion_governance import check_policy as check_expansion_policy
            policy = check_expansion_policy(payload["governance"], payload["policy_digest"], profile)
        else:
            policy = check_policy(payload["governance"], payload["policy_digest"], profile)
        if payload["expires_at"] != policy["expires_at"] or policy["slot_count"] != len(context["slots"]):
            raise Rejected("AUTH_POLICY_EXPIRY_OR_SLOTS_MISMATCH")
        if payload['schema_version'] >= 3 and canonical(policy['selected_slots']) != canonical(context['slots']):
            raise Rejected('AUTH_SELECTED_PERIODS_MISMATCH')
        if payload['schema_version'] >= 4 and any(payload[key] != policy[key] for key in ('key_epoch', 'trust_registry_digest')):
            raise Rejected('AUTH_TRUST_BINDING_MISMATCH')
