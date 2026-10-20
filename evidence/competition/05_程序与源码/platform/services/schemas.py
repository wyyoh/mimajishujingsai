"""Frozen, strict wire models shared by all roles."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from typing_extensions import Annotated

Identifier = Annotated[
    str, StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{96}$")]
Binary = Annotated[
    str, StringConstraints(min_length=1, max_length=16384, pattern=r"^[A-Za-z0-9_-]+$")
]
Decimal = Annotated[
    str, StringConstraints(min_length=1, max_length=2000, pattern=r"^(0|[1-9][0-9]*)$")
]
Timestamp = Annotated[
    str,
    StringConstraints(
        min_length=20, max_length=32, pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T.*Z$"
    ),
]
Profile = Literal["S0", "SA", "SB", "SAB"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Slot(Strict):
    slot_id: Identifier
    slot_start: Timestamp
    slot_end: Timestamp


class PublicTaskContext(Strict):
    object_type: Literal["GRID_PUBLIC_TASK_V1"]
    schema_version: Literal[1]
    task_id: Identifier
    run_id: Identifier
    task_nonce: Identifier
    metric_id: Literal["average_active_power_W"]
    param_id: Digest
    slots: list[Slot] = Field(min_length=1, max_length=4)


class TaskAuthorization(Strict):
    object_type: Literal["GRID_TASK_AUTH_V1"]
    schema_version: Literal[1]
    task_id: Identifier
    run_id: Identifier
    issuer_role: Literal["utility"]
    target_gw: Identifier
    slots: list[Slot] = Field(min_length=1, max_length=4)
    issued_at: Timestamp
    not_before: Timestamp
    expires_at: Timestamp
    metric_id: Literal["average_active_power_W"]
    param_id: Digest
    policy_ref: Identifier
    token_bundle: dict[str, list[Binary]]
    security_profile: Profile
    key_epoch: Literal[1]


class Signature(Strict):
    algorithm: Literal["ECDSA-P256-SHA256", "ML-DSA-65"]
    key_id: Identifier
    value: Binary


class SignedAuthorization(Strict):
    payload: TaskAuthorization
    signatures: list[Signature] = Field(min_length=1, max_length=2)


class Report(Strict):
    CT: Decimal
    B: Decimal
    C: Binary
    D: list[Binary] = Field(min_length=1, max_length=16)
    T: Timestamp


class ReportEnvelope(Strict):
    task_id: Identifier
    run_id: Identifier
    slot_id: Identifier
    param_id: Digest
    report: Report
    report_id: Digest


class Counts(Strict):
    received: int = Field(ge=0, le=100000)
    accepted: int = Field(ge=0, le=100000)
    joint_check_failed: int = Field(ge=0, le=100000)
    invalid: int = Field(ge=0, le=100000)
    duplicate: int = Field(ge=0, le=100000)
    late: int = Field(ge=0, le=100000)


class AggregationReceipt(Strict):
    object_type: Literal["GRID_AGG_RECEIPT_V1"]
    schema_version: Literal[1]
    task_id: Identifier
    run_id: Identifier
    authorization_digest: Digest
    snapshot_id: Identifier
    slot_id: Identifier
    param_id: Digest
    aggregate_ciphertext: Decimal
    native_signature: Binary
    native_timestamp: Timestamp
    counts: Counts
    status: Literal["AGGREGATED", "NO_VALID_DATA"]
    issued_at: Timestamp
    input_digest: Digest
    key_epoch: Literal[1]
    security_profile: Profile


class SignedReceipt(Strict):
    payload: AggregationReceipt
    signatures: list[Signature] = Field(min_length=1, max_length=2)


class CreateRun(Strict):
    region: Literal["A", "B"] = "A"
    resources: list[Literal["residential", "commercial", "charging"]] = Field(
        default=["residential", "charging"], min_length=1, max_length=3
    )
    scenario: Literal[
        "normal",
        "modified_report",
        "missing",
        "invalid_authorization",
        "invalid_receipt",
        "incompatible_tls",
    ] = "normal"
    nodes: Literal[120] = 120
    slots: Literal[4] = 4


class CollaborationRequest(Strict):
    asset_id: Literal["public-load-demo", "household-load-demo", "critical-load-demo"] = "household-load-demo"
    region: Literal["A", "B"] = "A"
    resources: list[Literal["residential", "commercial", "charging"]] = Field(default=["residential", "charging"], min_length=1, max_length=3)
    function: Literal["SUM", "AVG", "COUNT"] = "SUM"
    algorithm_suite: Literal["V41_HYBRID", "V41_HYBRID_SM"] = "V41_HYBRID_SM"
    validity_minutes: int = Field(default=10, ge=1, le=15)
    request_nonce: Identifier


class GovernancePolicy(Strict):
    policy_version: Literal["V41_POLICY_1"]
    requester_id: Identifier
    asset_id: Identifier
    dataset_version: Identifier
    data_level: Literal["general", "sensitive", "important_simulated"]
    classification_scope: Literal["SIMULATED_NOT_OFFICIAL"]
    operation: Literal["aggregate"]
    function: Literal["SUM", "AVG", "COUNT"]
    region: Literal["A", "B"]
    resources: list[Literal["residential", "commercial", "charging"]] = Field(min_length=1, max_length=3)
    algorithm_suite: Literal["V41_CLASSIC", "V41_SM", "V41_PQ", "V41_HYBRID", "V41_HYBRID_SM"]
    security_profile: Profile
    node_count: int = Field(ge=1, le=10000)
    slot_count: int = Field(ge=1, le=4)
    issued_at: Timestamp
    expires_at: Timestamp
    request_nonce: Identifier
    audit: Literal["FULL"]
    key_epoch: Literal[1]


Hash256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class PublicTaskContextV2(PublicTaskContext):
    object_type: Literal["GRID_PUBLIC_TASK_V2"]
    schema_version: Literal[2]
    governance: GovernancePolicy
    policy_digest: Digest


class TaskAuthorizationV2(TaskAuthorization):
    object_type: Literal["GRID_TASK_AUTH_V2"]
    schema_version: Literal[2]
    governance: GovernancePolicy
    policy_digest: Digest
    task_nonce: Identifier


class SignatureV2(Strict):
    algorithm: Literal["ECDSA-P256-SHA256", "ML-DSA-65", "SM2-SM3"]
    key_id: Identifier
    value: Binary


class SignedAuthorizationV2(Strict):
    payload: TaskAuthorizationV2
    signatures: list[SignatureV2] = Field(min_length=1, max_length=3)


class AggregationReceiptV2(AggregationReceipt):
    object_type: Literal["GRID_AGG_RECEIPT_V2"]
    schema_version: Literal[2]
    policy_digest: Digest
    algorithm_suite: Literal["V41_CLASSIC", "V41_SM", "V41_PQ", "V41_HYBRID", "V41_HYBRID_SM"]
    dataset_version: Identifier
    snapshot_root: Hash256
    snapshot_count: int = Field(ge=0, le=10000)
    snapshot_hash: Literal["SM3"]
    accepted_set_digest: Digest
    aggregation_digest: Digest
    audit_root: Hash256


class SignedReceiptV2(Strict):
    payload: AggregationReceiptV2
    signatures: list[SignatureV2] = Field(min_length=1, max_length=3)


ALL_MODELS = (
    PublicTaskContext,
    TaskAuthorization,
    SignedAuthorization,
    ReportEnvelope,
    AggregationReceipt,
    SignedReceipt,
    CreateRun,
    CollaborationRequest,
    GovernancePolicy,
    PublicTaskContextV2,
    TaskAuthorizationV2,
    SignedAuthorizationV2,
    AggregationReceiptV2,
    SignedReceiptV2,
)
