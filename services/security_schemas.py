"""Additive versions for managed keys; historical models remain unchanged."""
from typing import Literal
from pydantic import Field
from .schemas import Strict, Identifier, Digest, Hash256, Slot, SignatureV2, Timestamp
from .expansion_schemas import ExpansionPolicy, PublicTaskContextV3, TaskAuthorizationV3, AggregationReceiptV3


class ExpansionPolicyV4(ExpansionPolicy):
    policy_version: Literal['V43_POLICY_1']
    key_epoch: int = Field(ge=1, le=1000000)
    trust_registry_digest: Digest


class PublicTaskContextV4(PublicTaskContextV3):
    object_type: Literal['GRID_PUBLIC_TASK_V4']
    schema_version: Literal[4]
    governance: ExpansionPolicyV4


class TaskAuthorizationV4(TaskAuthorizationV3):
    object_type: Literal['GRID_TASK_AUTH_V4']
    schema_version: Literal[4]
    key_epoch: int = Field(ge=1, le=1000000)
    trust_registry_digest: Digest
    governance: ExpansionPolicyV4


class AggregationReceiptV4(AggregationReceiptV3):
    object_type: Literal['GRID_AGG_RECEIPT_V4']
    schema_version: Literal[4]
    key_epoch: int = Field(ge=1, le=1000000)
    trust_registry_digest: Digest


class SignedAuthorizationV4(Strict):
    payload: TaskAuthorizationV4
    signatures: list[SignatureV2] = Field(min_length=2, max_length=3)


class SignedReceiptV4(Strict):
    payload: AggregationReceiptV4
    signatures: list[SignatureV2] = Field(min_length=2, max_length=3)


class UCResultV1(Strict):
    object_type: Literal['GRID_UC_RESULT_V1']
    schema_version: Literal[1]
    task_id: Identifier
    run_id: Identifier
    param_id: Digest
    security_profile: Literal['SAB']
    key_epoch: int = Field(ge=1, le=1000000)
    trust_registry_digest: Digest
    algorithm_suite: Literal['V41_HYBRID', 'V41_HYBRID_SM']
    function: Literal['SUM', 'AVG', 'COUNT']
    selected_slot: Slot
    dataset_digest: Digest
    policy_digest: Digest
    authorization_digest: Digest
    receipt_digest: Digest
    result_digest: Digest
    accepted_set_digest: Digest
    snapshot_root: Hash256
    issued_at: Timestamp


class SignedUCResultV1(Strict):
    payload: UCResultV1
    signatures: list[SignatureV2] = Field(min_length=2, max_length=3)


MODELS = (ExpansionPolicyV4, PublicTaskContextV4, TaskAuthorizationV4, AggregationReceiptV4,
          SignedAuthorizationV4, SignedReceiptV4, UCResultV1, SignedUCResultV1)
