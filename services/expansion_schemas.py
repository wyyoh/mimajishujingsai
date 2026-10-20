"""Additive V3 schemas bind observed data, selected periods and independent sources."""
from typing import Literal
from pydantic import Field
from .schemas import (Strict, Identifier, Digest, Hash256, Profile, Slot, GovernancePolicy,
                      PublicTaskContext, TaskAuthorization, SignatureV2, ReportEnvelope, AggregationReceiptV2)

class ExpansionRequest(Strict):
    dataset_id: Literal['UCI370-WEEK-20130603-V1', 'SYN-WEEK-V42'] = 'SYN-WEEK-V42'
    nodes: int = Field(default=120, ge=120, le=900)
    day: int = Field(default=0, ge=0, le=6)
    periods: list[int] = Field(default=[68, 69, 70, 71], min_length=1, max_length=4)
    scene_id: Literal['residential', 'park', 'charging'] = 'residential'
    region: Literal['A', 'B'] = 'A'
    asset_id: Literal['public-load-demo', 'household-load-demo', 'critical-load-demo'] = 'household-load-demo'
    function: Literal['SUM', 'AVG', 'COUNT'] = 'SUM'
    algorithm_suite: Literal['V41_HYBRID', 'V41_HYBRID_SM'] = 'V41_HYBRID_SM'
    source_count: int = Field(default=1, ge=1, le=3)
    validity_minutes: int = Field(default=10, ge=1, le=15)
    request_nonce: Identifier

class SourceBinding(Strict):
    source_id: Identifier
    node_count: int = Field(ge=1, le=900)
    partition_digest: Digest
    certificate_sha256: Hash256

class ExpansionPolicy(GovernancePolicy):
    policy_version: Literal['V42_POLICY_1']
    dataset_digest: Digest
    parent_dataset_digest: Digest
    data_source: Literal['SYNTHETIC', 'PUBLIC_OBSERVED_SIMULATED_GROUPS']
    scene_id: Literal['residential', 'park', 'charging']
    period_indices: list[int] = Field(min_length=1, max_length=4)
    selected_slots: list[Slot] = Field(min_length=1, max_length=4)
    sources: list[SourceBinding] = Field(min_length=1, max_length=3)

class PublicTaskContextV3(PublicTaskContext):
    object_type: Literal['GRID_PUBLIC_TASK_V3']
    schema_version: Literal[3]
    governance: ExpansionPolicy
    policy_digest: Digest

class TaskAuthorizationV3(TaskAuthorization):
    object_type: Literal['GRID_TASK_AUTH_V3']
    schema_version: Literal[3]
    governance: ExpansionPolicy
    policy_digest: Digest
    task_nonce: Identifier

class SignedAuthorizationV3(Strict):
    payload: TaskAuthorizationV3
    signatures: list[SignatureV2] = Field(min_length=2, max_length=3)

class ReportEnvelopeV3(ReportEnvelope):
    source_id: Identifier

class SourceSnapshot(Strict):
    source_id: Identifier
    root: Hash256
    count: int = Field(ge=0, le=900)
    partition_digest: Digest
    certificate_sha256: Hash256

class AggregationReceiptV3(AggregationReceiptV2):
    object_type: Literal['GRID_AGG_RECEIPT_V3']
    schema_version: Literal[3]
    dataset_digest: Digest
    source_snapshots: list[SourceSnapshot] = Field(min_length=1, max_length=3)

class SignedReceiptV3(Strict):
    payload: AggregationReceiptV3
    signatures: list[SignatureV2] = Field(min_length=2, max_length=3)

MODELS = (ExpansionRequest, ExpansionPolicy, PublicTaskContextV3, TaskAuthorizationV3, SignedAuthorizationV3, ReportEnvelopeV3, AggregationReceiptV3, SignedReceiptV3)
