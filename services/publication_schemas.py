"""Explicit V5 publication contracts. Historical signed schemas stay unchanged."""
from typing import Literal
from pydantic import Field
from .schemas import Strict, Digest, Identifier, SignatureV2, Slot, Timestamp
from .security_schemas import ExpansionPolicyV4, PublicTaskContextV4, TaskAuthorizationV4, AggregationReceiptV4


class PublicationPolicy(ExpansionPolicyV4):
    policy_version: Literal['V5_RELEASE_POLICY_1']
    release_rules_digest: Digest
    release_domain: Identifier
    release_plan_id: Identifier
    response_basis_points: int = Field(ge=0, le=2000)
    parent_evaluation: Identifier
    runtime_instance: Digest
    input_binding_scheme: Literal['ROLE_HMAC_SHA384_V1']


class PublicTaskV5(PublicTaskContextV4):
    object_type: Literal['GRID_PUBLIC_TASK_V5']
    schema_version: Literal[5]
    governance: PublicationPolicy


class AuthorizationV5(TaskAuthorizationV4):
    object_type: Literal['GRID_TASK_AUTH_V5']
    schema_version: Literal[5]
    governance: PublicationPolicy


class ReceiptV5(AggregationReceiptV4):
    object_type: Literal['GRID_AGG_RECEIPT_V5']
    schema_version: Literal[5]
    release_rules_digest: Digest
    release_plan_id: Identifier


class SignedAuthorizationV5(Strict):
    payload: AuthorizationV5
    signatures: list[SignatureV2] = Field(min_length=2, max_length=3)


class SignedReceiptV5(Strict):
    payload: ReceiptV5
    signatures: list[SignatureV2] = Field(min_length=2, max_length=3)


class PublicationStatement(Strict):
    object_type: Literal['GRID_UC_RESULT_V2', 'GRID_RELEASE_DECISION_V1', 'GRID_RESPONSE_EVALUATION_V1']
    schema_version: Literal[1, 2]
    run_id: Identifier
    task_id: Identifier
    param_id: Digest
    security_profile: Literal['SAB']
    key_epoch: int = Field(ge=1, le=1000000)
    trust_registry_digest: Digest
    algorithm_suite: Literal['V41_HYBRID', 'V41_HYBRID_SM']
    release_rules_digest: Digest
    policy_digest: Digest
    content_digest: Digest
    issued_at: Timestamp
    publication_sequence: int = Field(ge=0)
    publication_id: Identifier
    decision: Literal['PUBLISHED', 'WITHHELD', 'EXPERIMENT_NOT_RELEASED']


class SignedPublicationStatement(Strict):
    payload: PublicationStatement
    signatures: list[SignatureV2] = Field(min_length=2, max_length=3)


class UCResultV2(PublicationStatement):
    object_type: Literal['GRID_UC_RESULT_V2']
    schema_version: Literal[2]


class ReleaseDecisionV1(PublicationStatement):
    object_type: Literal['GRID_RELEASE_DECISION_V1']
    schema_version: Literal[1]


class EvaluationV1(PublicationStatement):
    object_type: Literal['GRID_RESPONSE_EVALUATION_V1']
    schema_version: Literal[1]


class SignedUCResultV2(SignedPublicationStatement):
    payload: UCResultV2


class SignedReleaseDecisionV1(SignedPublicationStatement):
    payload: ReleaseDecisionV1


class SignedEvaluationV1(SignedPublicationStatement):
    payload: EvaluationV1
