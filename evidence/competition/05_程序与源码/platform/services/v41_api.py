import os
import uuid
from typing import Literal

from fastapi import Header, HTTPException, Request, Response
from pydantic import Field

from .agility import PROVIDERS
from .encoding import Rejected, digest
from .governance import ASSETS, SUBJECTS, classify, decide
from .initialization import ROOT, RUNTIME
from .schemas import Strict, CollaborationRequest, CreateRun
from .sessions import COOKIE, principal, login, logout
from .storage import read


class Login(Strict):
    subject: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class Attack(Strict):
    kind: Literal["snapshot_record", "snapshot_root", "policy", "aggregation_digest", "audit_event", "audit_drop", "audit_reorder", "accepted_set", "signature", "epoch_type", "replay_context"]


class SelfCheck(Strict):
    run_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


class LabCollaboration(CollaborationRequest):
    scenario: Literal["normal", "modified_report", "missing", "invalid_authorization", "invalid_receipt", "incompatible_tls", "snapshot_tamper", "policy_tamper", "audit_tamper", "result_digest_tamper"] = "normal"


def install_routes(app, enqueue, check_id, summary):
    @app.get("/api/session")
    def current_session(request: Request):
        subject = principal(request, required=False)
        return {"authenticated": subject is not None, "subject": subject, "grant": SUBJECTS.get(subject),
                "scope": "LOCAL_PROTOTYPE_OPERATOR", "subjects": [{"id": key, "name": value["name"]} for key, value in SUBJECTS.items()]}

    @app.post("/api/session")
    def sign_in(data: Login, response: Response):
        token = login(data.subject, data.password)
        response.set_cookie(COOKIE, token, max_age=1800, httponly=True, samesite="strict", path="/")
        return {"authenticated": True, "subject": data.subject, "grant": SUBJECTS[data.subject], "scope": "LOCAL_PROTOTYPE_OPERATOR"}

    @app.post("/api/session/logout")
    def sign_out(request: Request, response: Response):
        logout(request)
        response.delete_cookie(COOKIE, path="/")
        return {"authenticated": False}

    @app.get("/api/assets")
    def assets():
        return {"assets": [classify(key) for key in ASSETS], "classification_scope": "SIMULATED_NOT_OFFICIAL"}

    @app.get("/api/crypto/providers")
    def providers():
        return {"providers": [value.public() for value in PROVIDERS.values()], "default_business_suite": "V41_HYBRID_SM",
                "scope": "SM application signatures/hash/AEAD with TLS1.3; TLCP not implemented; classical certificate identity"}

    @app.get("/lab/v41/benchmarks")
    def benchmarks():
        if os.environ.get("GRID_LAB") != "1":
            raise HTTPException(403, "LAB_DISABLED")
        from .versioning import source_version
        path = ROOT / "artifacts/iterations/v41/benchmarks/summary.json"
        result = read(path) if path.exists() else {"status": "NOT_RUN", "profiles": []}
        result["current_core_source_digest"] = source_version()["core_source_digest"]
        result["current_version_matches"] = result.get("core_source_digest") == result["current_core_source_digest"]
        return result

    @app.post("/api/policies/preview")
    def preview(data: CollaborationRequest, request: Request):
        subject = principal(request)
        try:
            policy = decide(data, subject)
        except Rejected as exc:
            raise HTTPException(403, exc.code) from exc
        return {"policy": policy, "policy_digest": digest(policy), "decision": "ALLOW", "execution_mode": "PREVIEW", "authorization_signed": False,
                "provider": PROVIDERS[policy["algorithm_suite"]].public()}

    @app.post("/api/collaborations", status_code=202)
    def create(data: CollaborationRequest, request: Request, idempotency_key: str | None = Header(default=None)):
        subject = principal(request)
        try:
            policy = decide(data, subject)
        except Rejected as exc:
            raise HTTPException(403, exc.code) from exc
        run_data = CreateRun(region=data.region, resources=data.resources)
        return enqueue(run_data, idempotency_key, False, governance=policy,
                       request_digest=digest({"request": data.model_dump(), "subject": subject, "lab": False}))

    @app.post("/lab/collaborations", status_code=202)
    def lab_collaboration(data: LabCollaboration, request: Request, idempotency_key: str | None = Header(default=None)):
        if os.environ.get("GRID_LAB") != "1":
            raise HTTPException(403, "LAB_DISABLED")
        subject = principal(request)
        try:
            policy = decide(data, subject)
        except Rejected as exc:
            raise HTTPException(403, exc.code) from exc
        compatibility_scenarios = {"normal", "modified_report", "missing", "invalid_authorization", "invalid_receipt", "incompatible_tls"}
        run_data = CreateRun(region=data.region, resources=data.resources, scenario=data.scenario if data.scenario in compatibility_scenarios else "normal")
        # Additional V4.1 faults are explicit lab-only inputs, not business fields.
        class LabData:
            region, resources, scenario = data.region, data.resources, data.scenario
            def model_dump(self):
                return {"region": self.region, "resources": self.resources, "scenario": self.scenario, "nodes": 120, "slots": 4}
        return enqueue(run_data if data.scenario in compatibility_scenarios else LabData(), idempotency_key, True, governance=policy,
                       request_digest=digest({"request": data.model_dump(), "subject": subject, "lab": True}))

    @app.get("/api/runs/{run_id}/v41")
    def details(run_id: str, request: Request):
        subject = principal(request)
        current = summary(run_id)
        if current.get("requester_id") != subject or current.get("protocol_version") != 2:
            raise HTTPException(403, "V41_RUN_ACCESS_DENIED")
        directory = check_id(run_id)
        result = {name: read(directory / (name + ".json")) if (directory / (name + ".json")).exists() else None
                  for name in ("governance", "audit_checkpoints", "accepted_manifests")}
        snapshots = read(directory / "snapshots.json") if (directory / "snapshots.json").exists() else {}
        result["snapshots"] = {slot: {key: value for key, value in snapshot.items() if key != "records"} for slot, snapshot in snapshots.items()}
        result["scope"] = "Ciphertext inclusion and GW receipt assertions; UC plaintext correspondence is not independently proven"
        return result

    @app.post("/api/runs/{run_id}/v41/verify")
    def verify(run_id: str, request: Request):
        principal(request)
        current = summary(run_id)
        if current.get("protocol_version") != 2:
            raise HTTPException(409, "V41_RECORD_REQUIRED")
        from .evidence import export_public, verify_export
        archive = ROOT / "artifacts/exports" / (run_id + ".zip")
        if not archive.exists():
            try:
                archive = export_public(run_id)
            except Rejected as exc:
                raise HTTPException(409, exc.code) from exc
        try:
            return verify_export(archive, expected_context={key: current[key] for key in ("run_id", "task_id", "param_id", "security_profile", "slot_count", "algorithm_suite", "policy_digest")})
        except Rejected as exc:
            raise HTTPException(422, exc.code) from exc

    @app.post("/api/runs/{run_id}/v41/attack")
    def demonstrate(run_id: str, data: Attack, request: Request):
        principal(request)
        current = summary(run_id)
        if os.environ.get("GRID_LAB") != "1":
            raise HTTPException(403, "LAB_DISABLED")
        if current.get("protocol_version") != 2 or not current.get("results"):
            raise HTTPException(409, "COMPLETED_V41_RECORD_REQUIRED")
        from .v41_attacks import attack
        return attack(run_id, data.kind)

    @app.post("/api/self-check")
    def self_check(data: SelfCheck, request: Request):
        subject = principal(request)
        if data.run_id:
            current = summary(data.run_id)
            if current.get("requester_id") != subject:
                raise HTTPException(403, "RUN_SUBJECT_ACCESS_DENIED")
            from .custody import trust_pin
            if current.get('protocol_version')==5 and (current.get('runtime_instance')!=trust_pin(RUNTIME)['registry_pin'] or current.get('private_experiment')):
                raise HTTPException(403,'RUN_AUTHORITY_MISMATCH')
        from .selfcheck import check
        try:
            return check(data.run_id, subject=subject)
        except Rejected as exc:
            raise HTTPException(422, exc.code) from exc

    @app.get("/lab/runs/{run_id}/source-preview")
    def source_preview(run_id: str, request: Request):
        principal(request)
        raise HTTPException(409,'HISTORICAL_RECORD_OFFLINE_VERIFICATION_ONLY')
