import asyncio
import fcntl
import hashlib
import json
import os
import sqlite3
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .encoding import canonical, digest, Rejected, loads
from .initialization import ROOT, RUNTIME
from .orchestrator import RUNS, execute, initialize
from .schemas import CreateRun
from .storage import read, write
from .recovery import recover_interrupted_submissions

LOCK = threading.Lock()
JOBS = {}
LAB = os.environ.get("GRID_LAB") == "1"


@asynccontextmanager
async def lifespan(app):
    RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any(t.is_alive() for t in JOBS.values()):
        raise RuntimeError("API_JOBS_STILL_STOPPING")
    with (RUNTIME / "api.lock").open("a+") as lease:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("API_ALREADY_RUNNING_FOR_RUNTIME") from exc
        initialize()
        from .sessions import initialize_access
        initialize_access()
        RUNS.mkdir(parents=True, exist_ok=True)
        recover_interrupted_submissions()
        try:
            yield
        finally:
            for run_id, thread in JOBS.items():
                if thread.is_alive():
                    write(check_id(run_id) / "cancel.request", {"requested": True})
                    job = RUNTIME / "runs" / run_id
                    if job.exists():
                        write(job / "cancel.request", {"requested": True}, True)
            for thread in JOBS.values():
                if thread.is_alive():
                    await asyncio.to_thread(thread.join, 10)


app = FastAPI(title="新型电网密态聚合平台", version="0.1.0", lifespan=lifespan)


@app.middleware("http")
async def local_origin(request: Request, call_next):
    origin = request.headers.get("origin")
    if (
        request.method == "POST"
        and request.url.path.startswith(("/api/", "/lab/"))
        and request.headers.get("content-type", "").startswith("application/json")
    ):
        try:
            loads(await request.body())
        except Rejected as exc:
            return JSONResponse({"detail": exc.code}, status_code=422)
    if (
        request.method in ("POST", "PUT", "PATCH", "DELETE")
        and origin
        and origin not in ("http://127.0.0.1:8580", "http://localhost:8580")
    ):
        return JSONResponse({"detail": "LOCAL_ORIGIN_REQUIRED"}, status_code=403)
    parts = request.url.path.split("/")
    if request.method == 'POST' and request.url.path in ('/api/runs', '/lab/runs', '/api/collaborations', '/lab/collaborations'):
        from .sessions import principal
        try:
            principal(request)
        except HTTPException as exc:
            return JSONResponse({'detail': exc.detail}, status_code=exc.status_code)
        return JSONResponse({'detail': 'PROTECTED_WORKSPACE_REQUIRED'}, status_code=409)
    if len(parts) >= 4 and parts[1:3] == ["api", "runs"] and len(parts[3]) == 32:
        path = RUNS / parts[3] / "run_manifest.json"
        if path.is_file():
            value = read(path)
            from .sessions import principal
            try:
                principal(request)
            except HTTPException as exc:
                return JSONResponse({'detail':exc.detail},status_code=exc.status_code)
            if value.get("protocol_version") != 5 or value.get('input_binding_scheme')!='ROLE_HMAC_SHA384_V1':
                return JSONResponse({'detail': 'HISTORICAL_RECORD_OFFLINE_VERIFICATION_ONLY'}, status_code=409)
            from .custody import trust_pin
            if value.get('runtime_instance')!=trust_pin(RUNTIME)['registry_pin']:
                return JSONResponse({'detail':'RUN_AUTHORITY_MISMATCH'},status_code=403)
            if value.get("protocol_version") in (2, 3, 4, 5):
                from .sessions import principal
                try:
                    subject = principal(request)
                    if subject != value.get("requester_id"):
                        raise HTTPException(403, "RUN_SUBJECT_ACCESS_DENIED")
                except HTTPException as exc:
                    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = (
        "no-store" if request.url.path.startswith(("/api", "/lab")) else "no-cache"
    )
    return response


def check_id(run_id):
    if len(run_id) != 32 or any(c not in "0123456789abcdef" for c in run_id):
        raise HTTPException(404, "RUN_NOT_FOUND")
    return RUNS / run_id


def summary(run_id):
    path = check_id(run_id) / "run_manifest.json"
    try:
        result = read(path)
    except FileNotFoundError:
        raise HTTPException(404, "RUN_NOT_FOUND")
    if result.get("lab") and not LAB:
        raise HTTPException(403, "LAB_RECORD_ACCESS_DISABLED")
    config_path = RUNTIME / "runs" / run_id / "utility/config.json"
    if config_path.exists():
        private_config = read(config_path)
        result["display_policy"] = {
            k: private_config[k] for k in ("region", "resources")
        }
    published = RUNTIME / "runs" / run_id / "utility/published.json"
    if result.get('protocol_version') != 5 and result["status"] == "RUNNING" and published.exists():
        result["results"] = read(published)["results"]
    return result


def enqueue(data, key, lab, governance=None, request_digest=None, evaluation=None):
    if governance is None or governance.get('policy_version') != 'V5_RELEASE_POLICY_1':
        raise HTTPException(409, 'PROTECTED_WORKSPACE_REQUIRED')
    if not lab and data.scenario != "normal":
        raise HTTPException(403, "LAB_ENTRY_REQUIRED")
    if key is None or not 8 <= len(key) <= 128:
        raise HTTPException(400, "IDEMPOTENCY_KEY_REQUIRED")
    parameters = data.model_dump()
    hash_value = request_digest or digest({**parameters, "lab": lab})
    with LOCK:
        db = sqlite3.connect(RUNTIME / "api.sqlite")
        db.execute(
            "CREATE TABLE IF NOT EXISTS submissions (key TEXT PRIMARY KEY, digest TEXT, run_id TEXT)"
        )
        old = db.execute(
            "SELECT digest,run_id FROM submissions WHERE key=?", (key,)
        ).fetchone()
        if old:
            db.close()
            if old[0] != hash_value:
                raise HTTPException(409, "IDEMPOTENCY_KEY_CONFLICT")
            return {"run_id": old[1], "idempotent": True}
        if any(t.is_alive() for t in JOBS.values()):
            db.close()
            raise HTTPException(409, "RUN_IN_PROGRESS")
        if governance is not None:
            db.execute("CREATE TABLE IF NOT EXISTS v41_nonces (subject TEXT, nonce TEXT, run_id TEXT, PRIMARY KEY(subject,nonce))")
            if db.execute("SELECT run_id FROM v41_nonces WHERE subject=? AND nonce=?", (governance["requester_id"], governance["request_nonce"])).fetchone():
                db.close()
                raise HTTPException(409, "POLICY_REQUEST_NONCE_REPLAY")
        run_id = uuid.uuid4().hex
        if evaluation is not None:
            governance = {**governance,'parent_evaluation':run_id}
        path = RUNS / run_id
        path.mkdir(parents=True)
        initial_manifest = {
                "run_id": run_id,
                "status": "RUNNING",
                "execution_mode": "REAL",
                "data_source": "SYNTHETIC",
                "security_profile": "SAB",
                "scenario": data.scenario,
                "node_count": 120,
                "slot_count": 4,
                "results": [],
                "lab": lab,
            }
        if governance is not None:
            initial_manifest.update(protocol_version=2, requester_id=governance["requester_id"],
                                    algorithm_suite=governance["algorithm_suite"], policy_digest=digest(governance),
                                    asset_id=governance["asset_id"], data_level=governance["data_level"], function=governance["function"])
            initial_manifest['runtime_instance']=governance['runtime_instance']
            initial_manifest['input_binding_scheme']=governance['input_binding_scheme']
            if governance['policy_version'] in ('V42_POLICY_1', 'V43_POLICY_1', 'V5_RELEASE_POLICY_1'):
                initial_manifest.update(protocol_version=5 if governance['policy_version'] == 'V5_RELEASE_POLICY_1' else 4 if governance['policy_version'] == 'V43_POLICY_1' else 3, node_count=governance['node_count'], slot_count=governance['slot_count'],
                                        data_source=governance['data_source'], dataset_id=governance['dataset_version'], dataset_digest=governance['dataset_digest'],
                                        scene_id=governance['scene_id'], logical_source_process_count=len(governance['sources']))
        if evaluation is not None:
            initial_manifest['evaluation_id'] = run_id
        write(path / "run_manifest.json", initial_manifest)
        db.execute("INSERT INTO submissions VALUES(?,?,?)", (key, hash_value, run_id))
        if governance is not None:
            db.execute("INSERT INTO v41_nonces VALUES(?,?,?)", (governance["requester_id"], governance["request_nonce"], run_id))
        db.commit()
        db.close()

        def work():
            try:
                if evaluation is not None:
                    from .response import execute as evaluate
                    evaluate(evaluation,governance['requester_id'],run_id=run_id,lab=lab,policy=governance)
                    return
                if governance is not None and governance['policy_version'] in ('V42_POLICY_1', 'V43_POLICY_1', 'V5_RELEASE_POLICY_1'):
                    from .expansion_orchestrator import execute as execute_expansion
                    execute_expansion(governance, run_id=run_id, lab=lab, fault=data.scenario)
                    return
                extra = {"governance": governance} if governance is not None else {}
                execute(
                    nodes=120,
                    slots=4,
                    region=data.region,
                    resources=data.resources,
                    scenario=data.scenario,
                    run_id=run_id,
                    lab=lab,
                    **extra,
                )
            except BaseException as exc:
                current = read(path / "run_manifest.json")
                current.update(
                    status="FAILED",
                    errors=[
                        {
                            "code": getattr(exc, "code", "EXECUTION_FAILED"),
                            "message": str(exc),
                        }
                    ],
                )
                write(path / "run_manifest.json", current)

        thread = threading.Thread(target=work, daemon=True)
        JOBS[run_id] = thread
        thread.start()
    return {"run_id": run_id, "idempotent": False}


@app.get("/api/config")
def config():
    public = read(RUNTIME / "public/parameters.json")
    return {
        "title": "面向新型电网的细粒度密态聚合与可信数据协同平台",
        "lab_enabled": LAB,
        "execution_mode": "REAL",
        "data_source": "SYNTHETIC",
        "default_profile": "SAB",
        "param_id": public["param_id"],
        "core_version": public["core_version"],
        "policy_hiding": public["policy_hiding"],
        "core_audit_status": public["core_audit_status"],
        "iteration_version": "V4.1",
        "operator_access_scope": "Local prototype credentials; not enterprise IAM",
    }


@app.post("/api/runs", status_code=202)
def create(data: CreateRun, request: Request, idempotency_key: str | None = Header(default=None)):
    if data.scenario != "normal":
        raise HTTPException(403, "LAB_ENTRY_REQUIRED")
    return create_compatibility_run(data, request, idempotency_key, False)


def create_compatibility_run(data, request, key, lab):
    # The old UI endpoint is governed too; it must not bypass V4.1 asset grants.
    from .sessions import principal
    from .governance import decide
    subject = principal(request)
    body = {"asset_id": "household-load-demo", "region": data.region, "resources": data.resources,
            "function": "SUM", "algorithm_suite": "V41_HYBRID_SM",
            "request_nonce": hashlib.sha256((str(key) + subject + str(lab)).encode()).hexdigest()}
    try:
        policy = decide(body, subject)
    except Rejected as exc:
        raise HTTPException(403, exc.code) from exc
    return enqueue(data, key, lab, governance=policy, request_digest=digest({"request": data.model_dump(), "subject": subject, "lab": lab}))


@app.post("/lab/runs", status_code=202)
def lab_create(data: CreateRun, request: Request, idempotency_key: str | None = Header(default=None)):
    if not LAB:
        raise HTTPException(403, "LAB_DISABLED")
    return create_compatibility_run(data, request, idempotency_key, True)


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    return summary(run_id)


@app.get("/api/runs")
def history(request: Request):
    from .sessions import principal
    subject = principal(request, required=False)
    paths = sorted(
        RUNS.glob("*/run_manifest.json"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    records = []
    for path in paths:
        value = read(path)
        if value.get('protocol_version') in (3, 4, 5):
            continue
        if value.get("protocol_version") == 2 and value.get("requester_id") != subject:
            continue
        if value.get("lab") and not LAB:
            continue
        if value["status"] == "RUNNING":
            continue
        records.append(
            {
                k: value.get(k)
                for k in (
                    "run_id",
                    "status",
                    "security_profile",
                    "scenario",
                    "started_at",
                    "execution_mode",
                    "data_source",
                    "node_count",
                    "protocol_version",
                    "algorithm_suite",
                    "asset_id",
                )
            }
        )
        if len(records) >= 16:
            break
    return records


def events_for(run_id):
    path = check_id(run_id) / "events.json"
    if path.exists():
        return read(path)
    result = []
    directory = RUNTIME / "runs" / run_id / "events"
    if directory.exists():
        for f in directory.glob("*.jsonl"):
            for line in f.read_text().splitlines():
                try:
                    result.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    result.sort(key=lambda x: x["at"])
    record = read(check_id(run_id) / 'run_manifest.json')
    if record.get('protocol_version') == 5:
        result = [{key: row[key] for key in ('run_id','role','stage','at','slot_id','code') if key in row} for row in result]
    return [{**x, "sequence": i + 1} for i, x in enumerate(result)]


@app.get("/api/runs/{run_id}/events")
def events(run_id: str):
    summary(run_id)
    return events_for(run_id)


@app.get("/api/runs/{run_id}/stream")
async def stream(run_id: str):
    summary(run_id)

    async def generate():
        seen = set()
        while True:
            for item in events_for(run_id):
                identity = digest({k: v for k, v in item.items() if k != "sequence"})
                if identity not in seen:
                    seen.add(identity)
                    yield "data: " + json.dumps(item, ensure_ascii=False) + "\n\n"
            current = summary(run_id)
            if current["status"] != "RUNNING":
                yield "event: finished\ndata: {}\n\n"
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.post("/api/runs/{run_id}/cancel")
def cancel(run_id: str):
    current = summary(run_id)
    if current["status"] != "RUNNING":
        raise HTTPException(409, "RUN_ALREADY_FINISHED")
    path = RUNTIME / "runs" / run_id
    write(check_id(run_id) / "cancel.request", {"requested": True})
    if not path.exists():
        current["status"] = "CANCELLED"
        # display_policy is a UC-only view field and is not added to public records.
        current.pop("display_policy", None)
        write(check_id(run_id) / "run_manifest.json", current)
    else:
        write(path / "cancel.request", {"requested": True})
    return {"run_id": run_id, "cancel_requested": True}


@app.get("/api/runs/{run_id}/evidence")
def evidence(run_id: str):
    directory = check_id(run_id)
    summary(run_id)
    names = (
        "recovery_evidence.json",
        "connection_evidence.json",
        "signature_evidence.json",
        "authorization_evidence.json",
        "rejection_evidence.json",
    )
    result = {
        n.removesuffix(".json"): read(directory / n)
        if (directory / n).exists()
        else None
        for n in names
    }
    if LAB and summary(run_id).get('protocol_version') != 5 and (directory / "oracle_summary.json").exists():
        result["oracle_summary"] = read(directory / "oracle_summary.json")
    return result


@app.get("/api/runs/{run_id}/export")
def export(run_id: str):
    summary(run_id)
    from .evidence import export_public

    try:
        path = export_public(run_id)
    except Rejected as exc:
        raise HTTPException(409, exc.code) from exc
    return FileResponse(path, filename=path.name, media_type="application/zip")


@app.get("/lab/benchmarks")
def benchmarks():
    if not LAB:
        raise HTTPException(403, "LAB_DISABLED")
    path = ROOT / "artifacts/benchmarks/summary.json"
    return read(path) if path.exists() else {"status": "NOT_RUN", "profiles": []}


from .v41_api import install_routes
install_routes(app, enqueue, check_id, summary)
from .expansion_api import install as install_expansion
install_expansion(app, enqueue, summary)
from .response_api import install as install_response
install_response(app,enqueue,summary)

web = ROOT / "apps/web/dist"
if web.exists():
    app.mount("/", StaticFiles(directory=web, html=True), name="web")
