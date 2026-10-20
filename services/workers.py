"""One OS process per role. All inter-role business data uses native mTLS."""

import argparse
import copy
import json
import sqlite3
import sys
import time
import uuid
import resource
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import pfdam
from .encoding import Rejected, digest, canonical, decimal
from .native import TLS, Listener, utc, sandbox
from .schemas import PublicTaskContext, PublicTaskContextV2, ReportEnvelope
from .signatures import (
    sign_object,
    verify_object,
    check_authorization,
    validate,
    time_value,
)
from .storage import read, write, event


def request(kind, run_id, **data):
    return {"type": kind, "request_id": uuid.uuid4().hex, "run_id": run_id, **data}


class Worker:
    def __init__(self, args):
        self.args = args
        self.runtime = Path(args.runtime)
        self.job = Path(args.job)
        self.role = args.role
        self.private = self.job / self.role
        self.private.mkdir(exist_ok=True)
        from .custody import activate_worker
        activate_worker(self.runtime, self.role)
        self.public = read(self.runtime / "public/parameters.json")
        self.group = "X25519MLKEM768" if args.profile in ("SB", "SAB") else "X25519"
        self.v41 = getattr(args, "suite", "LEGACY") != "LEGACY"
        self.sm4 = False
        self.auth_kind, self.receipt_kind = "GRID_TASK_AUTH_V1", "GRID_AGG_RECEIPT_V1"
        self.context_model = PublicTaskContext
        if self.v41:
            from .agility import provider
            selected = provider(args.suite)
            if selected.profile != args.profile:
                raise Rejected("POLICY_CRYPTO_PROFILE_MISMATCH")
            self.group, self.sm4 = selected.group, selected.sm4_channel
            self.auth_kind, self.receipt_kind = "GRID_TASK_AUTH_V2", "GRID_AGG_RECEIPT_V2"
            self.context_model = PublicTaskContextV2
        self.events = self.job / "events" / f"{self.role}.jsonl"
        self.perf = []
        self.connections = []
        (self.job / "events").mkdir(exist_ok=True)
        abi = sandbox(self.runtime, self.job, self.role)
        checks = []
        targets = [self.runtime / "ta/ca.key"]
        for other in ("source", "gateway", "utility"):
            if other == self.role:
                continue
            targets.append(self.runtime / other / "tls.key")
            if other != "source":
                targets.extend(
                    [
                        self.runtime / other / "pfdam.json",
                        self.runtime / other / "mldsa.key",
                    ]
                )
        if self.role != "source":
            targets.append(self.job / "source/dataset.json")
        for target in targets:
            denied = False
            try:
                target.read_bytes()
            except PermissionError:
                denied = True
            if not denied:
                raise Rejected("ROLE_FILE_ISOLATION_FAILED")
            checks.append(
                {
                    "resource": f"{target.parent.name}/{target.name}",
                    "read_denied": denied,
                }
            )
        write(
            self.private / "isolation.json",
            {
                "mechanism": "Linux Landlock filesystem allowlist + non-dumpable process",
                "abi": abi,
                "checks": checks,
            },
            True,
        )

    def emit(self, stage, **fields):
        event(self.events, self.args.run_id, self.role, stage, **fields)

    def timed(self, name, start, slot=None):
        self.perf.append(
            {
                "operation": name,
                "elapsed_ns": time.perf_counter_ns() - start,
                "slot_id": slot,
                "role": self.role,
            }
        )

    def save(self):
        write(self.private / "timings.json", self.perf, True)
        write(self.private / "connections.json", self.connections, True)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        write(self.private / "resources.json", {"role": self.role, "cpu_user_ns": round(usage.ru_utime * 1_000_000_000),
              "cpu_system_ns": round(usage.ru_stime * 1_000_000_000), "peak_rss_KiB": usage.ru_maxrss,
              "scope": "Whole role process, including Python/native import and startup; RSS includes shared pages"}, True)

    def utility(self):
        secret = read(self.runtime / "utility/pfdam.json")
        config = read(self.private / "config.json")
        context = validate(self.context_model, read(self.private / "context.json"))
        start = time.perf_counter_ns()
        tokens = {
            s["slot_id"]: pfdam.authorize(
                self.public,
                secret,
                [
                    pfdam.tag(context, s["slot_id"], config["region"], r)
                    for r in config["resources"]
                ],
            )
            for s in context["slots"]
        }
        self.timed("authorize_tokens", start)
        now = datetime.now(timezone.utc)
        fmt = lambda x: x.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        payload = {
            "object_type": "GRID_TASK_AUTH_V1",
            "schema_version": 1,
            "task_id": context["task_id"],
            "run_id": context["run_id"],
            "issuer_role": "utility",
            "target_gw": "gateway",
            "slots": context["slots"],
            "issued_at": fmt(now),
            "not_before": fmt(now - timedelta(seconds=1)),
            "expires_at": fmt(now + timedelta(minutes=15)),
            "metric_id": context["metric_id"],
            "param_id": self.public["param_id"],
            "policy_ref": uuid.uuid4().hex,
            "token_bundle": tokens,
            "security_profile": self.args.profile,
            "key_epoch": 1,
        }
        if self.v41:
            payload.update(object_type=self.auth_kind, schema_version=2, governance=context["governance"],
                           policy_digest=context["policy_digest"], task_nonce=context["task_nonce"],
                           expires_at=context["governance"]["expires_at"])
        auth, perf = sign_object(payload, self.runtime)
        self.perf.extend(perf)
        write(self.private / "authorization.json", auth, True)
        sent_auth = copy.deepcopy(auth)
        if self.args.fault == "invalid_authorization":
            sent_auth["payload"]["target_gw"] = "other-gateway"
        if self.args.fault == "policy_tamper" and self.v41:
            sent_auth["payload"]["governance"]["region"] = "B" if config["region"] == "A" else "A"
        if self.args.fault == "expired_authorization":
            payload["expires_at"] = fmt(now - timedelta(seconds=1))
            sent_auth, perf = sign_object(payload, self.runtime)
            self.perf.extend(perf)
        actual_group = "X25519" if self.args.fault == "incompatible_tls" else self.group
        listener = Listener(
            self.args.l2, "utility", "gateway", actual_group, self.runtime, "L2", self.sm4
        )
        self.emit("AUTH_READY")
        write(self.private / "ready.json", {"ready": True, "port": self.args.l2})
        db = sqlite3.connect(self.private / "state.sqlite")
        db.execute(
            "CREATE TABLE IF NOT EXISTS results (run_id TEXT, slot_id TEXT, receipt_digest TEXT, value TEXT, PRIMARY KEY(run_id,slot_id))"
        )
        results = []
        signed_receipts = []
        signature_evidence = []
        v41_published = {"snapshots": {}, "audit_checkpoints": {}, "accepted_manifests": {}, "governance": context["governance"]} if self.v41 else {}
        try:
            with listener.accept() as conn:
                self.connections.append(conn.evidence)
                while True:
                    msg = conn.receive()
                    if msg.get("run_id") != self.args.run_id:
                        raise Rejected("REQUEST_RUN_MISMATCH")
                    if msg.get("type") == "pull_authorization":
                        conn.send(
                            {
                                "request_id": msg["request_id"],
                                "authorization": sent_auth,
                                "context": context,
                            }
                        )
                    elif msg.get("type") == "submit_receipt":
                        envelope = msg["receipt"]
                        evidence = None
                        try:
                            receipt, evidence = verify_object(
                                envelope,
                                self.receipt_kind,
                                self.args.profile,
                                self.runtime,
                            )
                            self.perf.extend(evidence["timings"])
                            if self.v41:
                                from .v41_evidence import verify_links
                                evidence["v41_links"] = verify_links(receipt, msg["snapshot"], msg["audit"], msg["accepted_ids"], context["governance"])
                            for field in ("task_id", "run_id", "param_id"):
                                if receipt[field] != context[field]:
                                    raise Rejected("RECEIPT_CONTEXT_MISMATCH")
                            if receipt["authorization_digest"] != digest(
                                auth["payload"]
                            ):
                                raise Rejected("RECEIPT_AUTHORIZATION_MISMATCH")
                            slot = receipt["slot_id"]
                            if slot not in tokens:
                                raise Rejected("RECEIPT_SLOT_MISMATCH")
                            check_authorization(
                                auth["payload"], context, self.args.profile
                            )
                            counts = receipt["counts"]
                            if (
                                counts["accepted"] > counts["received"]
                                or counts["received"] > config["node_count"] + 1
                            ):
                                raise Rejected("RECEIPT_COUNTS_INVALID")
                            old = db.execute(
                                "SELECT receipt_digest,value FROM results WHERE run_id=? AND slot_id=?",
                                (self.args.run_id, slot),
                            ).fetchone()
                            receipt_digest = digest(receipt)
                            if old:
                                if old[0] != receipt_digest:
                                    raise Rejected("RECEIPT_SNAPSHOT_CONFLICT")
                                conn.send(
                                    {
                                        "request_id": msg["request_id"],
                                        "accepted": True,
                                        "idempotent": True,
                                    }
                                )
                                continue
                            start = time.perf_counter_ns()
                            value = pfdam.verify_recover(
                                self.public,
                                secret,
                                receipt["aggregate_ciphertext"],
                                receipt["native_timestamp"],
                                receipt["native_signature"],
                                counts["accepted"],
                            )
                            self.timed("native_verify_recover", start, slot)
                            db.execute(
                                "INSERT INTO results VALUES(?,?,?,?)",
                                (
                                    self.args.run_id,
                                    slot,
                                    receipt_digest,
                                    None,  # Deduplication needs the receipt hash, not a second plaintext result.
                                ),
                            )
                            db.commit()
                            expected_count = config["expected_target_count"]
                            evidence.update(
                                context_valid=True,
                                native_verification_valid=True,
                                slot_id=slot,
                            )
                            result = {
                                "slot_id": slot,
                                "value_W": value,
                                "unit": "W",
                                "counts": counts,
                                "expected_target_count": expected_count,
                                "coverage_basis_points": counts["accepted"]
                                * 10000
                                // expected_count
                                if expected_count
                                else None,
                                "status": "NO_VALID_DATA"
                                if not counts["accepted"]
                                else "PUBLISHED",
                                "receipt_digest": receipt_digest,
                            }
                            if self.v41:
                                from .governance import present_value
                                result["published_value"] = present_value(context["governance"]["function"], value, counts["accepted"])
                                result.update(snapshot_root=receipt["snapshot_root"], policy_digest=receipt["policy_digest"],
                                              aggregation_digest=receipt["aggregation_digest"], audit_root=receipt["audit_root"])
                            results.append(result)
                            if self.v41:
                                v41_published["snapshots"][slot] = msg["snapshot"]
                                v41_published["audit_checkpoints"][slot] = msg["audit"]
                                v41_published["accepted_manifests"][slot] = msg["accepted_ids"]
                            signed_receipts.append(envelope)
                            signature_evidence.append(evidence)
                            self.emit(
                                "PUBLISHED",
                                slot_id=slot,
                                accepted_count=counts["accepted"],
                            )
                            write(
                                self.private / "published.json",
                                {
                                    "run_id": self.args.run_id,
                                    "results": results,
                                    "receipts": signed_receipts,
                                    "signature_evidence": signature_evidence,
                                    **v41_published,
                                },
                            )
                            conn.send(
                                {
                                    "request_id": msg["request_id"],
                                    "accepted": True,
                                    "idempotent": False,
                                }
                            )
                        except Rejected as exc:
                            self.emit(
                                "REJECTED",
                                code=exc.code,
                                signature_valid=(
                                    evidence or getattr(exc, "evidence", {})
                                ).get("signature_valid"),
                            )
                            write(
                                self.private / "rejection.json",
                                {
                                    "code": exc.code,
                                    "signature_evidence": evidence
                                    or getattr(exc, "evidence", None),
                                },
                            )
                            conn.send(
                                {
                                    "request_id": msg["request_id"],
                                    "accepted": False,
                                    "code": exc.code,
                                }
                            )
                            raise
                    elif msg.get("type") == "finish":
                        conn.send({"request_id": msg["request_id"], "finished": True})
                        break
                    else:
                        raise Rejected("REQUEST_TYPE_INVALID")
        finally:
            listener.close()
            db.close()

    def gateway(self):
        secret = read(self.runtime / "gateway/pfdam.json")
        auth_evidence = None
        with TLS.connect(
            self.args.l2, "gateway", "utility", self.group, self.runtime, "L2", self.sm4
        ) as l2:
            self.connections.append(l2.evidence)
            l2.send(request("pull_authorization", self.args.run_id))
            response = l2.receive()
            context = validate(self.context_model, response["context"])
            try:
                auth, auth_evidence = verify_object(
                    response["authorization"],
                    self.auth_kind,
                    self.args.profile,
                    self.runtime,
                )
                self.perf.extend(auth_evidence["timings"])
                check_authorization(auth, context, self.args.profile)
                if self.v41 and context["governance"]["algorithm_suite"] != self.args.suite:
                    raise Rejected("AUTH_CRYPTO_SUITE_MISMATCH")
                auth_evidence["context_valid"] = True
            except Rejected as exc:
                write(
                    self.private / "rejection.json",
                    {
                        "code": exc.code,
                        "signature_evidence": auth_evidence
                        or getattr(exc, "evidence", None),
                    },
                    True,
                )
                raise
            write(self.private / "authorization_evidence.json", auth_evidence, True)
            self.emit("COLLECTING")
            listener = Listener(
                self.args.l1, "gateway", "source", self.group, self.runtime, "L1", self.sm4
            )
            write(self.private / "ready.json", {"ready": True, "port": self.args.l1})
            accepted_by_slot = {}
            processed = {}
            snapshots, checkpoints = {}, {}
            try:
                with listener.accept() as l1:
                    self.connections.append(l1.evidence)
                    while True:
                        msg = l1.receive()
                        if msg.get("run_id") != self.args.run_id:
                            raise Rejected("REQUEST_RUN_MISMATCH")
                        if msg.get("type") == "pull_context":
                            l1.send(
                                {"request_id": msg["request_id"], "context": context}
                            )
                        elif msg.get("type") == "report_batch":
                            slot = msg.get("slot_id")
                            if slot not in auth["token_bundle"]:
                                raise Rejected("REPORT_SLOT_MISMATCH")
                            if slot in processed:
                                if processed[slot] != digest(msg["reports"]):
                                    raise Rejected("REPORT_SNAPSHOT_SEALED")
                                l1.send(
                                    {
                                        "request_id": msg["request_id"],
                                        "received": True,
                                        "idempotent": True,
                                    }
                                )
                                continue
                            validated = []
                            if len(msg["reports"]) > 10000:
                                raise Rejected("REPORT_BATCH_TOO_LARGE")
                            for item in msg["reports"]:
                                item = validate(ReportEnvelope, item)
                                if (
                                    any(
                                        item[f] != context[f]
                                        for f in ("task_id", "run_id", "param_id")
                                    )
                                    or item["slot_id"] != slot
                                ):
                                    raise Rejected("REPORT_CONTEXT_MISMATCH")
                                when = time_value(item["report"]["T"])
                                if (
                                    abs(
                                        (
                                            datetime.now(timezone.utc) - when
                                        ).total_seconds()
                                    )
                                    > 600
                                ):
                                    raise Rejected("REPORT_TIMESTAMP_INVALID")
                                validated.append(item)
                            self.emit(
                                "SEALED", slot_id=slot, received_count=len(validated)
                            )
                            current_snapshot = None
                            if self.v41:
                                from .merkle import snapshot
                                current_snapshot = snapshot(validated, context["governance"]["dataset_version"], slot)
                                if (msg.get("source_snapshot_root") != current_snapshot["merkle_root"]
                                        or type(msg.get("source_snapshot_count")) is not int
                                        or msg["source_snapshot_count"] != len(validated)):
                                    raise Rejected("SOURCE_SNAPSHOT_MISMATCH")
                            start = time.perf_counter_ns()
                            agg, accepted, rejected = pfdam.match_and_aggregate(
                                self.public,
                                secret,
                                auth["token_bundle"][slot],
                                validated,
                            )
                            self.timed("match_and_aggregate", start, slot)
                            self.emit(
                                "AGGREGATED", slot_id=slot, accepted_count=len(accepted)
                            )
                            stamp = utc()
                            start = time.perf_counter_ns()
                            signature = pfdam.native_sign(secret, agg, stamp)
                            self.timed("native_sign", start, slot)
                            codes = [x["code"] for x in rejected]
                            counts = {
                                "received": len(validated),
                                "accepted": len(accepted),
                                "joint_check_failed": codes.count(
                                    "REPORT_JOINT_CHECK_FAILED"
                                ),
                                "invalid": sum(
                                    c
                                    not in (
                                        "REPORT_JOINT_CHECK_FAILED",
                                        "REPORT_DUPLICATE",
                                    )
                                    for c in codes
                                ),
                                "duplicate": codes.count("REPORT_DUPLICATE"),
                                "late": 0,
                            }
                            payload = {
                                "object_type": "GRID_AGG_RECEIPT_V1",
                                "schema_version": 1,
                                "task_id": context["task_id"],
                                "run_id": self.args.run_id,
                                "authorization_digest": digest(auth),
                                "snapshot_id": uuid.uuid4().hex,
                                "slot_id": slot,
                                "param_id": self.public["param_id"],
                                "aggregate_ciphertext": str(agg),
                                "native_signature": signature,
                                "native_timestamp": stamp,
                                "counts": counts,
                                "status": "AGGREGATED" if accepted else "NO_VALID_DATA",
                                "issued_at": stamp,
                                "input_digest": digest(
                                    sorted(x["report_id"] for x in validated)
                                ),
                                "key_epoch": 1,
                                "security_profile": self.args.profile,
                            }
                            audit = None
                            if self.v41:
                                from .audit import checkpoint
                                from .governance import aggregation_digest
                                from .merkle import accepted_digest
                                audit = checkpoint(context, slot, current_snapshot, len(accepted), stamp)
                                payload.update(object_type=self.receipt_kind, schema_version=2, policy_digest=context["policy_digest"],
                                               algorithm_suite=self.args.suite, dataset_version=context["governance"]["dataset_version"],
                                               snapshot_root=current_snapshot["merkle_root"], snapshot_count=len(validated), snapshot_hash="SM3",
                                               accepted_set_digest=accepted_digest(accepted), audit_root=audit["root"])
                                payload["aggregation_digest"] = aggregation_digest(payload)
                            envelope, perf = sign_object(payload, self.runtime)
                            self.perf.extend(perf)
                            if self.args.fault == "invalid_receipt":
                                envelope["payload"]["counts"]["accepted"] += 1
                            extra = {}
                            if self.v41:
                                extra = {"snapshot": current_snapshot, "audit": audit, "accepted_ids": accepted}
                                if self.args.fault == "audit_tamper":
                                    extra["audit"] = copy.deepcopy(audit)
                                    extra["audit"]["records"][0]["result"] = "CHANGED"
                                if self.args.fault == "result_digest_tamper":
                                    envelope["payload"]["aggregation_digest"] = "0" * 96
                            l2.send(
                                request(
                                    "submit_receipt", self.args.run_id, receipt=envelope, **extra
                                )
                            )
                            ack = l2.receive()
                            if not ack.get("accepted"):
                                raise Rejected(ack.get("code", "RECEIPT_REJECTED"))
                            accepted_by_slot[slot] = accepted
                            if self.v41:
                                snapshots[slot], checkpoints[slot] = current_snapshot, audit
                                write(self.private / "snapshots.json", snapshots, True)
                                write(self.private / "audit_checkpoints.json", checkpoints, True)
                                write(self.private / "accepted_manifests.json", accepted_by_slot, True)
                            processed[slot] = digest(msg["reports"])
                            write(
                                self.private / "accepted.json", accepted_by_slot, True
                            )
                            write(
                                self.private / f"rejections-{slot}.json", rejected, True
                            )
                            l1.send(
                                {
                                    "request_id": msg["request_id"],
                                    "received": True,
                                    "idempotent": False,
                                }
                            )
                        elif msg.get("type") == "finish":
                            l1.send({"request_id": msg["request_id"], "finished": True})
                            break
                        else:
                            raise Rejected("REQUEST_TYPE_INVALID")
                l2.send(request("finish", self.args.run_id))
                l2.receive()
            finally:
                listener.close()

    def source(self):
        dataset = read(self.private / "dataset.json")
        injection = read(self.private / "injection.json")
        with TLS.connect(
            self.args.l1, "source", "gateway", self.group, self.runtime, "L1", self.sm4
        ) as l1:
            self.connections.append(l1.evidence)
            l1.send(request("pull_context", self.args.run_id))
            response = l1.receive()
            context = validate(self.context_model, response["context"])
            if self.v41:
                from .governance import check_policy
                check_policy(context["governance"], context["policy_digest"], self.args.profile)
                if context["governance"]["algorithm_suite"] != self.args.suite or context["governance"]["dataset_version"] != dataset["dataset_id"]:
                    raise Rejected("SOURCE_POLICY_DATASET_MISMATCH")
            mappings = {}
            for i, slot in enumerate(context["slots"]):
                start = time.perf_counter_ns()
                reports = []
                mapping = {}
                omitted = set(injection["omitted"].get(slot["slot_id"], []))
                modified = set(injection["modified"].get(slot["slot_id"], []))
                for node in dataset["nodes"]:
                    if node["node_id"] in omitted:
                        continue
                    label = pfdam.tag(
                        context, slot["slot_id"], node["region"], node["resource_class"]
                    )
                    value = pfdam.report(self.public, node["values_W"][i], label, utc())
                    if node["node_id"] in modified:
                        # Valid ciphertext-domain modification with original authentication.
                        n = decimal(self.public["N"])
                        value["CT"] = str(decimal(value["CT"]) * (1 + n) % (n * n))
                    envelope = {
                        "task_id": context["task_id"],
                        "run_id": self.args.run_id,
                        "slot_id": slot["slot_id"],
                        "param_id": self.public["param_id"],
                        "report": value,
                    }
                    envelope["report_id"] = digest(envelope)
                    reports.append(envelope)
                    mapping[envelope["report_id"]] = node["node_id"]
                if self.args.fault == "duplicate_report" and reports:
                    reports.append(copy.deepcopy(reports[0]))
                self.timed("generate_reports", start, slot["slot_id"])
                self.emit(
                    "REPORTS_READY", slot_id=slot["slot_id"], report_count=len(reports)
                )
                mappings[slot["slot_id"]] = mapping
                write(self.private / "oracle_mapping.json", mappings, True)
                extra = {}
                if self.v41:
                    from .merkle import snapshot
                    sealed = snapshot(reports, context["governance"]["dataset_version"], slot["slot_id"])
                    extra = {"source_snapshot_root": sealed["merkle_root"], "source_snapshot_count": len(reports)}
                    if self.args.fault == "snapshot_tamper" and reports:
                        reports[0]["report"]["CT"] = str(decimal(reports[0]["report"]["CT"]) + 1)
                l1.send(
                    request(
                        "report_batch",
                        self.args.run_id,
                        slot_id=slot["slot_id"],
                        reports=reports,
                        **extra,
                    )
                )
                ack = l1.receive()
                if not ack.get("received"):
                    raise Rejected("REPORT_BATCH_REJECTED")
            l1.send(request("finish", self.args.run_id))
            l1.receive()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", default="LEGACY")
    for name in ("role", "runtime", "job", "run-id", "profile", "fault"):
        parser.add_argument("--" + name, required=True)
    for name in ("l1", "l2"):
        parser.add_argument("--" + name, required=True, type=int)
    args = parser.parse_args()
    w = Worker(args)
    try:
        getattr(w, args.role)()
        w.emit("COMPLETED")
        return 0
    except Exception as exc:
        code = getattr(exc, "code", "CORE_OPERATION_FAILED")
        w.emit("FAILED", code=code)
        write(
            w.private / "error.json",
            {"code": code, "message": str(exc), "role": args.role},
            True,
        )
        print(f"{args.role}: {code}: {exc}", file=sys.stderr)
        return 1
    finally:
        w.save()


if __name__ == "__main__":
    sys.exit(main())
