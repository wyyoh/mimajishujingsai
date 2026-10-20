"""Readiness checks do not replace protocol review or a human submission."""

from pathlib import Path

from .initialization import ROOT
from .storage import read, write
from .versioning import source_version


def check():
    issues = []
    current = source_version()
    path = ROOT / "artifacts/tests/acceptance_results.json"
    if not path.exists():
        issues.append("ACCEPTANCE_NOT_RUN")
    else:
        acceptance = read(path)
        counts = acceptance["counts"]
        if acceptance.get("exit_code") != 0:
            issues.append("TEST_SUITE_FAILED")
        recovery = acceptance.get("recovery_cases", [])
        if {r["case_id"] for r in recovery} != {f"R{i:02d}" for i in range(1, 7)} or any(r["status"] != "PASS" for r in recovery):
            issues.append("RECOVERY_ACCEPTANCE_INCOMPLETE")
        if counts.get("PASS") != 60 or any(
            counts.get(x, 0) for x in ("FAIL", "BLOCKED", "NOT_RUN")
        ):
            issues.append("ACCEPTANCE_INCOMPLETE")
        if (
            read(path).get("build", {}).get("core_source_digest")
            != current["core_source_digest"]
        ):
            issues.append("ACCEPTANCE_SOURCE_VERSION_MISMATCH")
    for name in ("ui_results.json", "cleanroom_result.json"):
        record_path = ROOT / "artifacts/tests" / name
        if not record_path.exists():
            issues.append("MISSING_" + name.upper())
        else:
            record = read(record_path)
            if record.get("exit_code") != 0:
                issues.append("FAILED_" + name.upper())
            if record.get("core_source_digest") != current["core_source_digest"]:
                issues.append("SOURCE_VERSION_MISMATCH_" + name.upper())
    benchmark = ROOT / "artifacts/benchmarks/summary.json"
    if not benchmark.exists():
        issues.append("BENCHMARK_NOT_RUN")
    else:
        b = read(benchmark)
        if b["status"] != "COMPLETED" or any(
            p["sample_count"] < 30 or p["failure_count"] for p in b["profiles"]
        ):
            issues.append("BENCHMARK_INCOMPLETE")
        if {p["profile"] for p in b["profiles"]} != {"S0", "SA", "SB", "SAB"}:
            issues.append("BENCHMARK_PROFILE_MISSING")
        plan = ROOT / "artifacts/benchmarks/plan.json"
        if (
            not plan.exists()
            or read(plan).get("core_source_digest") != current["core_source_digest"]
        ):
            issues.append("BENCHMARK_SOURCE_VERSION_MISMATCH")
    claims = read(ROOT / "docs/claims_registry.json")
    if claims["optimized_paillier_parameter_security"]["status"] == "PENDING":
        issues.append("CORE_PARAMETER_REVIEW_PENDING")
    if not (ROOT / "docs/REVIEW_DECISION.json").exists():
        issues.append("HUMAN_PROTOCOL_SCOPE_DECISION_PENDING")
    result = {
        "formal_release_ready": not issues,
        "engineering_checks_ready": not [
            i for i in issues if i != "CORE_PARAMETER_REVIEW_PENDING"
        ],
        "issues": issues,
        "scope": "local engineering review; no external submission performed",
    }
    write(ROOT / "artifacts/tests/release_check.json", result)
    return result
