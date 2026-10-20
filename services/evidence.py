import hashlib
import zipfile
from pathlib import Path

from .encoding import Rejected, loads, canonical, digest
from .initialization import ROOT, RUNTIME
from .orchestrator import RUNS
from .signatures import verify_object
from .storage import read

PUBLIC_FILES = (
    "recovery_evidence.json",
    "run_manifest.json",
    "receipts.json",
    "signature_evidence.json",
    "authorization_evidence.json",
    "connection_evidence.json",
    "performance_raw.json",
    "events.json",
    "role_isolation.json",
    "rejection_evidence.json",
    "governance.json",
    "snapshots.json",
    "audit_checkpoints.json",
    "accepted_manifests.json",
    "resource_evidence.json",
    "data_provenance.json",
    "result_statements.json",
    "trust_evidence.json",
)


def export_public(run_id):
    run = RUNS / run_id
    manifest = read(run / "run_manifest.json")
    if manifest.get('protocol_version') == 5:
        from .publication_evidence import export_v5
        return export_v5(run_id)
    if manifest["status"] == "RUNNING":
        raise Rejected("RUN_NOT_FINISHED")
    destination = ROOT / "artifacts/exports" / f"{run_id}.zip"
    destination.parent.mkdir(parents=True, exist_ok=True)
    entries = {
        name: (run / name).read_bytes()
        for name in PUBLIC_FILES
        if (run / name).exists()
    }
    entries["parameter_manifest.json"] = (
        RUNTIME / "public/parameters.json"
    ).read_bytes()
    if manifest.get('protocol_version') == 4 and manifest['results']:
        from .trust import registry, _root_public
        receipts = read(run / 'receipts.json')
        identifiers = {row['payload']['trust_registry_digest'] for row in receipts}
        snapshots, public_keys = {}, {}
        for identifier in identifiers:
            body = registry(RUNTIME, identifier)
            snapshots[identifier] = read(RUNTIME / 'public/trust-history' / f'{identifier}.json')
            public_keys.update({row['public_key']: (RUNTIME / 'public' / row['public_key']).read_text() for row in body['entries']})
        entries['trust_evidence.json'] = canonical({'schema': 'GRID_ARCHIVED_TRUST_EVIDENCE_V1', 'registries': snapshots,
            'public_keys': public_keys, 'root_public_keys': _root_public(RUNTIME), 'trust': 'Candidates only; require separately pinned root and current state'})
    entries["verification_scope.json"] = canonical(
        {
            "receipt_signatures": "independently verifiable with separately trusted role keys",
            "authorization": "digest and signature-verification metadata only; full token body is private",
            "plaintext_correspondence": "UC V4 result statement authenticates content when present; correctness still requires trusted UC and isolated oracle",
            "core_policy_hiding": "DEMONSTRATED_LIMITATION",
            "core_parameter_review": "PENDING_REFERENCE_37_REVIEW",
        }
    )
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in entries.items()}
    entries["export_manifest.json"] = canonical(
        {
            "schema": "GRID_PUBLIC_EXPORT_V1",
            "run_id": run_id,
            "files": hashes,
            "trust_keys": "not adopted from archive; use an independently trusted role registry",
        }
    )
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return destination


def verify_export(path, runtime=RUNTIME, expected_context=None, *, trusted_pin=None):
    """Verify receipt links and, for V4, UC statement origin and content integrity.

    An expected context must come from outside the archive. Checksums and a
    self-described run cannot establish which task the verifier intended.
    """
    try:
        if trusted_pin is not None:
            from .custody import public_trust
            with public_trust(runtime, trusted_pin):
                return _verify_export(path, runtime, expected_context)
        return _verify_export(path, runtime, expected_context)
    except Rejected:
        raise
    except (KeyError, TypeError, IndexError, zipfile.BadZipFile) as exc:
        raise Rejected("EXPORT_STRUCTURE_INVALID") from exc


def _verify_export(path, runtime, expected_context):
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if (
            len(infos) > 64
            or sum(x.file_size for x in infos) > 64 * 1024 * 1024
            or len({x.filename for x in infos}) != len(infos)
        ):
            raise Rejected("EXPORT_ARCHIVE_INVALID")
        if any(
            "/" in x.filename or "\\" in x.filename or x.filename.startswith(".")
            for x in infos
        ):
            raise Rejected("EXPORT_PATH_INVALID")
        manifest = loads(z.read("export_manifest.json"))
        if loads(z.read('run_manifest.json')).get('protocol_version') == 5:
            from .publication_evidence import verify_v5
            return verify_v5(z,runtime,expected_context)
        if not isinstance(manifest, dict) or manifest.get("schema") != "GRID_PUBLIC_EXPORT_V1":
            raise Rejected("EXPORT_SCHEMA_INVALID")
        allowed = {*PUBLIC_FILES, "parameter_manifest.json", "verification_scope.json"}
        names = set(z.namelist())
        files = manifest["files"]
        if (
            not isinstance(files, dict)
            or set(files) != names - {"export_manifest.json"}
            or not set(files) <= allowed
            or not {"run_manifest.json", "parameter_manifest.json", "verification_scope.json"} <= set(files)
        ):
            raise Rejected("EXPORT_FILE_SET_MISMATCH")
        for name, sha in manifest["files"].items():
            if hashlib.sha256(z.read(name)).hexdigest() != sha:
                raise Rejected("EXPORT_HASH_MISMATCH")
        run = loads(z.read("run_manifest.json"))
        if not isinstance(run, dict) or manifest["run_id"] != run["run_id"]:
            raise Rejected("EXPORT_RUN_CONTEXT_MISMATCH")
        parameters = loads(z.read("parameter_manifest.json"))
        if (
            not isinstance(parameters, dict)
            or parameters["param_id"] != run["param_id"]
            or digest({k: v for k, v in parameters.items() if k != "param_id"}) != parameters["param_id"]
        ):
            raise Rejected("EXPORT_PARAMETER_MISMATCH")
        slot_count = run["slot_count"]
        if type(slot_count) is not int or not 1 <= slot_count <= 4:
            raise Rejected("EXPORT_SLOT_COUNT_INVALID")
        slots = {f"slot-{i}" for i in range(slot_count)}
        if expected_context is not None:
            permitted = {"run_id", "task_id", "param_id", "security_profile", "slot_count", "algorithm_suite", "policy_digest", "asset_id", "function", "requester_id", "dataset_id", "dataset_digest", "scene_id", "data_source", "logical_source_process_count"}
            if (
                not isinstance(expected_context, dict)
                or not expected_context
                or not set(expected_context) <= permitted
                or any(canonical(run[k]) != canonical(v) for k, v in expected_context.items())
            ):
                raise Rejected("EXPORT_EXPECTED_CONTEXT_MISMATCH")
        results = run["results"]
        receipts = loads(z.read("receipts.json")) if "receipts.json" in names else []
        if not isinstance(results, list) or not isinstance(receipts, list) or len(results) != len(receipts):
            raise Rejected("EXPORT_RESULT_RECEIPT_SET_MISMATCH")
        by_slot = {}
        for result in results:
            slot = result["slot_id"]
            if slot not in slots or slot in by_slot:
                raise Rejected("EXPORT_RESULT_SLOT_INVALID")
            by_slot[slot] = result
        if run["status"] not in ("COMPLETED", "PARTIAL", "REJECTED", "FAILED", "CANCELLED"):
            raise Rejected("EXPORT_RUN_STATUS_INVALID")
        if run["status"] in ("COMPLETED", "PARTIAL") and set(by_slot) != slots:
            raise Rejected("EXPORT_COMPLETED_SLOTS_MISSING")
        checks = []
        v41_checks, versions, result_checks, key_states = [], set(), [], []
        statements = loads(z.read('result_statements.json')) if 'result_statements.json' in names else []
        if run.get('protocol_version') == 4 and (not isinstance(statements, list) or len(statements) != len(results)):
            raise Rejected('EXPORT_UC_RESULT_STATEMENTS_MISSING')
        v41_maps = None
        seen_slots, snapshots, authorization_digests = set(), set(), set()
        for envelope in receipts:
            kind = envelope["payload"]["object_type"]
            if kind not in ("GRID_AGG_RECEIPT_V1", "GRID_AGG_RECEIPT_V2", "GRID_AGG_RECEIPT_V3", "GRID_AGG_RECEIPT_V4"):
                raise Rejected("EXPORT_RECEIPT_OBJECT_INVALID")
            receipt, evidence = verify_object(
                envelope,
                kind,
                run["security_profile"],
                Path(runtime),
                usage='history',
            )
            if (
                receipt["run_id"] != run["run_id"]
                or receipt["task_id"] != run["task_id"]
                or receipt["param_id"] != run["param_id"]
            ):
                raise Rejected("EXPORT_RECEIPT_CONTEXT_MISMATCH")
            slot = receipt["slot_id"]
            if slot in seen_slots or slot not in by_slot or receipt["snapshot_id"] in snapshots:
                raise Rejected("EXPORT_RECEIPT_SLOT_INVALID")
            seen_slots.add(slot)
            snapshots.add(receipt["snapshot_id"])
            authorization_digests.add(receipt["authorization_digest"])
            result = by_slot[slot]
            if result["receipt_digest"] != digest(receipt) or canonical(result["counts"]) != canonical(receipt["counts"]):
                raise Rejected("EXPORT_RESULT_RECEIPT_MISMATCH")
            empty = receipt["counts"]["accepted"] == 0
            if (
                receipt["counts"]["accepted"] > receipt["counts"]["received"]
                or receipt["status"] != ("NO_VALID_DATA" if empty else "AGGREGATED")
                or result["status"] != ("NO_VALID_DATA" if empty else "PUBLISHED")
                or result["unit"] != "W"
                or (empty and result["value_W"] is not None)
            ):
                raise Rejected("EXPORT_RESULT_STATUS_MISMATCH")
            versions.add(receipt["schema_version"])
            if receipt["schema_version"] >= 2:
                from .v41_evidence import verify_links
                if receipt['schema_version'] >= 3:
                    from .expansion_evidence import verify_links
                from .governance import present_value
                required = {"governance.json", "snapshots.json", "audit_checkpoints.json", "accepted_manifests.json"}
                if not required <= names:
                    raise Rejected("EXPORT_V41_EVIDENCE_MISSING")
                if v41_maps is None:
                    policy = loads(z.read("governance.json"))
                    v41_maps = [loads(z.read(name)) for name in ("snapshots.json", "audit_checkpoints.json", "accepted_manifests.json")]
                    if any(not isinstance(value, dict) or set(value) != set(by_slot) for value in v41_maps):
                        raise Rejected("EXPORT_V41_SLOT_SET_MISMATCH")
                    if run.get("protocol_version") != receipt['schema_version'] or type(run.get("protocol_version")) is not int:
                        raise Rejected("EXPORT_V41_VERSION_MISMATCH")
                    for field in ("algorithm_suite", "asset_id", "function", "requester_id", "data_level", "classification_scope"):
                        if canonical(run[field]) != canonical(policy[field]):
                            raise Rejected("EXPORT_V41_POLICY_CONTEXT_MISMATCH")
                if run["policy_digest"] != receipt["policy_digest"]:
                    raise Rejected("EXPORT_V41_POLICY_DIGEST_MISMATCH")
                if receipt['schema_version'] >= 3:
                    if (run['dataset_id'] != policy['dataset_version'] or run['dataset_digest'] != policy['dataset_digest']
                            or run['data_source'] != policy['data_source'] or run['scene_id'] != policy['scene_id']
                            or run['node_count'] != policy['node_count'] or run['logical_source_process_count'] != len(policy['sources'])):
                        raise Rejected('EXPORT_V42_DATA_SOURCE_CONTEXT_MISMATCH')
                    if 'data_provenance.json' not in names:
                        raise Rejected('EXPORT_V42_DATA_PROVENANCE_MISSING')
                    provenance = loads(z.read('data_provenance.json'))
                    bindings = {'dataset_id': 'dataset_version', 'dataset_digest': 'dataset_digest',
                                'parent_dataset_digest': 'parent_dataset_digest', 'source': 'data_source',
                                'period_indices': 'period_indices', 'selected_slots': 'selected_slots'}
                    if any(canonical(provenance[key]) != canonical(policy[field]) for key, field in bindings.items()):
                        raise Rejected('EXPORT_V42_DATA_PROVENANCE_MISMATCH')
                v41_checks.append(verify_links(receipt, v41_maps[0][slot], v41_maps[1][slot], v41_maps[2][slot], policy))
                if any(result[field] != receipt[field] for field in ("snapshot_root", "policy_digest", "aggregation_digest", "audit_root")):
                    raise Rejected("EXPORT_V41_RESULT_LINK_MISMATCH")
                if canonical(result["published_value"]) != canonical(present_value(policy["function"], result["value_W"], receipt["counts"]["accepted"])):
                    raise Rejected("EXPORT_V41_PRESENTED_VALUE_MISMATCH")
                if receipt['schema_version'] == 4:
                    from .result_attestation import verify_statement
                    candidates = [row for row in statements if row['payload']['selected_slot']['slot_id'] == slot]
                    if len(candidates) != 1 or 'trust_evidence.json' not in names:
                        raise Rejected('EXPORT_UC_RESULT_STATEMENTS_MISSING')
                    result_checks.append(verify_statement(candidates[0], result, receipt, policy, Path(runtime)))
                    bundle = loads(z.read('trust_evidence.json'))
                    from .trust import registry, _root_public
                    from .custody import trust_pin
                    if digest(bundle['root_public_keys']) != trust_pin(Path(runtime))['registry_pin']:
                        raise Rejected('EXPORT_TRUST_ROOT_MISMATCH')
                    reference = receipt['trust_registry_digest']
                    trusted = registry(Path(runtime), reference)
                    if digest(bundle['registries'][reference]['payload']) != reference or canonical(bundle['registries'][reference]) != (Path(runtime) / 'public/trust-history' / f'{reference}.json').read_bytes():
                        raise Rejected('EXPORT_TRUST_EVIDENCE_MISMATCH')
                    if any(hashlib.sha256(bundle['public_keys'][row['public_key']].encode()).hexdigest() != row['public_sha256'] for row in trusted['entries']):
                        raise Rejected('EXPORT_TRUST_EVIDENCE_MISMATCH')
            key_states.extend(evidence.get('key_trust', []))
            checks.append(
                {
                    "slot_id": receipt["slot_id"],
                    "signature_valid": evidence["signature_valid"],
                    "signed_metadata_consistent": True,
                }
            )
        if seen_slots != set(by_slot) or len(authorization_digests) > 1 or len(versions) > 1:
            raise Rejected("EXPORT_RECEIPT_SET_MISMATCH")
        result_key_states = [state for result in result_checks for state in result['key_trust']]
        return {
            "run_id": run["run_id"],
            "file_hashes_valid": True,
            "receipt_checks": checks,
            "v41_checks": v41_checks,
            "receipt_authenticity_verified": bool(checks) and all(row['current_status'] != 'REVOKED' for row in key_states),
            "receipt_signatures_mathematically_valid": bool(checks),
            "key_trust": key_states,
            "uc_result_key_trust": result_key_states,
            "historical_revocation_time_status": 'UNDETERMINED' if any(row['current_status'] == 'REVOKED' for row in [*key_states, *result_key_states]) else 'NO_INDEPENDENT_SIGNING_TIME',
            "uc_result_checks": result_checks,
            "uc_result_origin_and_integrity_verified": bool(result_checks),
            "uc_result_keys_trusted_for_provided_state": bool(result_checks) and all(row['current_status'] != 'REVOKED' for row in result_key_states),
            "signed_result_metadata_consistent": bool(checks),
            "expected_context_checked": expected_context is not None,
            "data_provenance_binding_verified": bool(checks) and bool(versions & {3, 4}),
            "archive_status_authenticity": "NOT_SIGNED",
            "task_completeness": "NOT_INDEPENDENTLY_PROVEN_BY_ARCHIVE",
            "unsigned_metadata": ([] if result_checks else ["value_W", "published_value", "expected_target_count", "coverage_basis_points"]) + ["run_status", "performance", "connection_evidence", "data_provenance_reading_grouping_and_import_details"],
            "trusted_key_source": str(Path(runtime) / ('public/trust-registry.json' if 4 in versions else 'public/key_registry.json')),
            "authorization_independent_verification": "NOT_INCLUDED_IN_PUBLIC_EXPORT",
            "plaintext_correspondence": "REQUIRES_TRUSTED_UC_OR_PRIVATE_ORACLE",
        }
