import argparse
import json
import subprocess
import sys
from pathlib import Path

from .initialization import ROOT, RUNTIME


def main():
    parser = argparse.ArgumentParser(prog="scripts/project")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    init = sub.add_parser("init")
    init.add_argument("--profile", choices=["SAB"], default="SAB")
    sub.add_parser("probe")
    sub.add_parser("release-check")
    sub.add_parser("offline-test")
    sub.add_parser("ui-test")
    sub.add_parser("access")
    security = sub.add_parser('security')
    security.add_argument('action', choices=['status', 'request', 'approve', 'execute', 'audit', 'emergency-audit-reanchor'])
    security.add_argument('--operation', choices=['rotate-signing', 'revoke-key', 'renew-tls', 'disable-account', 'enable-account', 'approve-program', 'recover-registry', 'backup', 'restore', 'destroy-key'])
    security.add_argument('--target', default='')
    security.add_argument('--reason', default='研发管理操作')
    security.add_argument('--request-id')
    security.add_argument('--subject')
    serve = sub.add_parser("serve")
    serve.add_argument("--lab", action="store_true")
    exp = sub.add_parser("export")
    exp.add_argument("--run", required=True)
    exp.add_argument("--public", action="store_true", required=True)
    ver = sub.add_parser("verify-export")
    ver.add_argument("--path", required=True)
    ver.add_argument("--expect-run")
    ver.add_argument("--expect-task")
    ver.add_argument("--expect-param")
    ver.add_argument("--expect-profile", choices=["S0", "SA", "SB", "SAB"])
    ver.add_argument("--expect-slots", type=int)
    ver.add_argument('--trusted-pin', help='Separately trusted public pin JSON; never take authority from the evidence archive')
    ver.add_argument('--trust-runtime', help='Directory containing independently provisioned public registry, history and public keys')
    bench = sub.add_parser("bench")
    bench.add_argument("--profiles", default="S0,SA,SB,SAB")
    bench.add_argument("--repeats", type=int, default=30)
    tests = sub.add_parser("test")
    tests.add_argument("--suite", choices=["acceptance"], default="acceptance")
    for cmd in ("smoke", "demo"):
        p = sub.add_parser(cmd)
        p.add_argument("--profile", choices=["S0", "SA", "SB", "SAB"], default="SAB")
        p.add_argument("--nodes", type=int, default=12 if cmd == "smoke" else 120)
        p.add_argument("--slots", type=int, default=2 if cmd == "smoke" else 4)
        p.add_argument("--scenario", default="normal")
        p.add_argument("--region", choices=["A", "B"], default="A")
        p.add_argument("--resources", default="residential,charging")
        p.add_argument("--real", action="store_true")
        p.add_argument("--dataset", choices=["SYN-120-V3"], default="SYN-120-V3")
    args = parser.parse_args()
    if args.command == 'security':
        import getpass, os, uuid
        from . import management, trust
        from .custody import load_root
        if not (RUNTIME / 'public/trust-registry.json').exists():
            from .orchestrator import initialize
            initialize()
        from .sessions import initialize_access
        initialize_access()
        def password(name='GRID_ADMIN_PASSWORD', prompt='管理账户口令：'):
            return os.environ.get(name) or getpass.getpass(prompt)
        if args.action == 'status':
            body = trust.registry(RUNTIME)
            root = load_root(RUNTIME)
            result = {'registry_version': body['version'], 'keys': [{key: entry[key] for key in ('key_id', 'role', 'algorithm', 'epoch', 'status')} for entry in body['entries']],
                      'custody_backend': root['backend'], 'program_integrity': management.verify_program(), 'audit': management.verify_audit(),
                      'scope': 'Local development controls; not certification or production identity assurance'}
        elif args.action == 'request':
            if not args.operation:
                parser.error('--operation is required')
            target = args.target or (management.program_fingerprint() if args.operation == 'approve-program' else uuid.uuid4().hex if args.operation == 'backup' else '')
            result = management.request(args.operation, target, args.reason, args.subject or 'grid_key_manager', password())
        elif args.action == 'approve':
            if not args.request_id:
                parser.error('--request-id is required')
            result = management.approve(args.request_id, args.subject or 'grid_security_approver', password())
        elif args.action == 'execute':
            if not args.request_id:
                parser.error('--request-id is required')
            row = management._pending(management._requests(), args.request_id)
            backup_password = (os.environ.get('GRID_ADMIN_BACKUP_PASSPHRASE') or getpass.getpass('独立备份口令（至少16字符）：')) if row['body']['operation'] in ('backup', 'restore') else None
            result = management.execute(args.request_id, args.subject or 'grid_key_manager', password(), backup_passphrase=backup_password)
        elif args.action == 'audit':
            management.authenticate(args.subject or 'grid_auditor', password(), 'auditor')
            result = management.verify_audit()
        else:
            result = management.reanchor_audit('grid_key_manager', password(), 'grid_security_approver',
                password('GRID_ADMIN_APPROVER_PASSWORD', '独立审批账户口令：'))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.command == "access":
        from .sessions import ACCESS_PATH, initialize_access
        from .orchestrator import initialize
        initialize()
        initialize_access()
        print("本机原型访问口令文件（含私密口令，请勿分享或打包）：" + str(ACCESS_PATH))
        from .storage import read
        print(json.dumps(read(ACCESS_PATH), ensure_ascii=False, indent=2))
        return 0
    if args.command == "release-check":
        from .release import check

        result = check()
        print(json.dumps(result))
        return 0 if result["formal_release_ready"] else 1
    if args.command == "offline-test":
        return subprocess.call(
            [sys.executable, str(ROOT / "scripts/cleanroom.py")], cwd=ROOT
        )
    if args.command == "ui-test":
        return subprocess.call(
            [sys.executable, str(ROOT / "scripts/ui_test.py")], cwd=ROOT
        )
    if args.command == "bench":
        from .benchmarks import run

        print(json.dumps(run(args.profiles.split(","), args.repeats)))
        return 0
    if args.command == "test":
        return subprocess.call(
            [sys.executable, str(ROOT / "scripts/standards_regression.py"), "tests", "-q"], cwd=ROOT
        )
    if args.command == "serve":
        import os, uvicorn

        if args.lab:
            os.environ["GRID_LAB"] = "1"
        uvicorn.run("services.api:app", host="127.0.0.1", port=8580, access_log=False)
        return 0
    if args.command in ("export", "verify-export"):
        from .evidence import export_public, verify_export

        print(
            export_public(args.run)
            if args.command == "export"
            else json.dumps(verify_export(args.path, expected_context={
                key: value for key, value in {
                    "run_id": args.expect_run, "task_id": args.expect_task,
                    "param_id": args.expect_param, "security_profile": args.expect_profile,
                    "slot_count": args.expect_slots,
                }.items() if value is not None
            } or None, runtime=Path(args.trust_runtime) if args.trust_runtime else RUNTIME,
                trusted_pin=json.loads(Path(args.trusted_pin).read_text(encoding='utf-8')) if args.trusted_pin else None), ensure_ascii=False)
        )
        return 0
    if args.command in ("doctor", "probe"):
        return subprocess.call(
            [
                sys.executable,
                str(
                    ROOT
                    / "scripts"
                    / ("doctor.py" if args.command == "doctor" else "probe.py")
                ),
            ]
        )
    from .orchestrator import initialize, execute

    if args.command == "init":
        public = initialize()
        print(
            json.dumps(
                {
                    "param_id": public["param_id"],
                    "status": "INITIALIZED",
                    "core_audit_status": public["core_audit_status"],
                }
            )
        )
        return 0
    result = execute(
        nodes=args.nodes,
        slots=args.slots,
        profile=args.profile,
        region=args.region,
        resources=args.resources.split(",") if args.resources else [],
        scenario=args.scenario,
    )
    print(
        json.dumps(
            {
                "run_id": result["run_id"],
                "status": result["status"],
                "profile": result["security_profile"],
                "oracle_match": result.get("oracle_match"),
                "results": [
                    {
                        "slot": r["slot_id"],
                        "value_W": r["value_W"],
                        "accepted": r["counts"]["accepted"],
                        "received": r["counts"]["received"],
                    }
                    for r in result["results"]
                ],
                "elapsed_ms": result["elapsed_ns"] // 1000000,
                "errors": result.get("errors", []),
            },
            ensure_ascii=False,
        )
    )
    return (
        0
        if result["status"] in ("COMPLETED", "PARTIAL") and result.get("oracle_match")
        else 1
    )


if __name__ == "__main__":
    sys.exit(main())
