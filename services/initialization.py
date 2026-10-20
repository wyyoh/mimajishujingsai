import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNTIME = (
    Path.home()
    / ".local/share/grid-collaboration"
    / hashlib.sha256(str(ROOT).encode()).hexdigest()[:12]
)
RUNTIME = Path(os.environ.get("GRID_RUNTIME", str(DEFAULT_RUNTIME)))


def command(*args):
    values = [str(x) for x in args]
    password = None
    if values and values[0] == 'openssl':
        from .custody import pem_password, enabled, role_for, role_key
        output_option = '-keyout' if '-keyout' in values else '-out'
        if enabled(RUNTIME) and output_option in values and values[values.index(output_option)+1].endswith('.key'):
            output_path = Path(values[values.index(output_option)+1])
            if values[1] == 'genpkey' and role_for(output_path, RUNTIME) is not None:
                values.extend(('-aes-256-cbc', '-pass', 'stdin'))
                password = role_key(RUNTIME, role_for(output_path, RUNTIME)).hex()+'\n'
            elif values[1] == 'req' and '-newkey' in values and role_for(output_path, RUNTIME) is not None:
                values = [value for value in values if value != '-nodes']
                values.extend(('-passout', 'stdin'))
                password = role_key(RUNTIME, role_for(output_path, RUNTIME)).hex()+'\n'
        for option in ('-key', '-CAkey', '-keyfile', '-in'):
            if option in values:
                path = Path(values[values.index(option)+1])
                if path.is_file() and path.read_bytes().startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'):
                    password = pem_password(path).decode()+'\n'
                    break
        if password is not None and values[1] not in ('genpkey',) and '-passout' not in values:
            values.extend(('-passin', 'stdin'))
    p = subprocess.run(values, input=password, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f"{args[0]} failed ({p.returncode}): {p.stderr[-1000:]}")
    return p


def initialize_keys():
    marker = RUNTIME / "credentials.json"
    if marker.exists():
        return RUNTIME
    RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(RUNTIME, 0o700)
    public = RUNTIME / "public"
    public.mkdir(exist_ok=True)
    from .custody import enable, enabled
    if not enabled(RUNTIME):
        enable(RUNTIME)
    ta = RUNTIME / "ta"
    ta.mkdir(exist_ok=True, mode=0o700)
    command(
        "openssl",
        "req",
        "-new",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-keyout",
        ta / "ca.key",
        "-out",
        public / "ca.pem",
        "-days",
        "30",
        "-subj",
        "/CN=Grid Research Local Root",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    )
    for role in ("source", "gateway", "utility"):
        d = RUNTIME / role
        d.mkdir(exist_ok=True, mode=0o700)
        command(
            "openssl",
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-out",
            d / "tls.key",
        )
        command(
            "openssl",
            "req",
            "-new",
            "-key",
            d / "tls.key",
            "-out",
            d / "tls.csr",
            "-subj",
            f"/CN={role}.grid",
        )
        ext = d / "tls.ext"
        ext.write_text(
            f"subjectAltName=DNS:{role}.grid\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\n",
            encoding="ascii",
        )
        command(
            "openssl",
            "x509",
            "-req",
            "-in",
            d / "tls.csr",
            "-CA",
            public / "ca.pem",
            "-CAkey",
            ta / "ca.key",
            "-CAcreateserial",
            "-out",
            d / "tls.pem",
            "-days",
            "14",
            "-extfile",
            ext,
        )
        if role != "source":
            for alg, opts in (
                (
                    "ecdsa",
                    ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1"],
                ),
                ("mldsa", ["-algorithm", "ML-DSA-65"]),
            ):
                command("openssl", "genpkey", *opts, "-out", d / f"{alg}.key")
                command(
                    "openssl",
                    "pkey",
                    "-in",
                    d / f"{alg}.key",
                    "-pubout",
                    "-out",
                    public / f"{role}-{alg}-1.pem",
                )
    for p in RUNTIME.rglob("*.key"):
        os.chmod(p, 0o600)
    registry = {
        role: {
            alg: {
                "key_id": f"{role}-{alg}-1",
                "public_key": f"{role}-{alg}-1.pem",
                "epoch": 1,
            }
            for alg in ("ecdsa", "mldsa")
        }
        for role in ("utility", "gateway")
    }
    (public / "key_registry.json").write_text(
        json.dumps(registry, indent=2), encoding="utf-8"
    )
    marker.write_text(
        json.dumps(
            {
                "key_epoch": 1,
                "platform": "WSL Ubuntu",
                "private_material": "outside_repository",
                "warning": "role process isolation does not protect against the same OS user or host administrator",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return RUNTIME
