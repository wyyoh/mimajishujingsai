"""PFDAM V-A--G functional reproduction with explicit research limitations.

Real optimized-Paillier-format arithmetic and real BLS12-381 pairings.
This module does not claim that the paper's policy-hiding proof is valid.
"""

import hashlib
import hmac
import json
import math
import secrets
import time
from pathlib import Path

import gmpy2 as gmp

from .encoding import Rejected, canonical, decimal, digest, unb64
from .pairing import Element, G1, G2, GT, ORDER, pairing, hash_gt

CORE_VERSION = "P1-functional-typed-v1"
MAX_DEGREE = 15
MODULUS_BITS = 3072
SUBPRIME_BITS = 384


def random_scalar():
    return secrets.randbelow(ORDER - 1) + 1


def prime(bits):
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        p = int(gmp.next_prime(n))
        if p.bit_length() == bits:
            return p


def structured_prime(subprime, bits):
    cofactor_bits = bits - subprime.bit_length() - 1
    while True:
        cofactor = secrets.randbits(cofactor_bits) | (1 << (cofactor_bits - 1)) | 1
        n = 2 * subprime * cofactor + 1
        if n.bit_length() == bits and gmp.is_prime(n, 40):
            return n, cofactor


def setup():
    started = time.perf_counter_ns()
    while True:
        pp, qp = prime(SUBPRIME_BITS), prime(SUBPRIME_BITS)
        p, cp = structured_prime(pp, MODULUS_BITS // 2)
        q, cq = structured_prime(qp, MODULUS_BITS // 2)
        n = p * q
        if (
            n.bit_length() == MODULUS_BITS
            and p != q
            and math.gcd(p - 1, q - 1) == 2
            and math.gcd(pp * qp, cp * cq) == 1
        ):
            break
    alpha = 4 * pp * qp
    beta = cp * cq
    # Follow V-A's literal h=-y^(2 beta) mod N; check its actual order.
    order = 2 * pp * qp
    while True:
        y = secrets.randbelow(n - 3) + 2
        if math.gcd(y, n) != 1:
            continue
        h = (-int(gmp.powmod(y, 2 * beta, n))) % n
        if pow(h, order, n) == 1 and all(
            pow(h, order // r, n) != 1 for r in (2, pp, qp)
        ):
            break
    v, u = random_scalar(), random_scalar()
    s = [random_scalar() for _ in range(MAX_DEGREE + 1)]
    xag, xgw = random_scalar(), random_scalar()
    public = {
        "core_version": CORE_VERSION,
        "N": str(n),
        "h": str(h),
        "max_degree": MAX_DEGREE,
        "U": G1.scale(u).encode(),
        "V": GT.scale(v).encode(),
        "S": [G1.scale(x).encode() for x in s],
        "PKAg": GT.scale(v * xag).encode(),
        "pkgw": G2.scale(xgw).encode(),
        "pairing": "BLS12-381",
        "group_encoding": "mcl-v3.08-canonical-non-ETH",
        "modulus_bits": n.bit_length(),
        "subgroup_bits": order.bit_length(),
        "core_audit_status": "PENDING_REFERENCE_37_REVIEW",
        "policy_hiding": "DEMONSTRATED_LIMITATION",
        "hash_instantiation": "SHA-256-to-Fr; HMAC-SHA256-to-Fr; domain-separated real hash-to-G1 and GT pairing image",
    }
    public["param_id"] = digest(public)
    uc = {
        "alpha": str(alpha),
        "v": str(v),
        "u": str(u),
        "s": [str(x) for x in s],
        "param_id": public["param_id"],
    }
    gw = {"xag": str(xag), "xgw": str(xgw), "param_id": public["param_id"]}
    audit = {
        "p": str(p),
        "q": str(q),
        "p_prime": str(pp),
        "q_prime": str(qp),
        "alpha": str(alpha),
        "beta": str(beta),
        "actual_h_order": str(order),
        "paper_claimed_h_order": str(2 * alpha),
        "actual_order_divides_decryption_exponent": (2 * alpha) % order == 0,
        "setup_ns": time.perf_counter_ns() - started,
    }
    return public, uc, gw, audit


def scalar_hash(data):
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % ORDER


def mask(element):
    return scalar_hash(unb64(element.encode()))


def tag(context, slot, region, resource):
    return canonical(
        {
            "schema": "grid-tag-v1",
            "task_nonce": context["task_nonce"],
            "slot_id": slot,
            "metric_id": context["metric_id"],
            "region": region,
            "resource_class": resource,
        }
    )


def authorize(public, secret, tags):
    if len(tags) > public["max_degree"] or len(set(tags)) != len(tags):
        raise Rejected("POLICY_DIMENSION_INVALID")
    # f(X)=v+product(X-H(tag)); empty policy uses f(X)=v+1.
    coeff = [1]
    for item in tags:
        root = scalar_hash(item)
        next_coeff = [0] * (len(coeff) + 1)
        for i, a in enumerate(coeff):
            next_coeff[i] = (next_coeff[i] - root * a) % ORDER
            next_coeff[i + 1] = (next_coeff[i + 1] + a) % ORDER
        coeff = next_coeff
    coeff[0] = (coeff[0] + decimal(secret["v"])) % ORDER
    coeff += [0] * (public["max_degree"] + 1 - len(coeff))
    return [
        G2.scale(a * pow(decimal(s), -1, ORDER)).encode()
        for a, s in zip(coeff, secret["s"], strict=True)
    ]


def report(public, plaintext, label, timestamp):
    if (
        not isinstance(plaintext, int)
        or isinstance(plaintext, bool)
        or not 0 <= plaintext <= 10**9
    ):
        raise Rejected("MESSAGE_BOUND_INVALID")
    n = decimal(public["N"])
    n2 = n * n
    k, gamma = random_scalar(), random_scalar()
    blind = Element.decode("GT", public["PKAg"]).scale(k)
    # Fresh CSPRNG randomness for every new report; no reusable precompute cache.
    r = secrets.randbits(1024)
    ct = int(
        (
            (1 + (plaintext + mask(blind)) * n)
            * gmp.powmod(gmp.powmod(decimal(public["h"]), r, n), n, n2)
        )
        % n2
    )
    t = hash_gt(label).scale(gamma)
    c = blind.multiply(t)
    hi = scalar_hash(label)
    ds = [
        Element.decode("G1", x).scale(k * pow(hi, j, ORDER)).encode()
        for j, x in enumerate(public["S"])
    ]
    key = Element.decode("GT", public["V"]).scale(k)
    content = canonical({"Theta": t.encode(), "CT": str(ct), "T": timestamp})
    mac = (
        int.from_bytes(hmac.digest(unb64(key.encode()), content, "sha256"), "big")
        % ORDER
    )
    return {"CT": str(ct), "B": str(mac), "C": c.encode(), "D": ds, "T": timestamp}


def match_and_aggregate(public, secret, token, reports):
    n = decimal(public["N"])
    n2 = n * n
    if len(token) != public["max_degree"] + 1:
        raise Rejected("TOKEN_DIMENSION_INVALID")
    omega = [Element.decode("G2", x) for x in token]
    # Zero coefficient points are mathematically valid; skip only their identity pairing.
    active = [(j, w) for j, w in enumerate(omega) if not w.is_identity()]
    aggregate = 1
    accepted = []
    rejected = []
    seen = set()
    for envelope in reports:
        rid = envelope.get("report_id")
        if rid in seen:
            rejected.append({"report_id": rid, "code": "REPORT_DUPLICATE"})
            continue
        seen.add(rid)
        try:
            value = envelope["report"]
            if (
                set(value) != {"CT", "B", "C", "D", "T"}
                or len(value["D"]) != public["max_degree"] + 1
            ):
                raise Rejected("REPORT_DIMENSION_INVALID")
            if digest({k: v for k, v in envelope.items() if k != "report_id"}) != rid:
                raise Rejected("REPORT_DIGEST_MISMATCH")
            ct = decimal(value["CT"])
            if not 0 < ct < n2 or math.gcd(ct, n) != 1:
                raise Rejected("CIPHERTEXT_DOMAIN_INVALID")
            c = Element.decode("GT", value["C"])
            ds = [Element.decode("G1", x) for x in value["D"]]
            if ds[0].is_identity():
                raise Rejected("REPORT_EPHEMERAL_ZERO")
            psi = None
            for j, w in active:
                x = pairing(ds[j], w)
                psi = x if psi is None else psi.multiply(x)
            if psi is None:
                raise Rejected("TOKEN_INVALID")
            blind = psi.scale(decimal(secret["xag"]))
            theta = c.divide(blind)
            content = canonical(
                {"Theta": theta.encode(), "CT": value["CT"], "T": value["T"]}
            )
            mac = (
                int.from_bytes(
                    hmac.digest(unb64(psi.encode()), content, "sha256"), "big"
                )
                % ORDER
            )
            if not hmac.compare_digest(str(mac), value["B"]):
                raise Rejected("REPORT_JOINT_CHECK_FAILED")
            aggregate = (aggregate * ct * (1 - mask(blind) * n)) % n2
            accepted.append(rid)
        except (Rejected, KeyError, TypeError, ValueError) as exc:
            rejected.append(
                {
                    "report_id": rid,
                    "code": getattr(exc, "code", "REPORT_INVALID_ENCODING"),
                }
            )
    return aggregate, accepted, rejected


def native_sign(secret, aggregate, timestamp):
    data = canonical({"AggSum": str(aggregate), "T": timestamp})
    return (
        Element.hash_point("G1", "GRID-PFDAM-NATIVE-RECEIPT-V1", data)
        .scale(decimal(secret["xgw"]))
        .encode()
    )


def verify_recover(public, secret, aggregate, timestamp, signature, count):
    c = decimal(str(aggregate))
    n = decimal(public["N"])
    if not 0 < c < n * n or math.gcd(c, n) != 1:
        raise Rejected("CIPHERTEXT_DOMAIN_INVALID")
    point = Element.hash_point(
        "G1",
        "GRID-PFDAM-NATIVE-RECEIPT-V1",
        canonical({"AggSum": str(c), "T": timestamp}),
    )
    if pairing(point, Element.decode("G2", public["pkgw"])) != pairing(
        Element.decode("G1", signature), G2
    ):
        raise Rejected("NATIVE_SIGNATURE_INVALID")
    exponent = 2 * decimal(secret["alpha"])
    # Restrict to the paper's exact ordinary-division recovery domain.
    bound = count * 10**9
    if exponent * bound >= n:
        raise Rejected("RECOVERY_MESSAGE_BOUND_INVALID")
    x = int(gmp.powmod(c, exponent, n * n))
    if (x - 1) % (exponent * n):
        raise Rejected("RECOVERY_DIVISIBILITY_INVALID")
    result = (x - 1) // (exponent * n)
    if result > bound:
        raise Rejected("RECOVERY_RESULT_BOUND_INVALID")
    return result if count else None
