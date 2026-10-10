"""Public mathematical problem in; verified answer and provenance out.

This module deliberately has no capture, TLS, HTTP, UI or eager Qiskit imports.
The demonstration substitutes only recovery, by looking up a known *test* key.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
from pathlib import Path
import time

from qsploit.models import (ExecutionOptions, Progress, QSploitError, Recovery, Report,
                            RSAFactors, RSAProblem, FFDLogProblem, FFDLogSecret,
                            ECDLogProblem, ECDLogSecret, X25519Secret,
                            PublicProblem, RecoveredSecret)
from qsploit.groups import validate_ffdhe2048

FACTOR_FILE = Path(__file__).resolve().parent.parent / "demo" / "factors.json"
DLOG_FILE = Path(__file__).resolve().parent.parent / "demo" / "dlog.json"
EC_DLOG_FILE = Path(__file__).resolve().parent.parent / "demo" / "ec_dlog.json"


@dataclass(frozen=True)
class DemoTiming:
    seconds: float
    kind: str = "illustrative_delay"
    assumptions: str = "Configured presentation delay; not a quantum runtime or resource estimate."


def validate_problem(problem: PublicProblem) -> None:
    if isinstance(problem, RSAProblem) and problem.kind == "rsa_factor":
        if type(problem.n) is not int or problem.n <= 1 or problem.n.bit_length() > 16384:
            raise QSploitError("INVALID_MODULUS", "RSA modulus must be an integer greater than one, at most 16384 bits.")
    elif isinstance(problem, FFDLogProblem) and problem.kind == "ff_dlog":
        validate_ffdhe2048(problem.p, problem.g, problem.order, problem.y)
    elif isinstance(problem, ECDLogProblem) and problem.kind == "ec_dlog":
        from qsploit.groups import validate_p256_point, validate_x25519_point
        if problem.curve == "secp256r1":
            validate_p256_point(problem.public_point)
        elif problem.curve == "x25519":
            validate_x25519_point(problem.public_point)
        else:
            raise QSploitError("UNSUPPORTED_GROUP", "Elliptic-curve recovery supports secp256r1 and X25519 only.")
    else:
        raise QSploitError("UNSUPPORTED_PROBLEM", "The mathematical problem type is not supported.")


def validate_options(options: ExecutionOptions) -> None:
    if options.backend not in ("fixture", "aer", "ionq_simulator", "ionq_qpu"):
        raise QSploitError("INVALID_BACKEND", "Unknown recovery backend.")
    for name, low, high in (("shots", 1, 100000), ("max_attempts", 1, 16),
                            ("timeout_seconds", 1, 7200), ("max_qubits", 1, 32),
                            ("max_compiled_ops", 1, 1000000)):
        value = getattr(options, name)
        if type(value) is not int or not low <= value <= high:
            raise QSploitError("INVALID_OPTIONS", f"{name} must be an integer between {low} and {high}.")
    if isinstance(options.demo_delay_seconds, bool) or not isinstance(options.demo_delay_seconds, (int, float)) or not math.isfinite(options.demo_delay_seconds) or not 0 <= options.demo_delay_seconds <= 3600:
        raise QSploitError("INVALID_OPTIONS", "demo_delay_seconds must be finite and between zero and 3600.")


def timing_for(problem: PublicProblem, options: ExecutionOptions) -> DemoTiming:
    """Separate timing seam: future justified resource models can consume problem.

    No credible cryptographic-scale resource model is supplied, so qubit capacity
    is never converted to a purported runtime. Real runners do not call this.
    """
    validate_problem(problem)
    validate_options(options)
    return DemoTiming(float(options.demo_delay_seconds))


def verify_factor_pair(n: int, factors: RSAFactors) -> None:
    """Prove a nontrivial factor pair, not primality or a valid RSA private key."""
    if not isinstance(factors, RSAFactors) or type(factors.p) is not int or type(factors.q) is not int:
        raise QSploitError("INVALID_FACTOR_PAIR", "Recovery did not return an integer factor pair.")
    if not 1 < factors.p < n or not 1 < factors.q < n or factors.p * factors.q != n:
        raise QSploitError("INVALID_FACTOR_PAIR", "Returned factors do not multiply to the public modulus.")


def known_factors(problem: RSAProblem) -> RSAFactors:
    validate_problem(problem)
    if not isinstance(problem, RSAProblem):
        raise QSploitError("UNSUPPORTED_PROBLEM", "This problem does not request an RSA factor pair.")
    try:
        entries = json.loads(FACTOR_FILE.read_text(encoding="utf-8"))
        item = entries.get(format(problem.n, "x"))
        if item is None:
            raise QSploitError("FIXTURE_NOT_FOUND", "No known test factors match this public modulus. Actual recovery requires a suitable quantum backend.")
        p, q = int(item["p"], 16), int(item["q"], 16)
    except QSploitError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise QSploitError("FIXTURE_INVALID", "The bundled demonstration factor fixture is unavailable or malformed.") from None
    factors = RSAFactors(min(p, q), max(p, q))
    verify_factor_pair(problem.n, factors)
    return factors


def has_known_factors(problem: RSAProblem) -> bool:
    try:
        known_factors(problem)
        return True
    except QSploitError:
        return False


def verify_secret(problem: PublicProblem, secret: RecoveredSecret) -> None:
    """Verify the mathematical answer against the complete public problem."""
    validate_problem(problem)
    if isinstance(problem, RSAProblem):
        verify_factor_pair(problem.n, secret)
    elif isinstance(problem, FFDLogProblem):
        if (not isinstance(secret, FFDLogSecret) or type(secret.x) is not int
                or not 1 <= secret.x < problem.order
                or pow(problem.g, secret.x, problem.p) != problem.y):
            raise QSploitError("INVALID_DLOG_RESULT", "The recovered exponent does not match the public finite-field problem.")
    elif isinstance(problem, ECDLogProblem):
        from cryptography.hazmat.primitives.asymmetric import ec, x25519
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from qsploit.groups import P256_ORDER, normalize_x25519_point
        if problem.curve == "x25519":
            if not isinstance(secret, X25519Secret) or type(secret.scalar) is not bytes or len(secret.scalar) != 32:
                raise QSploitError("INVALID_DLOG_RESULT", "X25519 recovery requires a 32-byte private input.")
            # RFC 7748 clamps the private input inside the X25519 primitive.
            # Bytes differing only in clamped-away bits represent the same key.
            derived = x25519.X25519PrivateKey.from_private_bytes(secret.scalar).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            if derived != normalize_x25519_point(problem.public_point):
                raise QSploitError("INVALID_DLOG_RESULT", "The recovered X25519 private input does not reproduce the public share.")
            return
        if not isinstance(secret, ECDLogSecret) or type(secret.x) is not int or not 1 <= secret.x < P256_ORDER:
            raise QSploitError("INVALID_DLOG_RESULT", "The recovered P-256 scalar has an invalid type or range.")
        derived = ec.derive_private_key(secret.x, ec.SECP256R1()).public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        if derived != problem.public_point:
            raise QSploitError("INVALID_DLOG_RESULT", "The recovered scalar does not reproduce the captured P-256 public point.")


def dlog_registry_key(problem: FFDLogProblem) -> str:
    validate_problem(problem)
    if not isinstance(problem, FFDLogProblem):
        raise QSploitError("UNSUPPORTED_PROBLEM", "This problem does not request a finite-field discrete logarithm.")
    return ":".join(format(value, "x") for value in (problem.p, problem.g, problem.y, problem.order))


def ec_registry_key(problem: ECDLogProblem) -> str:
    validate_problem(problem)
    if not isinstance(problem, ECDLogProblem):
        raise QSploitError("UNSUPPORTED_PROBLEM", "This problem does not request an elliptic-curve discrete logarithm.")
    point = problem.public_point
    if problem.curve == "x25519":
        from qsploit.groups import normalize_x25519_point
        point = normalize_x25519_point(point)
    return problem.curve + ":" + point.hex()


def known_secret(problem: PublicProblem) -> RecoveredSecret:
    validate_problem(problem)
    if isinstance(problem, RSAProblem):
        return known_factors(problem)
    if isinstance(problem, FFDLogProblem):
        key, path = dlog_registry_key(problem), DLOG_FILE
    else:
        key, path = ec_registry_key(problem), EC_DLOG_FILE
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
        item = entries.get(key)
        if item is None:
            raise QSploitError("FIXTURE_NOT_FOUND", "No known test scalar matches this complete public cryptographic problem.")
        if isinstance(problem, ECDLogProblem) and problem.curve == "x25519":
            secret = X25519Secret(bytes.fromhex(item["scalar"]))
        else:
            value = int(item["x"], 16)
            secret = FFDLogSecret(value) if isinstance(problem, FFDLogProblem) else ECDLogSecret(value)
    except QSploitError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise QSploitError("FIXTURE_INVALID", "The bundled demonstration exponent fixture is unavailable or malformed.") from None
    verify_secret(problem, secret)
    return secret


def has_known_recovery(problem: PublicProblem) -> bool:
    try:
        known_secret(problem)
        return True
    except QSploitError:
        return False


def recover(problem: PublicProblem, options: ExecutionOptions, report: Report) -> Recovery:
    validate_problem(problem)
    validate_options(options)
    if options.backend == "fixture":
        report(Progress("matching_test_modulus" if isinstance(problem, RSAProblem) else "matching_test_public_problem"))
        secret = known_secret(problem)
        timing = timing_for(problem, options)
        report(Progress("illustrative_demo_delay"))
        time.sleep(timing.seconds)
        report(Progress("verifying_factors" if isinstance(problem, RSAProblem) else "verifying_discrete_log"))
        verify_secret(problem, secret)
        return Recovery(secret, "fixture_lookup", "none", None, ())
    if isinstance(problem, (FFDLogProblem, ECDLogProblem)):
        raise QSploitError("UNSUPPORTED_PROBLEM", "A quantum discrete-logarithm solver is not implemented. No fixture fallback was used.")
    # Import lazily: the complete classical/demo application needs no Qiskit.
    from .backends import run_aer, run_ionq
    from .shor import factor_shor
    runner = run_aer if options.backend == "aer" else run_ionq
    return factor_shor(problem.n, runner, options, report)
