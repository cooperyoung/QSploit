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

from qsploit.models import ExecutionOptions, Progress, QSploitError, Recovery, Report, RSAFactors, RSAProblem

FACTOR_FILE = Path(__file__).resolve().parent.parent / "demo" / "factors.json"


@dataclass(frozen=True)
class DemoTiming:
    seconds: float
    kind: str = "illustrative_delay"
    assumptions: str = "Configured presentation delay; not a quantum runtime or resource estimate."


def validate_problem(problem: RSAProblem) -> None:
    if not isinstance(problem, RSAProblem) or problem.kind != "rsa_factor":
        raise QSploitError("UNSUPPORTED_PROBLEM", "Only RSA factorization is implemented.")
    if type(problem.n) is not int or problem.n <= 1 or problem.n.bit_length() > 16384:
        raise QSploitError("INVALID_MODULUS", "RSA modulus must be an integer greater than one, at most 16384 bits.")


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


def timing_for(problem: RSAProblem, options: ExecutionOptions) -> DemoTiming:
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


def recover(problem: RSAProblem, options: ExecutionOptions, report: Report) -> Recovery:
    validate_problem(problem)
    validate_options(options)
    if options.backend == "fixture":
        report(Progress("matching_test_modulus"))
        factors = known_factors(problem)
        timing = timing_for(problem, options)
        report(Progress("illustrative_demo_delay"))
        time.sleep(timing.seconds)
        report(Progress("verifying_factors"))
        verify_factor_pair(problem.n, factors)
        return Recovery(factors, "fixture_lookup", "none", None, ())
    # Import lazily: the complete classical/demo application needs no Qiskit.
    from .backends import run_aer, run_ionq
    from .shor import factor_shor
    runner = run_aer if options.backend == "aer" else run_ionq
    return factor_shor(problem.n, runner, options, report)
