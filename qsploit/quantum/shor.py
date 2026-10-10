"""Measured order finding and bounded exact-rational Shor postprocessing."""
from __future__ import annotations

import math
import secrets
import time
from dataclasses import replace

from qsploit.models import CircuitRunner, ExecutionOptions, Progress, QSploitError, Recovery, Report, RSAFactors
from .engine import verify_factor_pair


from .postprocess import convergent_denominators, factors_from_measurements as _factor_pair


def factors_from_measurements(modulus: int, base: int, phase_bits: int, weights: dict[int, float]) -> RSAFactors | None:
    pair = _factor_pair(modulus, base, phase_bits, weights)
    if pair is None:
        return None
    answer = RSAFactors(*pair)
    verify_factor_pair(modulus, answer)
    return answer


def preflight(modulus: int, options: ExecutionOptions) -> None:
    width = 4 * modulus.bit_length() + 2
    if width > options.max_qubits:
        raise QSploitError("RESOURCE_LIMIT", f"This circuit requires {width} logical qubits before compilation; the configured limit is {options.max_qubits}. No circuit was built or submitted.")


def factor_shor(modulus: int, runner: CircuitRunner, options: ExecutionOptions, report: Report) -> Recovery:
    from .arithmetic import order_finding_circuit
    preflight(modulus, options)
    if modulus <= 3:
        raise QSploitError("NO_FACTOR_FOUND", "This small prime has no nontrivial factor pair.")
    # Elementary preprocessing is explicitly distinguished from quantum work.
    root = math.isqrt(modulus)
    factor = 2 if modulus % 2 == 0 and modulus > 2 else root if root * root == modulus else None
    if factor is not None:
        answer = RSAFactors(min(factor, modulus // factor), max(factor, modulus // factor))
        verify_factor_pair(modulus, answer)
        return Recovery(answer, "classical_precheck", "none", None, ())
    measurements = []
    start = time.monotonic()
    for attempt in range(options.max_attempts):
        if time.monotonic() - start >= options.timeout_seconds:
            raise QSploitError("QUANTUM_TIMEOUT", "The configured local factoring deadline expired.")
        # Base 2 for first attempt is reproducible for every odd modulus, not a
        # special factor-15 circuit. Later attempts select independent bases.
        base = 2 if attempt == 0 else secrets.randbelow(modulus - 3) + 2
        divisor = math.gcd(base, modulus)
        if 1 < divisor < modulus:
            if measurements:
                # Do not mislabel earlier circuit execution as execution=none.
                # This retry base is unsuitable; its gcd is not used as a
                # quantum answer. The first coprime base already ran.
                continue
            answer = RSAFactors(min(divisor, modulus // divisor), max(divisor, modulus // divisor))
            verify_factor_pair(modulus, answer)
            return Recovery(answer, "classical_precheck", "none", None, ())
        report(Progress("building_circuit"))
        circuit = order_finding_circuit(modulus, base)
        remaining = int(options.timeout_seconds - (time.monotonic() - start))
        if remaining < 1:
            raise QSploitError("QUANTUM_TIMEOUT", "Circuit construction exhausted the factoring deadline; no job was submitted.")
        measurement = runner(circuit, replace(options, timeout_seconds=remaining), report)
        from .backends import validate_measurement
        validate_measurement(measurement, 2 * modulus.bit_length(), options.backend)
        measurements.append(measurement)
        report(Progress("processing_measurements"))
        answer = factors_from_measurements(modulus, base, 2 * modulus.bit_length(), measurement.weights)
        if answer:
            report(Progress("verifying_factors"))
            verify_factor_pair(modulus, answer)
            return Recovery(answer, "quantum_order_finding", measurement.execution, measurement.target, tuple(measurements))
    raise QSploitError("NO_FACTOR_FOUND", "Measured order finding did not yield nontrivial factors within the configured attempt budget. No demonstration fallback was used.")
