"""Bounded circuit runners. Only the IonQ runner can contact a provider."""
from __future__ import annotations

import hashlib
import math
import os
import re
import time

from qsploit.models import ExecutionOptions, Measurement, Progress, QSploitError, Report


def normalize_weights(raw: dict, phase_bits: int) -> dict[int, float]:
    if not isinstance(raw, dict) or not raw:
        raise QSploitError("INVALID_MEASUREMENT", "Provider returned no measurement distribution.")
    result = {}
    for outcome, weight in raw.items():
        try:
            if type(outcome) is int:
                parsed = outcome
            elif isinstance(outcome, str) and outcome.startswith("0x"):
                parsed = int(outcome, 16)
            elif isinstance(outcome, str) and set(outcome.replace(" ", "")) <= {"0", "1"}:
                parsed = int(outcome.replace(" ", ""), 2)
            else:
                raise ValueError
            number = float(weight)
            if isinstance(weight, bool) or not math.isfinite(number) or number < 0 or not 0 <= parsed < 1 << phase_bits or parsed in result:
                raise ValueError
        except (ValueError, TypeError, OverflowError):
            raise QSploitError("INVALID_MEASUREMENT", "Provider returned malformed weights or phase-register outcomes.") from None
        result[parsed] = number
    return result


def validate_measurement(measurement: Measurement, phase_bits: int, expected_execution: str) -> None:
    if not isinstance(measurement, Measurement) or measurement.execution != expected_execution or expected_execution not in ("aer", "ionq_simulator", "ionq_qpu"):
        raise QSploitError("INVALID_PROVENANCE", "Measurement execution does not match the requested runner.")
    if type(phase_bits) is not int or not 1 <= phase_bits <= 64 or not isinstance(measurement.weights, dict) or any(type(outcome) is not int for outcome in measurement.weights):
        raise QSploitError("INVALID_MEASUREMENT", "Internal measurement outcomes must be integer phase-register values.")
    weights = normalize_weights(measurement.weights, phase_bits)
    total = math.fsum(weights.values())
    if measurement.kind == "counts":
        if type(measurement.actual_shots) is not int or measurement.actual_shots <= 0 or any(not x.is_integer() for x in weights.values()) or total != measurement.actual_shots:
            raise QSploitError("INVALID_MEASUREMENT", "Count totals do not match the actual shot count.")
    elif measurement.kind == "probabilities":
        if measurement.actual_shots is not None or not math.isclose(total, 1, rel_tol=1e-6, abs_tol=1e-8):
            raise QSploitError("INVALID_MEASUREMENT", "Probability distribution is not normalized or invents a shot count.")
    else:
        raise QSploitError("INVALID_MEASUREMENT", "Unknown measurement distribution kind.")
    if (any(type(value) is not int or value < 1 for value in (measurement.qubits, measurement.compiled_ops, measurement.compiled_depth))
            or measurement.qubits < phase_bits
            or not isinstance(measurement.target, str) or not 1 <= len(measurement.target) <= 200
            or not isinstance(measurement.circuit_sha256, str) or re.fullmatch(r"[0-9a-fA-F]{64}", measurement.circuit_sha256) is None
            or (measurement.provider_job_id is not None and (not isinstance(measurement.provider_job_id, str) or not 1 <= len(measurement.provider_job_id) <= 200))
            or (expected_execution.startswith("ionq_") and not measurement.provider_job_id)):
        raise QSploitError("INVALID_PROVENANCE", "Measurement circuit provenance is incomplete.")


def circuit_hash(circuit) -> str:
    from qiskit import qasm2
    # Hash the exact executable instructions, excluding irrelevant random object
    # identities. Compiled circuits contain only the provider-supported basis.
    return hashlib.sha256(qasm2.dumps(circuit).encode()).hexdigest()


def _limits(circuit, options: ExecutionOptions) -> None:
    if circuit.num_qubits > options.max_qubits or circuit.size() > options.max_compiled_ops:
        raise QSploitError("RESOURCE_LIMIT", "Compiled circuit exceeds the configured qubit or operation budget; no job was submitted.")


def run_aer(circuit, options: ExecutionOptions, report: Report) -> Measurement:
    try:
        from qiskit import transpile
        from qiskit_aer import AerSimulator
    except ImportError:
        raise QSploitError("BACKEND_NOT_INSTALLED", "Install the quantum extra to run Qiskit Aer.") from None
    _limits(circuit, options)
    report(Progress("compiling"))
    backend = AerSimulator(method="matrix_product_state", max_parallel_threads=1)
    compiled = transpile(circuit, backend, optimization_level=1, seed_transpiler=23)
    _limits(compiled, options)
    digest = circuit_hash(compiled)
    report(Progress("simulating_quantum_circuit"))
    # A fixed sampler seed makes the published toy experiment reproducible; it
    # supplies neither factors nor an order. MPS is exact to floating tolerance
    # with no bond-dimension truncation configured.
    result = backend.run(compiled, shots=options.shots, seed_simulator=23).result(timeout=options.timeout_seconds)
    if not result.success:
        raise QSploitError("BACKEND_FAILED", "Aer did not complete the circuit successfully.")
    weights = normalize_weights(result.get_counts(0), circuit.num_clbits)
    measurement = Measurement(weights, "counts", int(result.results[0].shots), "aer", "aer_simulator_matrix_product_state", None, digest, compiled.num_qubits, compiled.size(), compiled.depth())
    validate_measurement(measurement, circuit.num_clbits, "aer")
    return measurement


def ionq_configuration_error(options: ExecutionOptions) -> str | None:
    if not os.environ.get("IONQ_API_KEY"):
        return "IONQ_API_KEY is not configured."
    if not options.target:
        return "An explicit QSPLOIT_IONQ_TARGET is required; no target is assumed."
    if os.environ.get("QSPLOIT_IONQ_ALLOW_SUBMIT") != "1":
        return "QSPLOIT_IONQ_ALLOW_SUBMIT=1 is required to authorize bounded cloud submissions."
    return None


def run_ionq(circuit, options: ExecutionOptions, report: Report) -> Measurement:
    deadline = time.monotonic() + options.timeout_seconds
    reason = ionq_configuration_error(options)
    if reason:
        raise QSploitError("IONQ_NOT_CONFIGURED", reason)
    try:
        from qiskit import transpile
        from qiskit.providers import JobStatus
        from qiskit_ionq import IonQProvider
        from qiskit_ionq.ionq_backend import IonQSimulatorBackend
    except ImportError:
        raise QSploitError("BACKEND_NOT_INSTALLED", "Install the ionq extra to use the IonQ provider.") from None
    _limits(circuit, options)
    job = None
    job_id = None
    known_terminal = False
    cancellation_attempted = False

    def cancel_pending() -> bool:
        nonlocal cancellation_attempted, known_terminal
        if job is None or known_terminal or cancellation_attempted:
            return False
        cancellation_attempted = True
        confirmed = False
        try:
            # Sending the cancel request is not an acknowledgment of remote
            # termination. Only an observed CANCELLED status establishes that.
            job.cancel()
            confirmed = job.status() == JobStatus.CANCELLED
            known_terminal = confirmed
        except Exception:
            pass
        try:
            report(Progress("provider_cancel_confirmed" if confirmed else "provider_cancel_unconfirmed", job_id))
        except Exception:
            pass  # A closing parent pipe must not hide the original failure.
        return confirmed

    try:
        provider = IonQProvider(token=os.environ["IONQ_API_KEY"])
        backend = provider.get_backend(options.target, gateset="qis")
        simulator = isinstance(backend, IonQSimulatorBackend)
        if simulator != (options.backend == "ionq_simulator"):
            raise QSploitError("TARGET_MISMATCH", "The configured IonQ target does not match simulator versus QPU execution.")
        if circuit.num_qubits > backend.num_qubits:
            raise QSploitError("RESOURCE_LIMIT", "Circuit width exceeds the actual IonQ target capacity.")
        report(Progress("compiling"))
        # IonQ has all-to-all connectivity. Basis compilation avoids Qiskit's
        # unnecessary idle-wire padding to every physical target qubit.
        qis_basis = ["rx", "ry", "rz", "h", "x", "cx"]
        if not set(qis_basis) <= set(backend.operation_names):
            raise QSploitError("TARGET_MISMATCH", "IonQ target does not advertise the required universal QIS gate subset.")
        compiled = transpile(circuit, basis_gates=qis_basis, optimization_level=1, seed_transpiler=23)
        _limits(compiled, options)
        digest = circuit_hash(compiled)
        if time.monotonic() >= deadline:
            raise QSploitError("PROVIDER_TIMEOUT", "Compilation exhausted the execution deadline; no IonQ job was submitted.")
        report(Progress("submitting_to_provider"))
        job = backend.run(compiled, shots=options.shots)
        job_id = str(job.job_id())
        while True:
            status = job.status()
            report(Progress("provider_" + status.name.lower(), job_id))
            if status == JobStatus.DONE:
                known_terminal = True
                break
            if status in (JobStatus.ERROR, JobStatus.CANCELLED):
                known_terminal = True
                raise QSploitError("PROVIDER_JOB_FAILED", "IonQ reported a failed or cancelled job; no demonstration fallback was used.")
            if time.monotonic() >= deadline:
                acknowledged = cancel_pending()
                state = "Provider confirmed cancellation." if acknowledged else "Remote cancellation was not confirmed; the job may still be running."
                raise QSploitError("PROVIDER_TIMEOUT", "IonQ polling deadline expired. " + state)
            time.sleep(min(2.0, max(0, deadline - time.monotonic())))
        result = job.result(timeout=max(1, deadline - time.monotonic()))
        # Ideal IonQ simulator reports exact probabilities. Do not convert these
        # into fictitious measured counts. Hardware uses the actual counts API.
        if simulator:
            weights = normalize_weights(result.get_probabilities(0), circuit.num_clbits)
            kind, actual_shots = "probabilities", None
        else:
            weights = normalize_weights(result.get_counts(0), circuit.num_clbits)
            kind, actual_shots = "counts", int(result.results[0].shots)
        measurement = Measurement(weights, kind, actual_shots, options.backend, backend.name, job_id, digest, compiled.num_qubits, compiled.size(), compiled.depth())
        validate_measurement(measurement, circuit.num_clbits, options.backend)
        return measurement
    except QSploitError:
        # Includes the worker's SIGTERM -> BACKEND_INTERRUPTED exception. Parent
        # allows a brief cleanup grace period, then may kill this process.
        cancel_pending()
        raise
    except Exception:
        # Provider exceptions can include request contents/credentials. Never
        # propagate arbitrary exception text through the public application.
        cancel_pending()
        raise QSploitError("IONQ_FAILED", "The IonQ provider call failed. Check target access and the provider job status; remote cancellation is not confirmed. No demonstration fallback was used.") from None
