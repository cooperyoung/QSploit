"""Spawned recovery worker: public mathematical problem and options only."""
from __future__ import annotations
import asyncio
import multiprocessing as mp
import signal
import time

from .models import ExecutionOptions, Progress, QSploitError, Recovery, RSAProblem, PublicProblem


def _worker(pipe, problem: PublicProblem, options: ExecutionOptions):
    # Child never receives or imports the application's capture store.
    from .quantum.engine import recover
    def interrupted(signum, frame):
        raise QSploitError("BACKEND_INTERRUPTED", "Recovery was interrupted; check any submitted provider job's status.")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        result = recover(problem, options, lambda p: pipe.send(("progress", p)))
        pipe.send(("result", result))
    except QSploitError as exc:
        pipe.send(("error", (exc.code, exc.message)))
    except Exception:
        pipe.send(("error", ("BACKEND_FAILED", "Recovery backend failed; no fallback was attempted.")))
    finally:
        pipe.close()


async def run_recovery(problem: PublicProblem, options: ExecutionOptions, report) -> Recovery:
    context = mp.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(child, problem, options), daemon=True)
    process.start()
    child.close()
    deadline = time.monotonic() + options.timeout_seconds + 5
    provider_seen = False
    try:
        while time.monotonic() < deadline:
            if parent.poll():
                try:
                    kind, value = parent.recv()
                except EOFError:
                    raise QSploitError("BACKEND_FAILED", "Recovery worker ended without a result.") from None
                if kind == "progress" and isinstance(value, Progress):
                    if value.provider_job_id and not provider_seen:
                        provider_seen = True
                        deadline = time.monotonic() + options.timeout_seconds + 5
                    report(value)
                elif kind == "result" and isinstance(value, Recovery):
                    return value
                elif kind == "error":
                    raise QSploitError(*value)
                else:
                    raise QSploitError("BACKEND_FAILED", "Invalid recovery worker response.")
            elif not process.is_alive():
                raise QSploitError("BACKEND_FAILED", "Recovery worker ended without a result.")
            await asyncio.sleep(0.05)
        raise QSploitError("BACKEND_TIMEOUT", "Recovery exceeded its deadline. A local stop does not prove a remote job was cancelled.")
    finally:
        if process.is_alive():
            process.terminate()
        await asyncio.to_thread(process.join, 3)
        if process.is_alive():
            process.kill()
            await asyncio.to_thread(process.join, 2)
        parent.close()


def verify_recovery(problem: PublicProblem, result: Recovery, options: ExecutionOptions):
    from .quantum.engine import verify_secret
    verify_secret(problem, result.secret)
    if result.method == "fixture_lookup":
        valid = options.backend == "fixture" and result.execution == "none" and result.target is None and not result.measurements
    elif result.method == "classical_precheck":
        valid = isinstance(problem, RSAProblem) and options.backend != "fixture" and result.execution == "none" and result.target is None and not result.measurements
    elif result.method == "quantum_order_finding":
        valid = isinstance(problem, RSAProblem) and result.execution == options.backend and bool(result.measurements) and all(m.execution == result.execution for m in result.measurements)
        if valid:
            from .quantum.backends import validate_measurement
            for measurement in result.measurements:
                validate_measurement(measurement, 2 * problem.n.bit_length(), options.backend)
                if measurement.qubits > options.max_qubits or measurement.compiled_ops > options.max_compiled_ops:
                    valid = False
                if measurement.actual_shots is not None and measurement.actual_shots > options.shots:
                    valid = False
                if options.backend.startswith("ionq") and not measurement.provider_job_id:
                    valid = False
            valid = valid and len(result.measurements) <= options.max_attempts and result.target == result.measurements[-1].target
    else:
        valid = False
    if not valid:
        raise QSploitError("INVALID_PROVENANCE", "Recovery provenance is inconsistent with the requested backend.")
