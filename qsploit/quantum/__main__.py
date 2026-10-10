"""Run a bounded small-number experiment separately from captured TLS recovery."""
from __future__ import annotations

import argparse
import json
import os

from qsploit.models import ExecutionOptions, QSploitError, RSAProblem
from .engine import recover


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modulus", type=int, choices=[15, 21], default=15)
    parser.add_argument("--backend", choices=["aer", "ionq_simulator", "ionq_qpu"], default="aer")
    parser.add_argument("--shots", type=int, default=512)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    options = ExecutionOptions(args.backend, target=os.environ.get("QSPLOIT_IONQ_TARGET"), shots=args.shots, max_attempts=1, timeout_seconds=args.timeout)
    try:
        result = recover(RSAProblem(args.modulus), options, lambda progress: print(json.dumps({"stage": progress.stage, "provider_job_id": progress.provider_job_id}), flush=True))
    except QSploitError as exc:
        print(json.dumps({"error": exc.code, "message": exc.message}))
        raise SystemExit(1) from None
    print(json.dumps({"modulus": args.modulus, "factors": [result.factors.p, result.factors.q],
                      "method": result.method, "execution": result.execution, "target": result.target,
                      "measurements": [{"kind": m.kind, "actual_shots": m.actual_shots,
                          "qubits": m.qubits, "compiled_ops": m.compiled_ops, "compiled_depth": m.compiled_depth,
                          "circuit_sha256": m.circuit_sha256, "provider_job_id": m.provider_job_id}
                          for m in result.measurements],
                      "note": "Small-number experiment, unrelated to the captured RSA-2048 key."}, indent=2))


if __name__ == "__main__":
    main()
