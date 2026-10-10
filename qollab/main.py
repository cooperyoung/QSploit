"""QSploit's Qollab companion: one real circuit job, never PCAP decryption.

Qollab supplies the global `backend` and automatically invokes main. Do not
construct an Aer/IonQ provider, supply credentials, or call main at import time.
"""
import hashlib
import json
import math

from arithmetic import order_finding_circuit
from postprocess import factors_from_measurements


def main(modulus: int = 15, shots: int = 256):
    from qiskit import transpile, qasm2
    if modulus not in (15, 21):
        raise ValueError("Presentation controls allow 15 or 21; the arithmetic builder itself is generic.")
    if not 16 <= shots <= 1024:
        raise ValueError("Use between 16 and 1024 shots for this bounded one-job demonstration.")
    circuit = order_finding_circuit(modulus, base=2)
    # Universal QIS gates supported by IonQ and ordinary simulators. No target
    # layout is assumed; trapped-ion connectivity is all-to-all. The platform
    # executes the selected simulator backend, not a local provider we create.
    compiled = transpile(circuit, basis_gates=["rx", "ry", "rz", "h", "x", "cx"], optimization_level=1, seed_transpiler=23)
    if compiled.num_qubits > 22 or compiled.size() > 250000:
        raise ValueError("Circuit exceeds this demonstration's local resource bounds.")
    print("QSploit quantum evidence: real generic order-finding circuit; unrelated to the captured RSA-2048 key.")
    print(json.dumps({"modulus": modulus, "base": 2, "qubits": compiled.num_qubits, "operations": compiled.size(), "depth": compiled.depth(), "requested_shots": shots}))
    job = backend.run(compiled, shots=shots)  # Qollab provides backend; exactly one job.
    result = job.result()
    # Prefer exact probabilities when a backend exposes them; otherwise use
    # counts without rounding a probability distribution into invented shots.
    probabilities = getattr(result, "get_probabilities", None)
    if callable(probabilities):
        raw = probabilities(0)
        kind, actual_shots = "probabilities", None
    else:
        raw = result.get_counts(0)
        kind, actual_shots = "counts", None
    if not isinstance(raw, dict) or not raw:
        raise ValueError("The selected backend returned no usable measurement distribution.")
    weights = {}
    for outcome, weight in raw.items():
        if type(outcome) is int:
            value = outcome
        elif isinstance(outcome, str) and outcome.startswith("0x"):
            value = int(outcome, 16)
        else:
            value = int(str(outcome).replace(" ", ""), 2)
        number = float(weight)
        if not math.isfinite(number) or number < 0 or not 0 <= value < 1 << circuit.num_clbits or value in weights:
            raise ValueError("Invalid phase-register measurements.")
        weights[value] = number
    total = math.fsum(weights.values())
    if kind == "counts":
        # Some simulator wrappers expose probabilities under get_counts(). Keep
        # the numerical evidence honest even when that interface is ambiguous.
        if any(not weight.is_integer() for weight in weights.values()) and math.isclose(total, 1, rel_tol=1e-6):
            kind = "probabilities"
        elif any(not weight.is_integer() for weight in weights.values()) or total != shots:
            raise ValueError("Counts do not match the requested shots.")
        else:
            actual_shots = int(total)
    if kind == "probabilities" and not math.isclose(total, 1, rel_tol=1e-6, abs_tol=1e-8):
        raise ValueError("Probabilities are not normalized.")
    factors = factors_from_measurements(modulus, 2, circuit.num_clbits, weights)
    name = getattr(backend, "name", type(backend).__name__)
    name = name() if callable(name) else str(name)
    job_id = getattr(job, "job_id", None)
    job_id = str(job_id()) if callable(job_id) else None
    evidence = {"backend_reported_name": name, "provider_job_id": job_id,
                "method": "quantum_order_finding", "distribution_kind": kind,
                "actual_shots": actual_shots,
                "circuit_sha256": hashlib.sha256(qasm2.dumps(compiled).encode()).hexdigest(),
                "factors": factors, "factor_pair_verified": bool(factors and factors[0] * factors[1] == modulus),
                "note": "This is a small-number quantum experiment. It did not factor the captured RSA key; no capture data was provided."}
    print(json.dumps(evidence, indent=2))
    if factors is None:
        print("No factor pair found in this one measured job. There is no stored-factor fallback; noisy simulations may fail.")
