from dataclasses import replace
import json
import math

import pytest

from qsploit.models import ExecutionOptions, Measurement, QSploitError, RSAFactors, RSAProblem
from qsploit.quantum import engine
from qsploit.quantum.backends import normalize_weights, validate_measurement
from qsploit.quantum.shor import factors_from_measurements


def test_fixture_exact_modulus_only_and_timing(monkeypatch, tmp_path):
    factors = tmp_path / "factors.json"
    factors.write_text(json.dumps({"f": {"p": "3", "q": "5"}}))
    monkeypatch.setattr(engine, "FACTOR_FILE", factors)
    delays, stages = [], []
    monkeypatch.setattr(engine.time, "sleep", delays.append)
    options = ExecutionOptions("fixture")
    answer = engine.recover(RSAProblem(15), options, stages.append)
    assert answer.factors == RSAFactors(3, 5)
    assert answer.method == "fixture_lookup" and answer.execution == "none"
    assert answer.measurements == () and answer.target is None
    assert delays == [3.0]
    assert engine.timing_for(RSAProblem(15), options).kind == "illustrative_delay"
    engine.recover(RSAProblem(15), replace(options, demo_delay_seconds=0), stages.append)
    assert delays == [3.0, 0.0]
    with pytest.raises(QSploitError, match="No known test factors"):
        engine.recover(RSAProblem(21), options, stages.append)
    assert delays == [3.0, 0.0]  # failure is honest and immediate


@pytest.mark.parametrize("delay", [-1, float("nan"), float("inf"), True, "3"])
def test_invalid_delays(delay):
    with pytest.raises(QSploitError):
        engine.timing_for(RSAProblem(15), ExecutionOptions("fixture", demo_delay_seconds=delay))


@pytest.mark.parametrize("n", [0, 1, -7, True, "15", 1 << 16384], ids=["zero", "one", "negative", "bool", "text", "oversized"])
def test_invalid_problems(n):
    with pytest.raises(QSploitError):
        engine.validate_problem(RSAProblem(n))


@pytest.mark.parametrize("factors", [RSAFactors(1, 15), RSAFactors(3, 7), RSAFactors(True, 15), RSAFactors(3, "5")])
def test_wrong_factor_pairs(factors):
    with pytest.raises(QSploitError):
        engine.verify_factor_pair(15, factors)


def test_real_rsa_preflight_before_circuit(monkeypatch):
    from qsploit.quantum import arithmetic
    monkeypatch.setattr(arithmetic, "order_finding_circuit", lambda *args: pytest.fail("huge circuit allocation"))
    with pytest.raises(QSploitError) as exc:
        engine.recover(RSAProblem((1 << 2048) - 1), ExecutionOptions("aer"), lambda _: None)
    assert exc.value.code == "RESOURCE_LIMIT"


def measurement(weights=None, **kwargs):
    return replace(Measurement({1: 4.0} if weights is None else weights, "counts", 4, "aer", "test", None, "a" * 64, 18, 20, 10), **kwargs)


def test_counts_probabilities_and_bit_order():
    assert normalize_weights({"0001": 2, "1000": 2}, 4) == {1: 2, 8: 2}
    assert normalize_weights({"0x8": 2, "0 001": 2}, 4) == {8: 2, 1: 2}
    validate_measurement(measurement(), 8, "aer")
    validate_measurement(measurement({1: .25, 2: .75}, kind="probabilities", actual_shots=None), 8, "aer")


@pytest.mark.parametrize("value", [
    measurement({1: float("nan")}), measurement({1: -1}), measurement({256: 4}),
    measurement({1: 3}), measurement({1: 1.5, 2: 2.5}),
    measurement({1: 1}, kind="probabilities"),
    measurement({1: .5}, kind="probabilities", actual_shots=None),
    measurement(execution="ionq_qpu"), measurement(circuit_sha256=""),
    measurement(circuit_sha256="z" * 64), measurement(qubits=float("nan")),
    measurement(compiled_ops=1.5), measurement(compiled_depth=True),
    measurement(target=123), measurement({"0001": 4}),
])
def test_reject_malformed_measurements(value):
    with pytest.raises(QSploitError):
        validate_measurement(value, 8, "aer")


def test_no_factors_from_useless_samples():
    assert factors_from_measurements(15, 2, 8, {0: 100}) is None
    assert factors_from_measurements(21, 2, 10, {0: 100}) is None


def test_failures_never_fallback(monkeypatch):
    from qsploit.quantum import backends
    def fail(*args):
        raise QSploitError("TEST_PROVIDER_FAILURE", "Provider failed")
    monkeypatch.setattr(backends, "run_aer", fail)
    monkeypatch.setattr(engine, "known_factors", lambda _: pytest.fail("fallback"))
    pytest.importorskip("qiskit")
    with pytest.raises(QSploitError) as exc:
        engine.recover(RSAProblem(15), ExecutionOptions("aer"), lambda _: None)
    assert exc.value.code == "TEST_PROVIDER_FAILURE"


def test_unconfigured_ionq_never_constructs_provider(monkeypatch):
    from qsploit.quantum.backends import run_ionq
    monkeypatch.delenv("IONQ_API_KEY", raising=False)
    with pytest.raises(QSploitError) as exc:
        run_ionq(None, ExecutionOptions("ionq_simulator"), lambda _: None)
    assert exc.value.code == "IONQ_NOT_CONFIGURED"


@pytest.mark.parametrize("modulus", [3, 5, 7])
def test_modular_add_exhaustive_controls_and_clean_flag(modulus):
    pytest.importorskip("qiskit")
    from qiskit import QuantumCircuit
    from qiskit.circuit.library import QFTGate
    from qiskit.quantum_info import Statevector
    from qsploit.quantum.arithmetic import controlled_add_mod_n
    width = modulus.bit_length() + 1
    for value in range(modulus):
        circuit = QuantumCircuit(width + 3)
        register = list(range(2, 2 + width))
        circuit.append(QFTGate(width), register)
        controlled_add_mod_n(circuit, register, width + 2, value, modulus, [0, 1])
        circuit.append(QFTGate(width).inverse(), register)
        for control in range(4):
            for b in range(modulus):
                state = Statevector.from_int(control + 4 * b, 2 ** circuit.num_qubits).evolve(circuit)
                expected = control + 4 * ((b + value) % modulus if control == 3 else b)
                assert abs(state.data[expected] - 1) < 1e-9


@pytest.mark.parametrize("modulus,base", [(3, 2), (5, 2), (5, 3), (7, 3), (9, 2), (15, 2), (21, 2)])
def test_modular_multiplication_and_relative_phase(modulus, base):
    pytest.importorskip("qiskit")
    import numpy as np
    from qiskit.quantum_info import Statevector
    from qsploit.quantum.arithmetic import controlled_multiply_mod_n
    gate = controlled_multiply_mod_n(base, modulus)
    # All valid inputs in coherent superposition with distinct complex amplitudes
    # expose input-dependent phase errors and dirty scratch at once.
    initial = np.zeros(1 << gate.num_qubits, dtype=complex)
    expected = np.zeros_like(initial)
    for control in (0, 1):
        for x in range(modulus):
            amplitude = complex(x + 1, control + 2)
            initial[control + 2 * x] = amplitude
            expected[control + 2 * ((base * x) % modulus if control else x)] = amplitude
    norm = np.linalg.norm(initial)
    actual = Statevector(initial / norm).evolve(gate)
    assert np.max(np.abs(actual.data - expected / norm)) < 1e-9
    restored = actual.evolve(gate.inverse())
    assert np.max(np.abs(restored.data - initial / norm)) < 1e-9


@pytest.mark.parametrize("modulus,expected", [(15, (3, 5)), (21, (3, 7))])
def test_genuine_aer_factorization(modulus, expected):
    pytest.importorskip("qiskit_aer")
    answer = engine.recover(RSAProblem(modulus), ExecutionOptions("aer", shots=512, max_attempts=1), lambda _: None)
    assert (answer.factors.p, answer.factors.q) == expected
    assert answer.method == "quantum_order_finding" and answer.execution == "aer"
    assert len(answer.measurements) == 1
    result = answer.measurements[0]
    assert result.actual_shots == 512
    assert result.qubits == 4 * modulus.bit_length() + 2
    assert result.compiled_ops > 100
    assert len(result.weights) > 1


def test_ionq_offline_qis_compile(monkeypatch):
    pytest.importorskip("qiskit_ionq")
    from qiskit import transpile
    from qiskit_ionq import IonQProvider
    from qiskit_ionq import ionq_backend
    from qsploit.quantum.arithmetic import order_finding_circuit
    # Metadata lookup mocked explicitly. This proves compilation only, NOT IonQ
    # credentials, target availability, remote simulation or physical execution.
    monkeypatch.setattr(ionq_backend, "get_n_qubits", lambda *args, **kwargs: 32)
    provider = IonQProvider(token="offline-test-placeholder")
    backend = provider.get_backend("simulator", gateset="qis")
    circuit = transpile(order_finding_circuit(15), basis_gates=["rx", "ry", "rz", "h", "x", "cx"], optimization_level=1)
    assert circuit.num_qubits == 18
    assert set(circuit.count_ops()) <= set(backend.operation_names)
    assert circuit.size() < 250000


@pytest.mark.parametrize("terminal", ["success", "failed", "timeout", "interrupted", "cancel_error"])
def test_ionq_adapter_status_probability_and_cancellation(monkeypatch, terminal):
    pytest.importorskip("qiskit_ionq")
    from types import SimpleNamespace
    from qiskit import QuantumCircuit
    from qiskit.providers import JobStatus
    import qiskit_ionq
    from qiskit_ionq import ionq_backend
    from qsploit.quantum import backends
    calls = []
    class FakeJob:
        cancelled = False
        def job_id(self): return "offline-contract-job"
        def status(self):
            if self.cancelled: return JobStatus.CANCELLED
            if terminal in ("interrupted", "cancel_error"):
                raise QSploitError("BACKEND_INTERRUPTED", "Worker shutdown")
            return {"success": JobStatus.DONE, "failed": JobStatus.ERROR, "timeout": JobStatus.RUNNING}[terminal]
        def result(self, **kwargs):
            return SimpleNamespace(get_probabilities=lambda _: {"00": .5, "11": .5})
        def cancel(self):
            calls.append("cancel")
            if terminal == "cancel_error":
                raise RuntimeError("offline cancellation failure")
            self.cancelled = True
    class FakeSimulator:
        name = "offline-simulator"
        num_qubits = 32
        operation_names = ["rx", "ry", "rz", "h", "x", "cx"]
        def run(self, circuit, **kwargs): calls.append("run"); return FakeJob()
    monkeypatch.setattr(ionq_backend, "IonQSimulatorBackend", FakeSimulator)
    monkeypatch.setattr(qiskit_ionq, "IonQProvider", lambda **kwargs: SimpleNamespace(get_backend=lambda *args, **kwargs: FakeSimulator()))
    monkeypatch.setenv("IONQ_API_KEY", "offline-placeholder")
    monkeypatch.setenv("QSPLOIT_IONQ_ALLOW_SUBMIT", "1")
    clock = iter([0, 0, 2, 3, 4])
    monkeypatch.setattr(backends, "time", SimpleNamespace(monotonic=lambda: next(clock), sleep=lambda _: None))
    circuit = QuantumCircuit(2, 2)
    circuit.h(0); circuit.cx(0, 1); circuit.measure([0, 1], [0, 1])
    options = ExecutionOptions("ionq_simulator", target="explicit-test-target", timeout_seconds=1)
    progress = []
    if terminal == "success":
        result = backends.run_ionq(circuit, options, progress.append)
        assert result.kind == "probabilities" and result.actual_shots is None
        assert result.provider_job_id == "offline-contract-job"
        assert result.weights == {0: .5, 3: .5}
    else:
        with pytest.raises(QSploitError) as exc:
            backends.run_ionq(circuit, options, progress.append)
        assert exc.value.code == {"timeout": "PROVIDER_TIMEOUT", "failed": "PROVIDER_JOB_FAILED", "interrupted": "BACKEND_INTERRUPTED", "cancel_error": "BACKEND_INTERRUPTED"}[terminal]
    assert calls == (["run", "cancel"] if terminal in ("timeout", "interrupted", "cancel_error") else ["run"])
    if terminal in ("timeout", "interrupted"):
        assert progress[-1].stage == "provider_cancel_confirmed"
    elif terminal == "cancel_error":
        assert progress[-1].stage == "provider_cancel_unconfirmed"


@pytest.mark.parametrize("modulus", [15, 21])
def test_qollab_companion_one_real_local_job(monkeypatch, capsys, modulus):
    pytest.importorskip("qiskit_aer")
    from pathlib import Path
    from qiskit_aer import AerSimulator
    root = Path(__file__).resolve().parents[1]
    for name in ("arithmetic.py", "postprocess.py"):
        assert (root / "qollab" / name).read_bytes() == (root / "qsploit" / "quantum" / name).read_bytes()
    monkeypatch.syspath_prepend(str(root / "qollab"))
    class SuppliedBackend:
        name = "test_supplied_aer_not_qollab_cloud"
        calls = 0
        def run(self, circuit, **kwargs):
            self.calls += 1
            return AerSimulator(method="matrix_product_state", max_parallel_threads=1).run(circuit, seed_simulator=23, **kwargs)
    supplied = SuppliedBackend()
    namespace = {"backend": supplied}
    source = (root / "qollab" / "main.py").read_text()
    exec(compile(source, str(root / "qollab" / "main.py"), "exec"), namespace)
    assert supplied.calls == 0  # Qollab itself invokes main after loading.
    namespace["main"](modulus=modulus, shots=256)
    assert supplied.calls == 1
    output = capsys.readouterr().out
    assert '"factor_pair_verified": true' in output
    assert '"actual_shots": 256' in output
    assert "unrelated to the captured RSA-2048 key" in output
