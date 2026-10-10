"""P-256 mathematical recovery: public point in, verified scalar out."""
from dataclasses import fields, replace
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from qsploit.groups import P256_ORDER
from qsploit.models import (ECDLogProblem, ECDLogSecret, FFDLogSecret, RSAFactors,
                            ExecutionOptions, QSploitError, Recovery)
from qsploit.quantum import engine
from qsploit.jobs import verify_recovery


def public_problem(x=17):
    public = ec.derive_private_key(x, ec.SECP256R1()).public_key()
    return ECDLogProblem("secp256r1", public.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint))


@pytest.fixture
def registry(tmp_path, monkeypatch):
    problem = public_problem()
    path = tmp_path / "ec_dlog.json"
    path.write_text(json.dumps({engine.ec_registry_key(problem): {"x": "11"}}))
    monkeypatch.setattr(engine, "EC_DLOG_FILE", path)
    return problem, path


def test_ec_contract_only_curve_and_one_public_point():
    assert {field.name for field in fields(ECDLogProblem)} == {"curve", "public_point", "kind"}
    assert {field.name for field in fields(ECDLogSecret)} == {"x"}
    assert "17" not in repr(ECDLogSecret(17))


def test_p256_automatic_fixture_recovery_and_zero_delay(registry, monkeypatch):
    problem, _ = registry
    delays, progress = [], []
    monkeypatch.setattr(engine.time, "sleep", delays.append)
    answer = engine.recover(problem, ExecutionOptions("fixture", demo_delay_seconds=0), progress.append)
    assert answer.secret == ECDLogSecret(17)
    assert answer.method == "fixture_lookup" and answer.execution == "none"
    assert answer.target is None and answer.measurements == ()
    assert delays == [0.0]
    assert engine.has_known_recovery(problem)
    assert engine.ec_registry_key(problem) == "secp256r1:" + problem.public_point.hex()
    assert progress[-1].stage == "verifying_discrete_log"
    verify_recovery(problem, answer, ExecutionOptions("fixture"))


def test_unknown_valid_p256_public_point_not_invented(registry):
    problem = public_problem(19)
    assert not engine.has_known_recovery(problem)
    with pytest.raises(QSploitError) as exc:
        engine.recover(problem, ExecutionOptions("fixture", demo_delay_seconds=0), lambda _: None)
    assert exc.value.code == "FIXTURE_NOT_FOUND"


@pytest.mark.parametrize("curve", ["secp384r1", "P-256", "", None])
def test_unimplemented_curve_not_accepted(curve):
    with pytest.raises(QSploitError) as exc:
        engine.validate_problem(replace(public_problem(), curve=curve))
    assert exc.value.code == "UNSUPPORTED_GROUP"


def test_p256_point_encoding_cannot_be_used_as_x25519():
    with pytest.raises(QSploitError) as exc:
        engine.validate_problem(replace(public_problem(), curve="x25519"))
    assert exc.value.code == "INVALID_EC_PUBLIC"


@pytest.mark.parametrize("point", [b"", b"\x00", b"\x04" + bytes(64), b"\x04" + b"\xff" * 64,
                                     b"\x02" + bytes(32), b"\x04" + bytes(63), b"\x04" + bytes(65),
                                     "encoded-point", None, bytearray(65)])
def test_invalid_p256_encoding_or_point_rejected(point):
    with pytest.raises(QSploitError) as exc:
        engine.validate_problem(ECDLogProblem("secp256r1", point))
    assert exc.value.code == "INVALID_EC_PUBLIC"


@pytest.mark.parametrize("secret", [ECDLogSecret(0), ECDLogSecret(-1), ECDLogSecret(18), ECDLogSecret(P256_ORDER),
                                      ECDLogSecret(P256_ORDER + 17), ECDLogSecret(True), ECDLogSecret(17.0),
                                      ECDLogSecret("17"), FFDLogSecret(17), RSAFactors(3, 5)],
                         ids=["zero", "negative", "wrong-point", "order", "noncanonical", "bool", "float", "text", "ff", "rsa"])
def test_scalar_type_range_and_public_equation_verified(secret):
    with pytest.raises(QSploitError) as exc:
        engine.verify_secret(public_problem(), secret)
    assert exc.value.code == "INVALID_DLOG_RESULT"


def test_wrong_registry_scalar_cannot_pass(registry):
    problem, path = registry
    path.write_text(json.dumps({engine.ec_registry_key(problem): {"x": "12"}}))
    with pytest.raises(QSploitError) as exc:
        engine.known_secret(problem)
    assert exc.value.code == "INVALID_DLOG_RESULT"


@pytest.mark.parametrize("backend", ["aer", "ionq_simulator", "ionq_qpu"])
def test_ec_real_backend_rejected_without_fixture_or_timer(backend, monkeypatch):
    monkeypatch.setattr(engine, "known_secret", lambda _: pytest.fail("fixture fallback"))
    monkeypatch.setattr(engine.time, "sleep", lambda _: pytest.fail("real mode timer"))
    with pytest.raises(QSploitError) as exc:
        engine.recover(public_problem(), ExecutionOptions(backend), lambda _: None)
    assert exc.value.code == "UNSUPPORTED_PROBLEM"


@pytest.mark.parametrize("method,execution,backend,target", [
    ("fixture_lookup", "aer", "fixture", None),
    ("fixture_lookup", "none", "aer", None),
    ("classical_precheck", "none", "aer", None),
    ("quantum_order_finding", "aer", "aer", None),
    ("fixture_lookup", "none", "fixture", "fake-qpu"),
])
def test_ec_parent_boundary_rejects_false_provenance(method, execution, backend, target):
    answer = Recovery(ECDLogSecret(17), method, execution, target, ())
    with pytest.raises(QSploitError) as exc:
        verify_recovery(public_problem(), answer, ExecutionOptions(backend))
    assert exc.value.code == "INVALID_PROVENANCE"


def test_ec_wrong_kind_rejected():
    with pytest.raises(QSploitError) as exc:
        engine.validate_problem(replace(public_problem(), kind="ff_dlog"))
    assert exc.value.code == "UNSUPPORTED_PROBLEM"


def test_shipped_ec_fixture_scalars_verify_against_only_public_points():
    entries = json.loads(engine.EC_DLOG_FILE.read_text())
    assert entries
    for key in entries:
        curve, public = key.split(":", 1)
        problem = ECDLogProblem(curve, bytes.fromhex(public))
        assert key == engine.ec_registry_key(problem)
        secret = engine.known_secret(problem)
        engine.verify_secret(problem, secret)
