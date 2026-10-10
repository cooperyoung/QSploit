"""Finite-field recovery contract: exact public problem, scalar-only fixture."""
from dataclasses import fields, replace
import json

import pytest

from qsploit.groups import FFDHE2048_P, FFDHE2048_G, FFDHE2048_ORDER
from qsploit.models import (ExecutionOptions, FFDLogProblem, FFDLogSecret,
                            QSploitError, Recovery, RSAFactors, RSAProblem)
from qsploit.quantum import engine
from qsploit.jobs import verify_recovery


def public_problem(x=17):
    return FFDLogProblem(FFDHE2048_P, FFDHE2048_G, pow(FFDHE2048_G, x, FFDHE2048_P), FFDHE2048_ORDER)


@pytest.fixture
def registry(tmp_path, monkeypatch):
    problem = public_problem()
    path = tmp_path / "dlog.json"
    path.write_text(json.dumps({engine.dlog_registry_key(problem): {"x": "11"}}))
    monkeypatch.setattr(engine, "DLOG_FILE", path)
    return problem, path


def test_ff_contract_contains_only_public_mathematical_parameters():
    assert {f.name for f in fields(FFDLogProblem)} == {"p", "g", "y", "order", "kind"}
    assert {f.name for f in fields(FFDLogSecret)} == {"x"}
    assert "17" not in repr(FFDLogSecret(17))


def test_ff_exact_public_problem_automatic_scalar_return(registry, monkeypatch):
    problem, _ = registry
    delays, progress = [], []
    monkeypatch.setattr(engine.time, "sleep", delays.append)
    result = engine.recover(problem, ExecutionOptions("fixture"), progress.append)
    assert result.secret == FFDLogSecret(17)
    assert result.method == "fixture_lookup" and result.execution == "none"
    assert result.target is None and result.measurements == ()
    assert delays == [3.0]
    assert engine.has_known_recovery(problem)
    assert engine.timing_for(problem, ExecutionOptions("fixture", demo_delay_seconds=0)).seconds == 0
    assert [p.stage for p in progress] == ["matching_test_public_problem", "illustrative_demo_delay", "verifying_discrete_log"]
    verify_recovery(problem, result, ExecutionOptions("fixture"))
    with pytest.raises(TypeError):
        _ = result.factors


def test_ff_unknown_valid_share_is_honestly_unavailable(registry):
    unknown = public_problem(19)
    assert not engine.has_known_recovery(unknown)
    with pytest.raises(QSploitError) as exc:
        engine.recover(unknown, ExecutionOptions("fixture", demo_delay_seconds=0), lambda _: None)
    assert exc.value.code == "FIXTURE_NOT_FOUND"


@pytest.mark.parametrize("change", [
    {"p": 23}, {"p": True}, {"p": "p"}, {"g": 3}, {"g": 2.0},
    {"order": FFDHE2048_P - 1}, {"order": None},
    {"y": 0}, {"y": 1}, {"y": FFDHE2048_P - 1}, {"y": FFDHE2048_P - 2},
    {"y": True}, {"y": 4.0}, {"y": "4"}, {"kind": "rsa_factor"},
], ids=["foreign-p", "bool-p", "text-p", "foreign-g", "float-g", "wrong-order", "missing-order", "zero-y", "one-y", "p-minus1-y", "wrong-subgroup", "bool-y", "float-y", "text-y", "wrong-kind"])
def test_ff_rejects_wrong_problem_shape_and_subgroup(change):
    with pytest.raises(QSploitError):
        engine.validate_problem(replace(public_problem(), **change))


@pytest.mark.parametrize("secret", [FFDLogSecret(0), FFDLogSecret(-1), FFDLogSecret(18), FFDLogSecret(FFDHE2048_ORDER), FFDLogSecret(True), FFDLogSecret(17.0), FFDLogSecret("17"), RSAFactors(3, 5)],
                         ids=["zero", "negative", "wrong", "order", "bool", "float", "text", "rsa"])
def test_ff_verifies_returned_scalar_and_result_type(secret):
    with pytest.raises(QSploitError) as exc:
        engine.verify_secret(public_problem(), secret)
    assert exc.value.code == "INVALID_DLOG_RESULT"


def test_ff_invalid_registry_answer_fails_verification(registry):
    problem, path = registry
    path.write_text(json.dumps({engine.dlog_registry_key(problem): {"x": "12"}}))
    with pytest.raises(QSploitError) as exc:
        engine.known_secret(problem)
    assert exc.value.code == "INVALID_DLOG_RESULT"


@pytest.mark.parametrize("backend", ["aer", "ionq_simulator", "ionq_qpu"])
def test_ff_real_solver_explicitly_unsupported_no_fixture_fallback(backend, monkeypatch):
    monkeypatch.setattr(engine, "known_secret", lambda _: pytest.fail("fixture fallback"))
    monkeypatch.setattr(engine.time, "sleep", lambda _: pytest.fail("demo timer in real mode"))
    with pytest.raises(QSploitError) as exc:
        engine.recover(public_problem(), ExecutionOptions(backend), lambda _: None)
    assert exc.value.code == "UNSUPPORTED_PROBLEM"


@pytest.mark.parametrize("method,execution,backend", [
    ("fixture_lookup", "aer", "fixture"),
    ("fixture_lookup", "none", "aer"),
    ("classical_precheck", "none", "aer"),
    ("quantum_order_finding", "aer", "aer"),
])
def test_ff_parent_rejects_false_provenance(method, execution, backend):
    result = Recovery(FFDLogSecret(17), method, execution, None, ())
    with pytest.raises(QSploitError) as exc:
        verify_recovery(public_problem(), result, ExecutionOptions(backend))
    assert exc.value.code == "INVALID_PROVENANCE"


def test_rsa_and_ff_result_types_cannot_cross():
    with pytest.raises(QSploitError) as exc:
        engine.verify_secret(RSAProblem(15), FFDLogSecret(17))
    assert exc.value.code == "INVALID_FACTOR_PAIR"


def test_shipped_ff_registry_answers_match_all_public_parameters():
    entries = json.loads(engine.DLOG_FILE.read_text())
    assert entries
    for key in entries:
        problem = FFDLogProblem(*(int(component, 16) for component in key.split(":")))
        assert key == engine.dlog_registry_key(problem)
        secret = engine.known_secret(problem)
        engine.verify_secret(problem, secret)
