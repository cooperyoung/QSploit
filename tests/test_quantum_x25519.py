"""X25519 recovery uses RFC 7748 private bytes, never a P-256 integer scalar."""
from dataclasses import fields, replace
import json

import pytest

from qsploit.groups import normalize_x25519_point
from qsploit.jobs import verify_recovery
from qsploit.models import (ECDLogProblem, ECDLogSecret, FFDLogSecret, RSAFactors,
                            X25519Secret, ExecutionOptions, QSploitError, Recovery)
from qsploit.quantum import engine

# Independent published vector: https://www.rfc-editor.org/rfc/rfc7748#section-6.1
ALICE_PRIVATE = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
ALICE_PUBLIC = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB_PUBLIC = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
PROBLEM = ECDLogProblem("x25519", ALICE_PUBLIC)
SECRET = X25519Secret(ALICE_PRIVATE)
FIELD_PRIME = 2**255 - 19


@pytest.fixture
def registry(tmp_path, monkeypatch):
    path = tmp_path / "ec_dlog.json"
    path.write_text(json.dumps({"x25519:" + ALICE_PUBLIC.hex(): {"scalar": ALICE_PRIVATE.hex()}}))
    monkeypatch.setattr(engine, "EC_DLOG_FILE", path)
    return path


def test_raw_private_contract_and_rfc7748_public_vector():
    assert {field.name for field in fields(X25519Secret)} == {"scalar"}
    assert repr(SECRET) == "X25519Secret()"
    engine.verify_secret(PROBLEM, SECRET)


def test_clamped_away_private_bits_are_equivalent():
    # Three low bits are cleared; top bit is cleared and bit254 is set.
    for low in range(8):
        for top in range(4):
            candidate = bytearray(ALICE_PRIVATE)
            candidate[0] = (candidate[0] & 248) | low
            candidate[31] = (candidate[31] & 63) | (top << 6)
            engine.verify_secret(PROBLEM, X25519Secret(bytes(candidate)))


@pytest.mark.parametrize("index,mask", [(0, 8), (10, 1), (31, 32)])
def test_meaningful_changed_private_bits_fail(index, mask):
    candidate = bytearray(ALICE_PRIVATE)
    candidate[index] ^= mask
    with pytest.raises(QSploitError) as exc:
        engine.verify_secret(PROBLEM, X25519Secret(bytes(candidate)))
    assert exc.value.code == "INVALID_DLOG_RESULT"


def test_rfc7748_public_encoding_normalization():
    top_bit = bytearray(ALICE_PUBLIC)
    top_bit[31] |= 128
    alternate = ECDLogProblem("x25519", bytes(top_bit))
    engine.verify_secret(alternate, SECRET)
    assert engine.ec_registry_key(alternate) == engine.ec_registry_key(PROBLEM)
    # A nonminimal field element must be reduced, after masking bit255.
    base = ECDLogProblem("x25519", (9).to_bytes(32, "little"))
    nonminimal = ECDLogProblem("x25519", (FIELD_PRIME + 9).to_bytes(32, "little"))
    assert engine.ec_registry_key(base) == engine.ec_registry_key(nonminimal)
    assert normalize_x25519_point(nonminimal.public_point) == base.public_point


@pytest.mark.parametrize("point", [b"", b"\x09", bytes(31), bytes(33), b"\x04" + bytes(64),
                                     "point", None, bytearray(32)])
def test_invalid_public_encoding_rejected(point):
    with pytest.raises(QSploitError) as exc:
        engine.validate_problem(ECDLogProblem("x25519", point))
    assert exc.value.code == "INVALID_EC_PUBLIC"


@pytest.mark.parametrize("u", [0, 1, FIELD_PRIME - 1, FIELD_PRIME, FIELD_PRIME + 1])
def test_low_order_and_equivalent_public_points_rejected(u):
    for mask in (0, 1 << 255):
        with pytest.raises(QSploitError) as exc:
            engine.validate_problem(ECDLogProblem("x25519", (u | mask).to_bytes(32, "little")))
        assert exc.value.code == "INVALID_EC_PUBLIC"


@pytest.mark.parametrize("secret", [ECDLogSecret(17), FFDLogSecret(17), RSAFactors(3, 5),
                                      X25519Secret(17), X25519Secret("00" * 32), X25519Secret(None),
                                      X25519Secret(bytearray(ALICE_PRIVATE)), X25519Secret(bytes(31)),
                                      X25519Secret(bytes(33))],
                         ids=["p256", "ff", "rsa", "int", "hex-text", "none", "bytearray", "short", "long"])
def test_wrong_result_type_or_private_encoding_rejected(secret):
    with pytest.raises(QSploitError) as exc:
        engine.verify_secret(PROBLEM, secret)
    assert exc.value.code == "INVALID_DLOG_RESULT"


@pytest.mark.parametrize("delay", [0, 1.25])
def test_automatic_registry_recovery_preserves_timing_and_provenance(registry, monkeypatch, delay):
    delays, progress = [], []
    monkeypatch.setattr(engine.time, "sleep", delays.append)
    result = engine.recover(PROBLEM, ExecutionOptions("fixture", demo_delay_seconds=delay), progress.append)
    assert result.secret == SECRET
    assert (result.method, result.execution, result.target, result.measurements) == ("fixture_lookup", "none", None, ())
    assert delays == [delay]
    assert progress[-1].stage == "verifying_discrete_log"
    verify_recovery(PROBLEM, result, ExecutionOptions("fixture"))


def test_masked_public_encoding_matches_same_registry_entry(registry):
    alternate = bytearray(ALICE_PUBLIC)
    alternate[31] |= 128
    assert engine.known_secret(replace(PROBLEM, public_point=bytes(alternate))) == SECRET


def test_unknown_share_honestly_unavailable(registry):
    unknown = replace(PROBLEM, public_point=BOB_PUBLIC)
    assert not engine.has_known_recovery(unknown)
    with pytest.raises(QSploitError) as exc:
        engine.known_secret(unknown)
    assert exc.value.code == "FIXTURE_NOT_FOUND"


@pytest.mark.parametrize("entry,code", [({"x": "11"}, "FIXTURE_INVALID"),
                                       ({"scalar": "zz"}, "FIXTURE_INVALID"),
                                       ({"scalar": "00"}, "INVALID_DLOG_RESULT"),
                                       ({"scalar": "00" * 32}, "INVALID_DLOG_RESULT")])
def test_malformed_or_wrong_fixture_cannot_succeed(registry, entry, code):
    registry.write_text(json.dumps({engine.ec_registry_key(PROBLEM): entry}))
    with pytest.raises(QSploitError) as exc:
        engine.known_secret(PROBLEM)
    assert exc.value.code == code


@pytest.mark.parametrize("backend", ["aer", "ionq_simulator", "ionq_qpu"])
def test_real_backend_no_fixture_or_delay(backend, monkeypatch):
    monkeypatch.setattr(engine, "known_secret", lambda _: pytest.fail("fixture fallback"))
    monkeypatch.setattr(engine.time, "sleep", lambda _: pytest.fail("real mode delay"))
    with pytest.raises(QSploitError) as exc:
        engine.recover(PROBLEM, ExecutionOptions(backend), lambda _: None)
    assert exc.value.code == "UNSUPPORTED_PROBLEM"


@pytest.mark.parametrize("method,execution,backend,target", [
    ("fixture_lookup", "aer", "fixture", None),
    ("fixture_lookup", "none", "aer", None),
    ("fixture_lookup", "none", "fixture", "imagined-hardware"),
    ("classical_precheck", "none", "aer", None),
    ("quantum_order_finding", "aer", "aer", None),
])
def test_parent_boundary_rejects_false_provenance(method, execution, backend, target):
    result = Recovery(SECRET, method, execution, target, ())
    with pytest.raises(QSploitError) as exc:
        verify_recovery(PROBLEM, result, ExecutionOptions(backend))
    assert exc.value.code == "INVALID_PROVENANCE"


def test_parent_rechecks_private_public_equation():
    result = Recovery(SECRET, "fixture_lookup", "none", None, ())
    with pytest.raises(QSploitError) as exc:
        verify_recovery(replace(PROBLEM, public_point=BOB_PUBLIC), result, ExecutionOptions("fixture"))
    assert exc.value.code == "INVALID_DLOG_RESULT"


def test_every_shipped_x25519_scalar_rederives_its_exact_public_share():
    entries = json.loads(engine.EC_DLOG_FILE.read_text())
    matching = {key: entry for key, entry in entries.items() if key.startswith("x25519:")}
    assert len(matching) >= 4
    for key in matching:
        problem = ECDLogProblem("x25519", bytes.fromhex(key.split(":", 1)[1]))
        assert key == engine.ec_registry_key(problem)
        secret = engine.known_secret(problem)
        assert isinstance(secret, X25519Secret)
        engine.verify_secret(problem, secret)
