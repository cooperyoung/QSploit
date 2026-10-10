"""P-256 TLS captures have independent endpoint oracles; mutations are synthetic."""
import base64
from dataclasses import replace
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from qsploit.groups import P256_ORDER, validate_p256_point
from qsploit.models import ECDLogProblem, ECDLogSecret, FFDLogSecret, QSploitError
from qsploit.pcap import read_connections
from qsploit.tls import _ecdhe_key_exchange, _hello, parse_tls, problem_for
from qsploit.tls12 import decrypt_tls12, derive_key_block, derive_master_secret, recover_premaster

FIXTURES = Path(__file__).parent / "fixtures"
REGISTRY = Path(__file__).parents[1] / "qsploit/demo/ec_dlog.json"
NAMES = [f"tls12-ecdhe-p256-aes{bits}-{ems}" for bits in (128, 256) for ems in ("ems", "noems")]


def fixture(name=NAMES[0]):
    connection = read_connections((FIXTURES / f"{name}.pcap").read_bytes()).connections[0]
    expected = json.loads((FIXTURES / f"{name}.expected.json").read_text())
    entry = json.loads(REGISTRY.read_text())[expected["recovery_registry_key"]]
    return parse_tls(connection), ECDLogSecret(int(entry["x"], 16)), expected


def point(scalar):
    return ec.derive_private_key(scalar, ec.SECP256R1()).public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def protected_indices(session, direction=None):
    active, indices = set(), []
    for i, record in enumerate(session.records):
        if record.content_type == 20:
            active.add(record.direction)
        elif record.direction in active and direction in (None, record.direction):
            indices.append(i)
    return indices


@pytest.mark.parametrize("name", NAMES)
def test_genuine_p256_matches_independent_masters_http_and_finished(name):
    session, secret, expected = fixture(name)
    assert session.blockers == () and session.rsa is None and session.dhe is None
    assert session.kex == "ecdhe" and session.authentication == "RSA" and session.selected_group == 23
    assert session.ems is expected["ems"]
    problem = problem_for(session)
    assert isinstance(problem, ECDLogProblem)
    assert {"curve": problem.curve, "public_point": problem.public_point.hex()} == expected["public_problem"]
    assert problem.public_point == session.ecdhe.server_public
    assert derive_master_secret(session, secret).hex() == expected["master_secret_hex"]
    output = decrypt_tls12(session, secret)
    assert output.c2s == base64.b64decode(expected["c2s_base64"])
    assert output.s2c == base64.b64decode(expected["s2c_base64"])
    assert output.client_finished_verified and output.server_finished_verified
    assert output.authenticated_records == len(protected_indices(session))


@pytest.mark.parametrize("invalid", [b"", b"\x00", b"\x04" + bytes(64), b"\x04" + b"\xff" * 64, b"\x02" + bytes(32), bytes(65), bytearray(65)])
def test_p256_invalid_infinite_compressed_or_offcurve_points_rejected(invalid):
    with pytest.raises(QSploitError) as exc:
        validate_p256_point(invalid)
    assert exc.value.code == "INVALID_EC_PUBLIC"


def test_p256_premaster_retains_leading_zero_bytes():
    session, _, _ = fixture()
    # Synthetic vector: server scalar one; peer scalar 379 has x starting 00.
    peer = bytes.fromhex("04005543894af3d00ed7d740abdbd75c96b06877b787db5f70eea78b90a8d7c00abb4c85a3d8ea29efaafa24406912dd84d5b14dc32bf656ef6c6bd58a5d943f92")
    assert peer == point(379)
    changed = replace(session, ecdhe=replace(session.ecdhe, server_public=point(1), client_public=peer))
    premaster = recover_premaster(changed, ECDLogSecret(1))
    assert premaster == peer[1:33] and len(premaster) == 32 and premaster[0] == 0


@pytest.mark.parametrize("name", [NAMES[0], NAMES[2]])
def test_wrong_scalar_result_type_peer_and_group_fail_closed(name):
    session, secret, _ = fixture(name)
    for scalar in (0, -1, P256_ORDER, True, secret.x + 1):
        with pytest.raises(QSploitError) as exc:
            decrypt_tls12(session, ECDLogSecret(scalar))
        assert exc.value.code == "INVALID_DLOG_RESULT"
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(session, FFDLogSecret(secret.x))
    assert exc.value.code == "INVALID_RECOVERY_RESULT"
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(replace(session, ecdhe=replace(session.ecdhe, client_public=point(7))), secret)
    assert exc.value.code == "AEAD_AUTH_FAILED"
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(replace(session, ecdhe=replace(session.ecdhe, group=24)), secret)
    assert exc.value.code == "UNSUPPORTED_GROUP"


@pytest.mark.parametrize("name", [NAMES[0], NAMES[2]])
def test_each_ecdhe_protected_record_authenticates(name):
    session, secret, _ = fixture(name)
    for index in protected_indices(session):
        records = list(session.records)
        fragment = records[index].fragment
        records[index] = replace(records[index], fragment=fragment[:-1] + bytes([fragment[-1] ^ 1]))
        with pytest.raises(QSploitError) as exc:
            decrypt_tls12(replace(session, records=tuple(records)), secret)
        assert exc.value.code == "AEAD_AUTH_FAILED"


@pytest.mark.parametrize("name", [NAMES[0], NAMES[2]])
@pytest.mark.parametrize("direction", ["c2s", "s2c"])
def test_p256_wrong_finished_with_valid_gcm_tag_rejected(name, direction):
    session, secret, _ = fixture(name)
    block = derive_key_block(derive_master_secret(session, secret), session.client_random, session.server_random, session.cipher_suite)
    key_length = 16 if session.cipher_suite == 0xc02f else 32
    side = 0 if direction == "c2s" else 1
    cipher = AESGCM(block[side * key_length:(side + 1) * key_length])
    salt = block[2 * key_length + 4 * side:2 * key_length + 4 * side + 4]
    records = list(session.records)
    index = protected_indices(session, direction)[0]
    record = records[index]
    nonce = salt + record.fragment[:8]
    aad = bytes(8) + bytes([22]) + b"\x03\x03" + (len(record.fragment) - 24).to_bytes(2, "big")
    plaintext = cipher.decrypt(nonce, record.fragment[8:], aad)
    assert plaintext[:4] == b"\x14\x00\x00\x0c"
    changed = plaintext[:-1] + bytes([plaintext[-1] ^ 1])
    records[index] = replace(record, fragment=record.fragment[:8] + cipher.encrypt(nonce, changed, aad))
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(replace(session, records=tuple(records)), secret)
    assert exc.value.code == "FINISHED_VERIFY_FAILED"


@pytest.mark.parametrize("variant,code", [("signature", "SERVER_SIGNATURE_FAILED"), ("random", "SERVER_SIGNATURE_FAILED"),
    ("unoffered_group", "INVALID_TLS"), ("unsupported_group", "UNSUPPORTED_GROUP"), ("explicit_curve", "UNSUPPORTED_GROUP"),
    ("client_offcurve", "INVALID_EC_PUBLIC"), ("server_offcurve", "INVALID_EC_PUBLIC"),
    ("client_formats", "UNSUPPORTED_POINT_FORMAT"), ("server_formats", "UNSUPPORTED_POINT_FORMAT"),
    ("unoffered_formats", "INVALID_TLS"), ("client_trailing", "INVALID_TLS"), ("signature_truncated", "INCOMPLETE_HANDSHAKE")])
def test_ecdhe_ske_params_signature_and_negotiation_failures(variant, code):
    session, _, _ = fixture()
    wires = {(h.direction, h.wire[0]): h.wire for h in session.clear_handshakes}
    ch, sh = _hello(wires["c2s", 1], True), _hello(wires["s2c", 2], False)
    fields = [wires["s2c", 12], wires["c2s", 16], wires["s2c", 11], ch["random"], sh["random"], ch["ext"], sh["ext"]]
    if variant == "signature":
        fields[0] = fields[0][:-1] + bytes([fields[0][-1] ^ 1])
    elif variant == "random":
        fields[3] = b"x" * 32
    elif variant == "unoffered_group":
        fields[5][10] = b"\x00\x02\x00\x18"
    elif variant == "unsupported_group":
        fields[0] = fields[0][:5] + b"\x00\x18" + fields[0][7:]
    elif variant == "explicit_curve":
        fields[0] = fields[0][:4] + b"\x01" + fields[0][5:]
    elif variant == "client_offcurve":
        fields[1] = b"\x10\x00\x00\x42\x41\x04" + bytes(64)
    elif variant == "server_offcurve":
        fields[0] = fields[0][:8] + b"\x04" + bytes(64) + fields[0][73:]
    elif variant == "client_formats":
        fields[5][11] = b"\x01\x01"
    elif variant == "server_formats":
        fields[6][11] = b"\x01\x01"
    elif variant == "unoffered_formats":
        fields[5].pop(11, None)
        fields[6][11] = b"\x01\x00"
    elif variant == "client_trailing":
        fields[1] += b"x"
    else:
        fields[0] = fields[0][:-1]
    with pytest.raises(QSploitError) as exc:
        _ecdhe_key_exchange(*fields)
    assert exc.value.code == code
