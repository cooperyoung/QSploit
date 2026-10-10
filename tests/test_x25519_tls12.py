"""X25519 genuine TLS captures, RFC 7748 vectors, and synthetic failure tests."""
import base64
from dataclasses import replace
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from qsploit.groups import X25519_FIELD, normalize_x25519_point, validate_x25519_point
from qsploit.models import ECDLogSecret, QSploitError, X25519Secret
from qsploit.pcap import read_connections
from qsploit.tls import _ecdhe_key_exchange, _hello, parse_tls, problem_for
from qsploit.tls12 import decrypt_tls12, derive_key_block, derive_master_secret, recover_premaster

FIXTURES = Path(__file__).parent / "fixtures"
REGISTRY = Path(__file__).parents[1] / "qsploit/demo/ec_dlog.json"
NAMES = [f"tls12-ecdhe-x25519-aes{bits}-{ems}" for bits in (128, 256) for ems in ("ems", "noems")]


def fixture(name=NAMES[0]):
    connection = read_connections((FIXTURES / f"{name}.pcap").read_bytes()).connections[0]
    expected = json.loads((FIXTURES / f"{name}.expected.json").read_text())
    entry = json.loads(REGISTRY.read_text())[expected["recovery_registry_key"]]
    return parse_tls(connection), X25519Secret(bytes.fromhex(entry["scalar"])), expected


def protected_indices(session, direction=None):
    active, indices = set(), []
    for i, record in enumerate(session.records):
        if record.content_type == 20:
            active.add(record.direction)
        elif record.direction in active and direction in (None, record.direction):
            indices.append(i)
    return indices


@pytest.mark.parametrize("name", NAMES)
def test_genuine_x25519_matches_keylogs_http_and_finished(name):
    session, secret, expected = fixture(name)
    assert not session.blockers and session.ecdhe.group == session.selected_group == 29
    assert session.kex == "ecdhe" and session.authentication == "RSA" and session.ems is expected["ems"]
    problem = problem_for(session)
    assert {"curve": problem.curve, "public_point": problem.public_point.hex()} == expected["public_problem"]
    assert derive_master_secret(session, secret).hex() == expected["master_secret_hex"]
    output = decrypt_tls12(session, secret)
    assert output.c2s == base64.b64decode(expected["c2s_base64"])
    assert output.s2c == base64.b64decode(expected["s2c_base64"])
    assert output.client_finished_verified and output.server_finished_verified
    assert output.authenticated_records == len(protected_indices(session)) == 19


def test_rfc7748_independent_vector_and_scalar_clamping():
    # RFC 7748 section 6.1, https://www.rfc-editor.org/rfc/rfc7748#section-6.1
    scalar = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    public = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    peer = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    expected = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    session, _, _ = fixture()
    changed = replace(session, ecdhe=replace(session.ecdhe, server_public=public, client_public=peer))
    assert recover_premaster(changed, X25519Secret(scalar)) == expected
    masked = bytearray(scalar)
    masked[0] ^= 7
    masked[31] ^= 0xc0  # all altered bits are overwritten by RFC scalar clamping
    assert recover_premaster(changed, X25519Secret(bytes(masked))) == expected
    with pytest.raises(QSploitError) as exc:
        recover_premaster(changed, X25519Secret(scalar[::-1]))
    assert exc.value.code == "INVALID_DLOG_RESULT"


def test_received_u_msb_masking_and_noncanonical_modulus_reduction():
    session, secret, _ = fixture()
    high_server = session.ecdhe.server_public[:-1] + bytes([session.ecdhe.server_public[-1] | 0x80])
    high_client = session.ecdhe.client_public[:-1] + bytes([session.ecdhe.client_public[-1] | 0x80])
    changed = replace(session, ecdhe=replace(session.ecdhe, server_public=high_server, client_public=high_client))
    assert problem_for(changed) == problem_for(session)
    assert recover_premaster(changed, secret) == recover_premaster(session, secret)
    # A clamped scalar congruent to -1 modulo the base-point order has public u=9.
    order = 2**252 + int("14def9dea2f79cd65812631a5cf5d3ed", 16)
    raw = (5 * order - 1).to_bytes(32, "little")
    public = x25519.X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert public == b"\x09" + bytes(31)
    noncanonical = (X25519_FIELD + 9).to_bytes(32, "little")
    changed = replace(session, ecdhe=replace(session.ecdhe, server_public=noncanonical, client_public=noncanonical))
    assert problem_for(changed).public_point == public
    assert recover_premaster(changed, X25519Secret(raw)) == public
    assert normalize_x25519_point(noncanonical) == public


@pytest.mark.parametrize("value", [0, 1, X25519_FIELD - 1, X25519_FIELD, X25519_FIELD + 1, 2**255])
def test_x25519_low_order_points_and_aliases_rejected(value):
    with pytest.raises(QSploitError) as exc:
        validate_x25519_point(value.to_bytes(32, "little"))
    assert exc.value.code == "INVALID_EC_PUBLIC"


@pytest.mark.parametrize("invalid", [b"", bytes(31), bytes(33), bytearray(32), 9])
def test_x25519_public_encoding_width_and_type(invalid):
    with pytest.raises(QSploitError) as exc:
        validate_x25519_point(invalid)
    assert exc.value.code == "INVALID_EC_PUBLIC"


@pytest.mark.parametrize("name", [NAMES[0], NAMES[2]])
def test_x25519_wrong_private_scalar_type_and_peer_fail_closed(name):
    session, secret, _ = fixture(name)
    for scalar in (b"", bytes(31), bytes(33), bytearray(32), secret.scalar[::-1]):
        with pytest.raises(QSploitError) as exc:
            decrypt_tls12(session, X25519Secret(scalar))
        assert exc.value.code == "INVALID_DLOG_RESULT"
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(session, ECDLogSecret(int.from_bytes(secret.scalar, "little")))
    assert exc.value.code == "INVALID_RECOVERY_RESULT"
    changed = replace(session, ecdhe=replace(session.ecdhe, client_public=b"\x09" + bytes(31)))
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(changed, secret)
    assert exc.value.code == "AEAD_AUTH_FAILED"
    for side in ("client_public", "server_public"):
        with pytest.raises(QSploitError) as exc:
            decrypt_tls12(replace(session, ecdhe=replace(session.ecdhe, **{side: bytes(32)})), secret)
        assert exc.value.code == "INVALID_EC_PUBLIC"


@pytest.mark.parametrize("name", [NAMES[0], NAMES[2]])
def test_each_x25519_record_authenticated(name):
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
def test_x25519_valid_tag_but_wrong_finished(name, direction):
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


@pytest.mark.parametrize("variant,code", [("signature", "SERVER_SIGNATURE_FAILED"), ("client_loworder", "INVALID_EC_PUBLIC"),
    ("server_loworder", "INVALID_EC_PUBLIC"), ("unoffered_group", "INVALID_TLS"), ("client_width", "INVALID_EC_PUBLIC"),
    ("empty_formats", "INVALID_TLS"), ("truncated_formats", "INCOMPLETE_HANDSHAKE")])
def test_x25519_parser_negatives(variant, code):
    session, _, _ = fixture()
    wires = {(h.direction, h.wire[0]): h.wire for h in session.clear_handshakes}
    ch, sh = _hello(wires["c2s", 1], True), _hello(wires["s2c", 2], False)
    fields = [wires["s2c", 12], wires["c2s", 16], wires["s2c", 11], ch["random"], sh["random"], ch["ext"], sh["ext"]]
    if variant == "signature":
        fields[0] = fields[0][:-1] + bytes([fields[0][-1] ^ 1])
    elif variant == "client_loworder":
        fields[1] = b"\x10\x00\x00\x21\x20" + bytes(32)
    elif variant == "server_loworder":
        fields[0] = fields[0][:8] + bytes(32) + fields[0][40:]
    elif variant == "unoffered_group":
        fields[5][10] = b"\x00\x02\x00\x17"
    elif variant == "client_width":
        fields[1] = b"\x10\x00\x00\x20\x1f" + bytes(31)
    elif variant == "empty_formats":
        fields[5][11] = b"\x00"
    else:
        fields[5][11] = b"\x02\x00"
    with pytest.raises(QSploitError) as exc:
        _ecdhe_key_exchange(*fields)
    assert exc.value.code == code
