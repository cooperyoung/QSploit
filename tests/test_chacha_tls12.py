"""Genuine DHE/ECDHE ChaCha TLS 1.2 captures; mutations are synthetic."""
import base64
from dataclasses import replace
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import pytest

from qsploit.models import ECDLogSecret, FFDLogSecret, QSploitError, X25519Secret
from qsploit.pcap import read_connections
from qsploit.tls import _ecdhe_key_exchange, _hello, parse_tls
from qsploit.tls12 import decrypt_record, decrypt_tls12, derive_key_block, derive_master_secret

ROOT = Path(__file__).parents[1]
NAMES = ["tls12-dhe-chacha-ems", "tls12-dhe-chacha-noems", "tls12-ecdhe-p256-chacha-ems", "tls12-ecdhe-p256-chacha-noems",
         "tls12-ecdhe-x25519-chacha-ems", "tls12-ecdhe-x25519-chacha-noems"]


def fixture(name):
    path = ROOT / "tests/fixtures" / name
    session = parse_tls(read_connections(path.with_suffix(".pcap").read_bytes()).connections[0])
    expected = json.loads(path.with_suffix(".expected.json").read_text())
    registry_file = "dlog.json" if session.kex == "dhe" else "ec_dlog.json"
    registry = json.loads((ROOT / "qsploit/demo" / registry_file).read_text())
    entry = registry[expected["recovery_registry_key"]]
    if "scalar" in entry:
        secret = X25519Secret(bytes.fromhex(entry["scalar"]))
    else:
        scalar = int(entry["x"], 16)
        secret = FFDLogSecret(scalar) if session.kex == "dhe" else ECDLogSecret(scalar)
    return session, secret, expected


def protected_indices(session, direction=None):
    active, indices = set(), []
    for i, record in enumerate(session.records):
        if record.content_type == 20:
            active.add(record.direction)
        elif record.direction in active and direction in (None, record.direction):
            indices.append(i)
    return indices


def traffic(session, secret, direction):
    master = derive_master_secret(session, secret)
    block = derive_key_block(master, session.client_random, session.server_random, session.cipher_suite)
    assert len(block) == 88
    return (block[:32], block[64:76]) if direction == "c2s" else (block[32:64], block[76:88])


def encrypt(record, key, iv, seq, plaintext):
    nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
    aad = seq.to_bytes(8, "big") + bytes([record.content_type]) + record.version.to_bytes(2, "big") + len(plaintext).to_bytes(2, "big")
    return replace(record, fragment=ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad))


@pytest.mark.parametrize("name", NAMES)
def test_genuine_chacha_matches_independent_endpoint_oracles(name):
    session, secret, expected = fixture(name)
    assert not session.blockers and session.cipher_suite == (0xccaa if session.kex == "dhe" else 0xcca8)
    assert session.ems is expected["ems"]
    assert derive_master_secret(session, secret).hex() == expected["master_secret_hex"]
    output = decrypt_tls12(session, secret)
    assert output.c2s == base64.b64decode(expected["c2s_base64"])
    assert output.s2c == base64.b64decode(expected["s2c_base64"])
    assert output.client_finished_verified and output.server_finished_verified
    assert output.authenticated_records == 19


@pytest.mark.parametrize("name", NAMES)
def test_every_chacha_record_authenticates(name):
    session, secret, _ = fixture(name)
    for index in protected_indices(session):
        records = list(session.records)
        fragment = records[index].fragment
        records[index] = replace(records[index], fragment=fragment[:-1] + bytes([fragment[-1] ^ 1]))
        with pytest.raises(QSploitError) as exc:
            decrypt_tls12(replace(session, records=tuple(records)), secret)
        assert exc.value.code == "AEAD_AUTH_FAILED"


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("direction", ["c2s", "s2c"])
def test_valid_chacha_tag_with_wrong_finished_rejected(name, direction):
    session, secret, _ = fixture(name)
    key, iv = traffic(session, secret, direction)
    records = list(session.records)
    index = protected_indices(session, direction)[0]
    plaintext = decrypt_record(records[index], key, iv, 0, session.cipher_suite)
    assert plaintext[:4] == b"\x14\x00\x00\x0c"
    changed = plaintext[:-1] + bytes([plaintext[-1] ^ 1])
    records[index] = encrypt(records[index], key, iv, 0, changed)
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(replace(session, records=tuple(records)), secret)
    assert exc.value.code == "FINISHED_VERIFY_FAILED"


@pytest.mark.parametrize("direction", ["c2s", "s2c"])
@pytest.mark.parametrize("name", [NAMES[0], NAMES[2], NAMES[4]])
def test_split_chacha_finished_updates_implicit_record_nonces(direction, name):
    session, secret, expected = fixture(name)
    key, iv = traffic(session, secret, direction)
    indices = protected_indices(session, direction)
    changed = []
    for index, record in enumerate(session.records):
        if index not in indices:
            changed.append(record)
            continue
        seq = indices.index(index)
        plaintext = decrypt_record(record, key, iv, seq, session.cipher_suite)
        if seq == 0:
            changed.extend([encrypt(record, key, iv, 0, plaintext[:7]), encrypt(record, key, iv, 1, plaintext[7:])])
        else:
            changed.append(encrypt(record, key, iv, seq + 1, plaintext))
    output = decrypt_tls12(replace(session, records=tuple(changed)), secret)
    assert output.c2s == base64.b64decode(expected["c2s_base64"])
    assert output.s2c == base64.b64decode(expected["s2c_base64"])
    assert output.authenticated_records == 20


@pytest.mark.parametrize("name", NAMES[2:])
def test_ecdhe_chacha_signature_binds_server_parameters(name):
    session, _, _ = fixture(name)
    wires = {(h.direction, h.wire[0]): h.wire for h in session.clear_handshakes}
    client, server = _hello(wires["c2s", 1], True), _hello(wires["s2c", 2], False)
    signed = wires["s2c", 12]
    altered = signed[:-1] + bytes([signed[-1] ^ 1])
    with pytest.raises(QSploitError) as exc:
        _ecdhe_key_exchange(altered, wires["c2s", 16], wires["s2c", 11], client["random"], server["random"], client["ext"], server["ext"])
    assert exc.value.code == "SERVER_SIGNATURE_FAILED"
