"""Real OpenSSL captures + independently recorded endpoint bytes/keylog oracles.

Mutation vectors are deliberately synthetic and are not demonstration captures.
"""
import base64
from dataclasses import replace
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

from qsploit.models import Handshake, QSploitError, RSAFactors, Record
from qsploit.pcap import read_connections
from qsploit.tls import parse_tls, problem_for
from qsploit.tls12 import _transcript, decrypt_tls12, derive_key_block, derive_master_secret, prf

FIXTURES = Path(__file__).parent / "fixtures"
FACTORS = Path(__file__).parents[1] / "qsploit/demo/factors.json"


def fixture(name="tls12-rsa-ems"):
    capture = read_connections((FIXTURES / (name + ".pcap")).read_bytes())
    session = parse_tls(capture.connections[0])
    expected = json.loads((FIXTURES / (name + ".expected.json")).read_text())
    entry = json.loads(FACTORS.read_text())[format(session.rsa.n, "x")]
    factors = RSAFactors(int(entry["p"], 16), int(entry["q"], 16))
    return session, factors, expected


def crypto_context(session, factors, direction):
    master = derive_master_secret(session, factors)
    block = derive_key_block(master, session.client_random, session.server_random)
    return (AESGCM(block[:16]), block[32:36]) if direction == "c2s" else (AESGCM(block[16:32]), block[36:40])


def unprotect(record, sequence, cipher, salt):
    length = len(record.fragment) - 24
    aad = sequence.to_bytes(8, "big") + bytes([record.content_type]) + record.version.to_bytes(2, "big") + length.to_bytes(2, "big")
    return cipher.decrypt(salt + record.fragment[:8], record.fragment[8:], aad)


def protect(record, plaintext, sequence, cipher, salt, nonce=None):
    nonce = record.fragment[:8] if nonce is None else nonce
    aad = sequence.to_bytes(8, "big") + bytes([record.content_type]) + record.version.to_bytes(2, "big") + len(plaintext).to_bytes(2, "big")
    return replace(record, fragment=nonce + cipher.encrypt(salt + nonce, plaintext, aad))


def protected_indices(session, direction=None):
    active = {"c2s": False, "s2c": False}
    output = []
    for index, record in enumerate(session.records):
        if record.content_type == 20:
            active[record.direction] = True
        elif active[record.direction] and (direction is None or record.direction == direction):
            output.append(index)
    return output


@pytest.mark.parametrize("name,ems", [("tls12-rsa-ems", True), ("tls12-rsa-noems", False), ("tls12-rsa-ticket", True)])
def test_genuine_tls_end_to_end_matches_independent_oracles(name, ems):
    session, factors, expected = fixture(name)
    assert not session.blockers and session.ems is ems
    assert problem_for(session).n == int(expected["rsa_modulus_hex"], 16)
    assert derive_master_secret(session, factors).hex() == expected["master_secret_hex"]
    result = decrypt_tls12(session, factors)
    assert result.c2s == base64.b64decode(expected["c2s_base64"])
    assert result.s2c == base64.b64decode(expected["s2c_base64"])
    assert result.client_finished_verified and result.server_finished_verified
    assert result.client_close_notify and result.server_close_notify
    assert result.authenticated_records == 19
    assert len(derive_key_block(bytes.fromhex(expected["master_secret_hex"]), session.client_random, session.server_random)) == 40


def test_wrong_and_equal_factors_rejected():
    session, factors, _ = fixture()
    for invalid in (RSAFactors(factors.p + 2, factors.q), RSAFactors(1, session.rsa.n), RSAFactors(factors.p, factors.p)):
        with pytest.raises(QSploitError) as exc:
            decrypt_tls12(session, invalid)
        assert exc.value.code == "INVALID_FACTOR_PAIR"


def test_composite_factors_and_invalid_exponent_rejected_by_validated_rsa_key():
    session, factors, _ = fixture()
    composite = RSAFactors(3 * factors.p, factors.q)
    changed = replace(session, rsa=replace(session.rsa, n=composite.p * composite.q))
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(changed, composite)
    assert exc.value.code == "INVALID_RSA_KEY"
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(replace(session, rsa=replace(session.rsa, e=2)), factors)
    assert exc.value.code == "INVALID_RSA_KEY"


@pytest.mark.parametrize("variant", ["width", "range", "garbage", "premaster_length", "premaster_version"])
def test_invalid_rsa_ciphertext_and_premaster(variant):
    session, factors, _ = fixture()
    if variant == "width":
        encrypted = session.rsa.encrypted_premaster[:-1]
    elif variant == "range":
        encrypted = session.rsa.n.to_bytes(256, "big")
    elif variant == "garbage":
        encrypted = b"\x00" * 256
    else:
        public = rsa.RSAPublicNumbers(session.rsa.e, session.rsa.n).public_key()
        data = b"\x03\x03" + b"x" * 45 if variant == "premaster_length" else b"\x03\x02" + b"x" * 46
        encrypted = public.encrypt(data, padding.PKCS1v15())
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(replace(session, rsa=replace(session.rsa, encrypted_premaster=encrypted)), factors)
    assert exc.value.code == "INVALID_PREMASTER"


@pytest.mark.parametrize("which", ["ems", "randoms"])
def test_wrong_schedule_never_tries_another_schedule(which):
    session, factors, _ = fixture()
    changed = replace(session, ems=False) if which == "ems" else replace(session, client_random=session.server_random, server_random=session.client_random)
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(changed, factors)
    assert exc.value.code == "AEAD_AUTH_FAILED"


def test_every_protected_record_is_authenticated_including_alerts():
    session, factors, _ = fixture()
    for index in protected_indices(session):
        records = list(session.records)
        record = records[index]
        records[index] = replace(record, fragment=record.fragment[:-1] + bytes([record.fragment[-1] ^ 1]))
        with pytest.raises(QSploitError) as exc:
            decrypt_tls12(replace(session, records=tuple(records)), factors)
        assert exc.value.code == "AEAD_AUTH_FAILED"


@pytest.mark.parametrize("direction", ["c2s", "s2c"])
def test_valid_aead_but_wrong_finished_is_rejected(direction):
    session, factors, _ = fixture()
    cipher, salt = crypto_context(session, factors, direction)
    index = protected_indices(session, direction)[0]
    records = list(session.records)
    plaintext = unprotect(records[index], 0, cipher, salt)
    assert plaintext[0] == 20
    altered = plaintext[:-1] + bytes([plaintext[-1] ^ 1])
    records[index] = protect(records[index], altered, 0, cipher, salt)
    assert unprotect(records[index], 0, cipher, salt) == altered
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(replace(session, records=tuple(records)), factors)
    assert exc.value.code == "FINISHED_VERIFY_FAILED"


@pytest.mark.parametrize("direction", ["c2s", "s2c"])
def test_split_finished_and_nonce_independent_of_sequence(direction):
    session, factors, expected = fixture()
    cipher, salt = crypto_context(session, factors, direction)
    indices = protected_indices(session, direction)
    first = indices[0]
    plain = unprotect(session.records[first], 0, cipher, salt)
    transformed = []
    for index, record in enumerate(session.records):
        if index not in indices:
            transformed.append(record)
            continue
        original_sequence = indices.index(index)
        plaintext = unprotect(record, original_sequence, cipher, salt)
        if index == first:
            transformed.extend((protect(record, plain[:7], 0, cipher, salt, b"SPLIT001"),
                                protect(record, plain[7:], 1, cipher, salt, b"SPLIT002")))
        else:
            sequence = original_sequence + 1
            transformed.append(protect(record, plaintext, sequence, cipher, salt, (1000 + sequence).to_bytes(8, "big")))
    output = decrypt_tls12(replace(session, records=tuple(transformed)), factors)
    assert output.authenticated_records == 20
    assert output.c2s == base64.b64decode(expected["c2s_base64"])
    assert output.s2c == base64.b64decode(expected["s2c_base64"])


def test_synthetic_new_session_ticket_contributes_after_client_finished():
    session, factors, expected = fixture()
    master = derive_master_secret(session, factors)
    transcript, _ = _transcript(session)
    client_cipher, client_salt = crypto_context(session, factors, "c2s")
    server_cipher, server_salt = crypto_context(session, factors, "s2c")
    client_finished = unprotect(session.records[protected_indices(session, "c2s")[0]], 0, client_cipher, client_salt)
    ticket_body = (300).to_bytes(4, "big") + b"\x00\x04test"
    ticket = b"\x04" + len(ticket_body).to_bytes(3, "big") + ticket_body
    server_finished = b"\x14\x00\x00\x0c" + prf(master, b"server finished", hashlib.sha256(transcript + client_finished + ticket).digest(), 12)
    index = protected_indices(session, "s2c")[0]
    records = list(session.records)
    records[index] = protect(records[index], server_finished, 0, server_cipher, server_salt)
    ccs_index = next(i for i, r in enumerate(records) if r.direction == "s2c" and r.content_type == 20)
    records.insert(ccs_index, Record("s2c", records[ccs_index].offset, 22, 0x0303, ticket))
    modified = replace(session, records=tuple(records), clear_handshakes=session.clear_handshakes + (Handshake("s2c", 0, ticket),))
    assert derive_master_secret(modified, factors) == master  # ticket not in EMS boundary
    output = decrypt_tls12(modified, factors)
    assert output.s2c == base64.b64decode(expected["s2c_base64"])
    assert output.server_finished_verified
    # Leaving the old server Finished has a valid tag but the wrong transcript.
    records[index + 1] = session.records[index]
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(replace(modified, records=tuple(records)), factors)
    assert exc.value.code == "FINISHED_VERIFY_FAILED"


def test_cleartext_flight_timestamp_order_is_irrelevant():
    session, factors, expected = fixture()
    reordered = tuple(h for h in session.clear_handshakes if h.direction == "s2c") + tuple(h for h in session.clear_handshakes if h.direction == "c2s")
    assert decrypt_tls12(replace(session, clear_handshakes=reordered), factors).c2s == base64.b64decode(expected["c2s_base64"])


@pytest.mark.parametrize("code", ["TCP_GAP", "TCP_OVERLAP_CONFLICT", "AMBIGUOUS_CONNECTION", "CLIENT_AUTH_UNSUPPORTED", "RENEGOTIATION_UNSUPPORTED"])
def test_capture_and_protocol_blockers_prevent_recovery(code):
    session, factors, _ = fixture()
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(replace(session, blockers=(code,)), factors)
    assert exc.value.code == code


def test_missing_finished_and_repeated_ccs_rejected():
    session, factors, _ = fixture()
    indices = protected_indices(session, "s2c")
    changed = replace(session, records=tuple(r for i, r in enumerate(session.records) if i not in indices))
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(changed, factors)
    assert exc.value.code == "INCOMPLETE_HANDSHAKE"
    ccs = next(r for r in session.records if r.direction == "c2s" and r.content_type == 20)
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(replace(session, records=session.records + (ccs,)), factors)
    assert exc.value.code == "RENEGOTIATION_UNSUPPORTED"


def test_prf_public_test_vector():
    # Published TLS 1.2 SHA-256 PRF vector (IETF TLS list, 2008-10-21).
    output = prf(bytes.fromhex("9bbe436ba940f017b17652849a71db35"), b"test label",
                 bytes.fromhex("a0ba9f936cda311827a6f796ffd5198c"), 100)
    assert output.hex() == ("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a"
                            "6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab"
                            "4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701"
                            "87347b66")
