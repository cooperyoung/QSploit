"""Independent RFC 8448 section 3 answers for the shared TLS 1.3 schedule.

These published X25519-derived bytes test HKDF and record protection directly;
they do not enable another capture-parser curve or supply runtime TLS secrets.
https://www.rfc-editor.org/rfc/rfc8448#section-3
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qsploit.models import QSploitError, Record
from qsploit.tls13 import (hkdf_extract, hkdf_expand_label, derive_secret,
                           traffic_key_iv, finished_verify_data, decrypt_record,
                           handshake_secrets)


_PUBLISHED = json.loads((Path(__file__).parent / "fixtures" / "rfc8448-simple-handshake.json").read_text())
V = {name: bytes.fromhex(value) for name, value in _PUBLISHED.items() if name not in {"source", "description"}}
HELLOS = V["client_hello"] + V["server_hello"]
THROUGH_SERVER_FINISHED = HELLOS + V["server_handshake_payload"]
THROUGH_CLIENT_FINISHED = THROUGH_SERVER_FINISHED + V["client_finished"]


def record(name):
    wire = V[name]
    assert len(wire) == 5 + int.from_bytes(wire[3:5], "big")
    return Record("s2c" if name.startswith(("server", "new_session")) else "c2s",
                  0, wire[0], int.from_bytes(wire[1:3], "big"), wire[5:])


def test_published_transcript_boundaries_include_handshake_headers_only():
    assert hashlib.sha256(HELLOS).digest() == V["hello_transcript_hash"]
    assert hashlib.sha256(THROUGH_SERVER_FINISHED).digest() == V["server_finished_transcript_hash"]
    assert hashlib.sha256(THROUGH_CLIENT_FINISHED).digest() == V["client_finished_transcript_hash"]


def test_published_extract_and_derived_schedule_with_absent_psk():
    early = hkdf_extract(bytes(32), bytes(32))
    assert early == V["early_secret"]
    derived = derive_secret(early, "derived", b"")
    assert derived == V["early_derived"]
    # Derive-Secret hashes empty messages; an empty ExpandLabel context differs.
    assert hkdf_expand_label(early, "derived", b"", 32) != derived
    handshake = hkdf_extract(derived, V["shared_secret"])
    assert handshake == V["handshake_secret"]
    handshake_derived = derive_secret(handshake, "derived", b"")
    assert handshake_derived == V["handshake_derived"]
    assert hkdf_extract(handshake_derived, bytes(32)) == V["master_secret"]
    assert hkdf_extract(handshake_derived, b"") != V["master_secret"]


def test_handshake_schedule_wrapper_matches_all_published_outputs():
    assert handshake_secrets(V["shared_secret"], HELLOS) == (
        V["client_handshake_secret"], V["server_handshake_secret"], V["master_secret"])


@pytest.mark.parametrize("label,expected", [("c hs traffic", "client_handshake_secret"),
                                           ("s hs traffic", "server_handshake_secret")])
def test_published_handshake_traffic_secrets(label, expected):
    assert derive_secret(V["handshake_secret"], label, HELLOS) == V[expected]


@pytest.mark.parametrize("label,expected", [("c ap traffic", "client_application_secret"),
                                           ("s ap traffic", "server_application_secret"),
                                           ("exp master", "exporter_master_secret")])
def test_published_application_secrets_end_at_server_finished(label, expected):
    assert derive_secret(V["master_secret"], label, THROUGH_SERVER_FINISHED) == V[expected]
    assert derive_secret(V["master_secret"], label, THROUGH_CLIENT_FINISHED) != V[expected]


def test_published_resumption_secret_ends_at_client_finished():
    assert derive_secret(V["master_secret"], "res master", THROUGH_CLIENT_FINISHED) == V["resumption_master_secret"]


@pytest.mark.parametrize("side,transcript", [("server", THROUGH_SERVER_FINISHED[:-36]),
                                            ("client", THROUGH_SERVER_FINISHED)])
def test_published_finished_keys_and_authentication(side, transcript):
    secret = V[side + "_handshake_secret"]
    assert hkdf_expand_label(secret, "finished", b"", 32) == V[side + "_finished_key"]
    assert finished_verify_data(secret, transcript) == V[side + "_finished"][4:]
    assert finished_verify_data(secret, transcript + V[side + "_finished"]) != V[side + "_finished"][4:]


@pytest.mark.parametrize("epoch", ["client_handshake", "server_handshake", "client_application", "server_application"])
def test_published_traffic_key_and_iv(epoch):
    assert traffic_key_iv(V[epoch + "_secret"]) == (V[epoch + "_key"], V[epoch + "_iv"])


@pytest.mark.parametrize("wire,secret,sequence,content_type,plaintext", [
    ("server_handshake_record", "server_handshake_secret", 0, 22, "server_handshake_payload"),
    ("client_finished_record", "client_handshake_secret", 0, 22, "client_finished"),
    ("new_session_ticket_record", "server_application_secret", 0, 22, "new_session_ticket"),
    ("client_application_record", "client_application_secret", 0, 23, "client_application_plaintext"),
    ("server_application_record", "server_application_secret", 1, 23, "server_application_plaintext"),
    ("client_alert_record", "client_application_secret", 1, 21, "client_alert_plaintext"),
    ("server_alert_record", "server_application_secret", 2, 21, "server_alert_plaintext"),
])
def test_published_records_authenticate_with_separate_direction_and_epoch_sequences(wire, secret, sequence, content_type, plaintext):
    assert decrypt_record(record(wire), V[secret], sequence) == (content_type, V[plaintext])


@pytest.mark.parametrize("mutation", ["ciphertext", "tag", "version", "outer_type", "sequence", "wrong_direction"])
def test_published_record_tampering_never_returns_plaintext(mutation):
    value = record("client_application_record")
    secret, sequence = V["client_application_secret"], 0
    if mutation in {"ciphertext", "tag"}:
        fragment = bytearray(value.fragment)
        fragment[0 if mutation == "ciphertext" else -1] ^= 1
        value = replace(value, fragment=bytes(fragment))
    elif mutation == "version":
        value = replace(value, version=0x0302)
    elif mutation == "outer_type":
        value = replace(value, content_type=22)
    elif mutation == "sequence":
        sequence = 1
    else:
        secret = V["server_application_secret"]
    with pytest.raises(QSploitError):
        decrypt_record(value, secret, sequence)


def protected_inner(inner):
    # Deliberately independent AESGCM construction using published key/IV.
    length = len(inner) + 16
    header = bytes.fromhex("170303") + length.to_bytes(2, "big")
    encrypted = AESGCM(V["client_application_key"]).encrypt(V["client_application_iv"], inner, header)
    return Record("c2s", 0, 23, 0x0303, encrypted)


@pytest.mark.parametrize("padding", [0, 1, 37])
def test_inner_padding_removed_after_tag_verification_without_trimming_content(padding):
    content = b"response contains a trailing nul\x00"
    value = protected_inner(content + b"\x17" + bytes(padding))
    assert decrypt_record(value, V["client_application_secret"], 0) == (23, content)


def test_empty_application_content_is_valid_with_inner_type():
    assert decrypt_record(protected_inner(b"\x17\x00\x00"), V["client_application_secret"], 0) == (23, b"")


def test_record_limit_includes_content_type_and_padding():
    maximum = protected_inner(b"\x17" + bytes(16384))
    assert decrypt_record(maximum, V["client_application_secret"], 0) == (23, b"")
    excessive = protected_inner(b"\x17" + bytes(16385))
    with pytest.raises(QSploitError):
        decrypt_record(excessive, V["client_application_secret"], 0)


@pytest.mark.parametrize("sequence", [-1, 2**64])
def test_sequence_number_never_wraps(sequence):
    with pytest.raises(QSploitError):
        decrypt_record(record("client_application_record"), V["client_application_secret"], sequence)


def test_nonce_uses_all_eight_network_order_sequence_bytes():
    sequence = 0x0102030405060708
    nonce = (int.from_bytes(V["client_application_iv"], "big") ^ sequence).to_bytes(12, "big")
    header = bytes.fromhex("1703030014")
    fragment = AESGCM(V["client_application_key"]).encrypt(nonce, b"abc\x17", header)
    value = Record("c2s", 0, 23, 0x0303, fragment)
    assert decrypt_record(value, V["client_application_secret"], sequence) == (23, b"abc")


@pytest.mark.parametrize("inner", [b"", bytes(40), b"data\x19", b"\x16", b"\x15"])
def test_authenticated_but_invalid_inner_plaintext_rejected(inner):
    with pytest.raises(QSploitError):
        decrypt_record(protected_inner(inner), V["client_application_secret"], 0)
