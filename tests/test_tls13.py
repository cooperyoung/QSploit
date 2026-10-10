"""Real TLS 1.3 capture plus synthetic authenticated-negative/epoch vectors."""
import base64
from dataclasses import replace
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

from qsploit.keyexchange import ecdhe_shared_secret
from qsploit.models import ECDLogSecret, QSploitError, Record, TCPConnection
from qsploit.pcap import read_connections
from qsploit.tls import HRR_RANDOM, _hello, parse_tls, problem_for
from qsploit.tls13 import decrypt_tls13, decrypt_record, handshake_secrets, hkdf_expand_label, traffic_key_iv

ROOT = Path(__file__).parents[1]


def fixture():
    path = ROOT / "tests/fixtures/tls13-p256-aes128"
    session = parse_tls(read_connections(path.with_suffix(".pcap").read_bytes()).connections[0])
    expected = json.loads(path.with_suffix(".expected.json").read_text())
    registry = json.loads((ROOT / "qsploit/demo/ec_dlog.json").read_text())
    secret = ECDLogSecret(int(registry[expected["recovery_registry_key"]]["x"], 16))
    return session, secret, expected


def traffic(expected, direction, epoch):
    prefix = "CLIENT" if direction == "c2s" else "SERVER"
    suffix = "_HANDSHAKE_TRAFFIC_SECRET" if epoch == "handshake" else "_TRAFFIC_SECRET_0"
    return bytes.fromhex(expected["tls13_secrets"][prefix + suffix])


def encrypt(record, secret, sequence, payload, kind=22, padding=0):
    return encrypt_inner(record, secret, sequence, payload + bytes([kind]) + bytes(padding))


def encrypt_inner(record, secret, sequence, plaintext):
    key, iv = traffic_key_iv(secret)
    nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, "big")))
    aad = b"\x17\x03\x03" + (len(plaintext) + 16).to_bytes(2, "big")
    return replace(record, content_type=23, version=0x0303, fragment=AESGCM(key).encrypt(nonce, plaintext, aad))


def indices(session, direction):
    return [i for i, r in enumerate(session.records) if r.direction == direction and r.content_type == 23]


def messages(payload):
    result = []
    while payload:
        size = 4 + int.from_bytes(payload[1:4], "big")
        result.append(payload[:size]); payload = payload[size:]
    return result


def test_genuine_tls13_schedule_and_http_match_independent_endpoints():
    session, secret, expected = fixture()
    assert not session.blockers and session.alpn is None and session.authentication is None
    assert problem_for(session).curve == "secp256r1"
    transcript = b"".join(h.wire for h in session.clear_handshakes)
    client, server, master = handshake_secrets(ecdhe_shared_secret(session.ecdhe, secret), transcript)
    assert client == traffic(expected, "c2s", "handshake")
    assert server == traffic(expected, "s2c", "handshake")
    assert master.hex() == expected["tls13_master_secret_hex"]
    output = decrypt_tls13(session, secret)
    assert output.c2s == base64.b64decode(expected["c2s_base64"])
    assert output.s2c == base64.b64decode(expected["s2c_base64"])
    assert output.client_finished_verified and output.server_finished_verified
    assert output.client_close_notify and output.server_close_notify
    assert output.authenticated_records == 20
    assert output.negotiated_alpn == "http/1.1" and output.authentication == "RSA"


def test_every_tls13_protected_record_authenticates():
    session, secret, _ = fixture()
    for index, record in enumerate(session.records):
        if record.content_type != 23:
            continue
        records = list(session.records)
        records[index] = replace(record, fragment=record.fragment[:-1] + bytes([record.fragment[-1] ^ 1]))
        with pytest.raises(QSploitError) as exc:
            decrypt_tls13(replace(session, records=tuple(records)), secret)
        assert exc.value.code == "AEAD_AUTH_FAILED"


@pytest.mark.parametrize("direction,handshake,code", [("s2c", 15, "SERVER_SIGNATURE_FAILED"), ("s2c", 20, "FINISHED_VERIFY_FAILED"), ("c2s", 20, "FINISHED_VERIFY_FAILED")])
def test_valid_record_tag_does_not_replace_signature_or_finished_checks(direction, handshake, code):
    session, secret, expected = fixture()
    records = list(session.records); index = indices(session, direction)[0]
    key = traffic(expected, direction, "handshake")
    kind, payload = decrypt_record(records[index], key, 0)
    pieces = messages(payload)
    target = next(i for i, msg in enumerate(pieces) if msg[0] == handshake)
    pieces[target] = pieces[target][:-1] + bytes([pieces[target][-1] ^ 1])
    records[index] = encrypt(records[index], key, 0, b"".join(pieces), kind)
    with pytest.raises(QSploitError) as exc:
        decrypt_tls13(replace(session, records=tuple(records)), secret)
    assert exc.value.code == code


@pytest.mark.parametrize("direction", ["c2s", "s2c"])
def test_fragmented_handshake_and_padding_preserve_exact_transcript(direction):
    session, secret, expected = fixture()
    records = list(session.records); index = indices(session, direction)[0]
    key = traffic(expected, direction, "handshake")
    _, payload = decrypt_record(records[index], key, 0)
    first = encrypt(records[index], key, 0, payload[:7], padding=11)
    second = encrypt(records[index], key, 1, payload[7:], padding=23)
    records[index:index + 1] = [first, second]
    output = decrypt_tls13(replace(session, records=tuple(records)), secret)
    assert output.c2s == base64.b64decode(expected["c2s_base64"])
    assert output.s2c == base64.b64decode(expected["s2c_base64"])
    assert output.authenticated_records == 21


@pytest.mark.parametrize("direction", ["c2s", "s2c"])
def test_key_update_uses_old_keys_then_resets_new_epoch_sequence(direction):
    session, secret, expected = fixture()
    old = traffic(expected, direction, "application")
    new = hkdf_expand_label(old, "traffic upd", b"", 32)
    protected = indices(session, direction)
    records = list(session.records)
    start = protected[1]
    update = encrypt(records[start], old, 0, b"\x18\x00\x00\x01\x00")
    for seq, index in enumerate(protected[1:]):
        kind, payload = decrypt_record(records[index], old, seq)
        records[index] = encrypt(records[index], new, seq, payload, kind)
    records.insert(start, update)
    output = decrypt_tls13(replace(session, records=tuple(records)), secret)
    assert output.c2s == base64.b64decode(expected["c2s_base64"])
    assert output.s2c == base64.b64decode(expected["s2c_base64"])
    assert output.authenticated_records == 21
    # Omitting the authenticated KeyUpdate cannot manufacture the new epoch.
    del records[start]
    with pytest.raises(QSploitError) as exc:
        decrypt_tls13(replace(session, records=tuple(records)), secret)
    assert exc.value.code == "AEAD_AUTH_FAILED"


@pytest.mark.parametrize("variant,code", [("bad_update", "INVALID_TLS"), ("update_after_bytes", "INVALID_TLS"),
    ("empty_ticket", "INCOMPLETE_HANDSHAKE"), ("client_auth", "CLIENT_AUTH_UNSUPPORTED"),
    ("early_app", "FINISHED_VERIFY_FAILED"), ("unknown_inner", "INVALID_TLS"), ("padding_limit", "INVALID_TLS")])
def test_authenticated_protocol_failures_still_reject(variant, code):
    session, secret, expected = fixture()
    records = list(session.records)
    index = indices(session, "s2c")[1]
    key = traffic(expected, "s2c", "application")
    if variant in ("early_app", "unknown_inner", "padding_limit"):
        index = indices(session, "s2c")[0]
        key = traffic(expected, "s2c", "handshake")
    if variant == "bad_update":
        changed = b"\x18\x00\x00\x01\x02"
    elif variant == "update_after_bytes":
        changed = b"\x18\x00\x00\x01\x00" + b"\x18\x00\x00\x01\x00"
    elif variant == "empty_ticket":
        changed = b"\x04\x00\x00\x00"
    elif variant == "client_auth":
        changed = b"\x0d\x00\x00\x00"
    else:
        changed = b"test"
    if variant == "unknown_inner":
        records[index] = encrypt_inner(records[index], key, 0, b"test\x19")
    elif variant == "padding_limit":
        records[index] = encrypt_inner(records[index], key, 0, b"test\x16" + bytes(16381))
    else:
        records[index] = encrypt(records[index], key, 0, changed, 23 if variant == "early_app" else 22)
    with pytest.raises(QSploitError) as exc:
        decrypt_tls13(replace(session, records=tuple(records)), secret)
    assert exc.value.code == code


def test_missing_finished_late_ccs_and_wrong_scalar_rejected():
    session, secret, _ = fixture()
    index = indices(session, "c2s")[0]
    records = tuple(r for i, r in enumerate(session.records) if i != index)
    with pytest.raises(QSploitError):
        decrypt_tls13(replace(session, records=records), secret)
    with pytest.raises(QSploitError) as exc:
        decrypt_tls13(replace(session, records=session.records + (Record("s2c", 0, 20, 0x0303, b"\x01"),)), secret)
    assert exc.value.code == "INVALID_TLS"
    with pytest.raises(QSploitError) as exc:
        decrypt_tls13(session, ECDLogSecret(secret.x + 1))
    assert exc.value.code == "INVALID_DLOG_RESULT"


@pytest.mark.parametrize("variant,code", [("psk", "PSK_UNSUPPORTED"), ("early_data", "EARLY_DATA_UNSUPPORTED"), ("hrr", "HRR_UNSUPPORTED")])
def test_tls13_unsupported_handshake_families_have_explicit_blockers(variant, code):
    session, _, _ = fixture()
    records = list(session.records)
    direction = "c2s" if variant == "early_data" else "s2c"
    index = next(i for i, r in enumerate(records) if r.direction == direction and r.content_type == 22)
    wire = records[index].fragment
    if variant == "hrr":
        hrr = wire[:6] + HRR_RANDOM + wire[38:]
        records.insert(index, replace(records[index], fragment=hrr))
    else:
        client = direction == "c2s"
        hello = _hello(wire, client)
        extension = (42).to_bytes(2, "big") + b"\x00\x00" if client else (41).to_bytes(2, "big") + b"\x00\x02\x00\x00"
        existing = b"".join(k.to_bytes(2, "big") + len(v).to_bytes(2, "big") + v for k, v in hello["ext"].items())
        old_length = len(existing) + 2
        body = wire[4:-old_length] + (len(existing) + len(extension)).to_bytes(2, "big") + existing + extension
        records[index] = replace(records[index], fragment=wire[:1] + len(body).to_bytes(3, "big") + body)
    def stream(side):
        return b"".join(bytes([r.content_type]) + r.version.to_bytes(2, "big") + len(r.fragment).to_bytes(2, "big") + r.fragment for r in records if r.direction == side)
    changed = parse_tls(TCPConnection("synthetic-negotiation", session.client, session.server,
                                     stream("c2s"), stream("s2c"), True, True, (), ()))
    assert code in changed.blockers
    with pytest.raises(QSploitError):
        problem_for(changed)


def test_tls13_key_update_limit_is_enforced_before_release():
    from qsploit.tls13 import MAX_KEY_UPDATES
    session, secret, expected = fixture()
    indices_client = indices(session, "c2s")
    start = indices_client[1]
    records = list(session.records)
    current = traffic(expected, "c2s", "application")
    updates = []
    for _ in range(MAX_KEY_UPDATES + 1):
        updates.append(encrypt(records[start], current, 0, b"\x18\x00\x00\x01\x00"))
        current = hkdf_expand_label(current, "traffic upd", b"", 32)
    records[start:start] = updates
    with pytest.raises(QSploitError) as exc:
        decrypt_tls13(replace(session, records=tuple(records)), secret)
    assert exc.value.code == "RESOURCE_LIMIT"
