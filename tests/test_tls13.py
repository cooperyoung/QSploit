"""Real TLS 1.3 capture plus synthetic authenticated-negative/epoch vectors."""
import base64
from dataclasses import replace
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import pytest

from qsploit.keyexchange import ecdhe_shared_secret, ffdhe_shared_secret
from qsploit.models import ECDLogSecret, FFDLogSecret, QSploitError, Record, TCPConnection, X25519Secret
from qsploit.pcap import read_connections
from qsploit.tls import HRR_RANDOM, _hello, parse_tls, problem_for
from qsploit.tls13 import decrypt_tls13, decrypt_record, handshake_secrets, hkdf_expand_label, traffic_key_iv

ROOT = Path(__file__).parents[1]


def fixture(name="tls13-p256-aes128"):
    path = ROOT / "tests/fixtures" / name
    session = parse_tls(read_connections(path.with_suffix(".pcap").read_bytes()).connections[0])
    expected = json.loads(path.with_suffix(".expected.json").read_text())
    registry = json.loads((ROOT / "qsploit/demo" / ("dlog.json" if session.dhe else "ec_dlog.json")).read_text())
    entry = registry[expected["recovery_registry_key"]]
    secret = FFDLogSecret(int(entry["x"], 16)) if session.dhe else ECDLogSecret(int(entry["x"], 16)) if "x" in entry else X25519Secret(bytes.fromhex(entry["scalar"]))
    return session, secret, expected


@pytest.fixture(params=["tls13-p256-aes128", "tls13-x25519-aes128", "tls13-p256-aes256", "tls13-x25519-aes256", "tls13-p256-chacha", "tls13-x25519-chacha", "tls13-dhe-aes128", "tls13-dhe-aes256", "tls13-dhe-chacha"])
def tls_capture(request):
    return fixture(request.param)


def traffic(expected, direction, epoch):
    prefix = "CLIENT" if direction == "c2s" else "SERVER"
    suffix = "_HANDSHAKE_TRAFFIC_SECRET" if epoch == "handshake" else "_TRAFFIC_SECRET_0"
    return bytes.fromhex(expected["tls13_secrets"][prefix + suffix])


def encrypt(record, secret, sequence, payload, kind=22, padding=0, *, cipher_suite=0x1301):
    return encrypt_inner(record, secret, sequence, payload + bytes([kind]) + bytes(padding), cipher_suite=cipher_suite)


def encrypt_inner(record, secret, sequence, plaintext, *, cipher_suite=0x1301):
    key, iv = traffic_key_iv(secret, cipher_suite)
    nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, "big")))
    aad = b"\x17\x03\x03" + (len(plaintext) + 16).to_bytes(2, "big")
    cipher = ChaCha20Poly1305(key) if cipher_suite == 0x1303 else AESGCM(key)
    return replace(record, content_type=23, version=0x0303, fragment=cipher.encrypt(nonce, plaintext, aad))


def indices(session, direction):
    return [i for i, r in enumerate(session.records) if r.direction == direction and r.content_type == 23]


def messages(payload):
    result = []
    while payload:
        size = 4 + int.from_bytes(payload[1:4], "big")
        result.append(payload[:size]); payload = payload[size:]
    return result


def test_genuine_tls13_schedule_and_http_match_independent_endpoints(tls_capture):
    session, secret, expected = tls_capture
    assert not session.blockers and session.alpn is None and session.authentication is None
    problem = problem_for(session)
    if session.dhe:
        assert problem.kind == "ff_dlog"
        for field in ("p", "g", "y", "order"):
            assert getattr(problem, field) == int(expected["public_problem"][field], 16)
    else:
        assert problem.curve == expected["public_problem"]["curve"]
    transcript = b"".join(h.wire for h in session.clear_handshakes)
    shared = ffdhe_shared_secret(session.dhe, secret, padded=True) if session.dhe else ecdhe_shared_secret(session.ecdhe, secret)
    client, server, master = handshake_secrets(shared, transcript, session.cipher_suite)
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


def test_every_tls13_protected_record_authenticates(tls_capture):
    session, secret, _ = tls_capture
    for index, record in enumerate(session.records):
        if record.content_type != 23:
            continue
        records = list(session.records)
        records[index] = replace(record, fragment=record.fragment[:-1] + bytes([record.fragment[-1] ^ 1]))
        with pytest.raises(QSploitError) as exc:
            decrypt_tls13(replace(session, records=tuple(records)), secret)
        assert exc.value.code == "AEAD_AUTH_FAILED"


@pytest.mark.parametrize("direction,handshake,code", [("s2c", 15, "SERVER_SIGNATURE_FAILED"), ("s2c", 20, "FINISHED_VERIFY_FAILED"), ("c2s", 20, "FINISHED_VERIFY_FAILED")])
def test_valid_record_tag_does_not_replace_signature_or_finished_checks(direction, handshake, code, tls_capture):
    session, secret, expected = tls_capture
    records = list(session.records); index = indices(session, direction)[0]
    key = traffic(expected, direction, "handshake")
    kind, payload = decrypt_record(records[index], key, 0, session.cipher_suite)
    pieces = messages(payload)
    target = next(i for i, msg in enumerate(pieces) if msg[0] == handshake)
    pieces[target] = pieces[target][:-1] + bytes([pieces[target][-1] ^ 1])
    records[index] = encrypt(records[index], key, 0, b"".join(pieces), kind, cipher_suite=session.cipher_suite)
    with pytest.raises(QSploitError) as exc:
        decrypt_tls13(replace(session, records=tuple(records)), secret)
    assert exc.value.code == code


@pytest.mark.parametrize("direction", ["c2s", "s2c"])
def test_fragmented_handshake_and_padding_preserve_exact_transcript(direction, tls_capture):
    session, secret, expected = tls_capture
    records = list(session.records); index = indices(session, direction)[0]
    key = traffic(expected, direction, "handshake")
    _, payload = decrypt_record(records[index], key, 0, session.cipher_suite)
    first = encrypt(records[index], key, 0, payload[:7], padding=11, cipher_suite=session.cipher_suite)
    second = encrypt(records[index], key, 1, payload[7:], padding=23, cipher_suite=session.cipher_suite)
    records[index:index + 1] = [first, second]
    output = decrypt_tls13(replace(session, records=tuple(records)), secret)
    assert output.c2s == base64.b64decode(expected["c2s_base64"])
    assert output.s2c == base64.b64decode(expected["s2c_base64"])
    assert output.authenticated_records == 21


@pytest.mark.parametrize("direction", ["c2s", "s2c"])
def test_key_update_uses_old_keys_then_resets_new_epoch_sequence(direction, tls_capture):
    session, secret, expected = tls_capture
    old = traffic(expected, direction, "application")
    new = hkdf_expand_label(old, "traffic upd", b"", len(old), session.cipher_suite)
    protected = indices(session, direction)
    records = list(session.records)
    start = protected[1]
    update = encrypt(records[start], old, 0, b"\x18\x00\x00\x01\x00", cipher_suite=session.cipher_suite)
    for seq, index in enumerate(protected[1:]):
        kind, payload = decrypt_record(records[index], old, seq, session.cipher_suite)
        records[index] = encrypt(records[index], new, seq, payload, kind, cipher_suite=session.cipher_suite)
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
def test_authenticated_protocol_failures_still_reject(variant, code, tls_capture):
    session, secret, expected = tls_capture
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
        records[index] = encrypt_inner(records[index], key, 0, b"test\x19", cipher_suite=session.cipher_suite)
    elif variant == "padding_limit":
        records[index] = encrypt_inner(records[index], key, 0, b"test\x16" + bytes(16381), cipher_suite=session.cipher_suite)
    else:
        records[index] = encrypt(records[index], key, 0, changed, 23 if variant == "early_app" else 22, cipher_suite=session.cipher_suite)
    with pytest.raises(QSploitError) as exc:
        decrypt_tls13(replace(session, records=tuple(records)), secret)
    assert exc.value.code == code


def test_missing_finished_late_ccs_and_wrong_scalar_rejected(tls_capture):
    session, secret, _ = tls_capture
    index = indices(session, "c2s")[0]
    records = tuple(r for i, r in enumerate(session.records) if i != index)
    with pytest.raises(QSploitError):
        decrypt_tls13(replace(session, records=records), secret)
    with pytest.raises(QSploitError) as exc:
        decrypt_tls13(replace(session, records=session.records + (Record("s2c", 0, 20, 0x0303, b"\x01"),)), secret)
    assert exc.value.code == "INVALID_TLS"
    with pytest.raises(QSploitError) as exc:
        wrong = type(secret)(secret.x + 1) if isinstance(secret, (ECDLogSecret, FFDLogSecret)) else X25519Secret(secret.scalar[:1] + bytes([secret.scalar[1] ^ 1]) + secret.scalar[2:])
        decrypt_tls13(session, wrong)
    assert exc.value.code == "INVALID_DLOG_RESULT"


@pytest.mark.parametrize("variant,code", [("psk", "PSK_UNSUPPORTED"), ("early_data", "EARLY_DATA_UNSUPPORTED"),
    ("hrr", "HRR_UNSUPPORTED"), ("invalid_public", "INVALID_EC_PUBLIC")])
def test_tls13_unsupported_handshake_families_have_explicit_blockers(variant, code, tls_capture):
    session, _, _ = tls_capture
    if variant == "invalid_public" and session.dhe:
        code = "INVALID_DH_PUBLIC"
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
        old_extensions = dict(hello["ext"])
        if variant == "invalid_public":
            share = hello["ext"][51]
            value = bytes(256) if session.dhe else b"\x04" + bytes(64) if session.ecdhe.group == 23 else bytes(32)
            hello["ext"][51] = share[:4] + value
            extension = b""
        else:
            extension = (42).to_bytes(2, "big") + b"\x00\x00" if client else (41).to_bytes(2, "big") + b"\x00\x02\x00\x00"
        existing = b"".join(k.to_bytes(2, "big") + len(v).to_bytes(2, "big") + v for k, v in hello["ext"].items())
        old_length = sum(4 + len(value) for value in old_extensions.values()) + 2
        body = wire[4:-old_length] + (len(existing) + len(extension)).to_bytes(2, "big") + existing + extension
        records[index] = replace(records[index], fragment=wire[:1] + len(body).to_bytes(3, "big") + body)
    def stream(side):
        return b"".join(bytes([r.content_type]) + r.version.to_bytes(2, "big") + len(r.fragment).to_bytes(2, "big") + r.fragment for r in records if r.direction == side)
    changed = parse_tls(TCPConnection("synthetic-negotiation", session.client, session.server,
                                     stream("c2s"), stream("s2c"), True, True, (), ()))
    assert code in changed.blockers
    with pytest.raises(QSploitError):
        problem_for(changed)


def test_tls13_key_update_limit_is_enforced_before_release(tls_capture):
    from qsploit.tls13 import MAX_KEY_UPDATES
    session, secret, expected = tls_capture
    indices_client = indices(session, "c2s")
    start = indices_client[1]
    records = list(session.records)
    current = traffic(expected, "c2s", "application")
    updates = []
    for _ in range(MAX_KEY_UPDATES + 1):
        updates.append(encrypt(records[start], current, 0, b"\x18\x00\x00\x01\x00", cipher_suite=session.cipher_suite))
        current = hkdf_expand_label(current, "traffic upd", b"", len(current), session.cipher_suite)
    records[start:start] = updates
    with pytest.raises(QSploitError) as exc:
        decrypt_tls13(replace(session, records=tuple(records)), secret)
    assert exc.value.code == "RESOURCE_LIMIT"


def test_tls13_wrong_recovery_result_type_is_rejected(tls_capture):
    session, secret, _ = tls_capture
    wrong = X25519Secret(bytes(32)) if isinstance(secret, ECDLogSecret) else ECDLogSecret(7)
    with pytest.raises(QSploitError) as exc:
        decrypt_tls13(session, wrong)
    assert exc.value.code == "INVALID_RECOVERY_RESULT"
