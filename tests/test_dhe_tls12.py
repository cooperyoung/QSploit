"""Genuine OpenSSL/tlslite DHE captures and explicitly synthetic failure vectors."""
import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding
import pytest

from qsploit.groups import FFDHE2048_G as G, FFDHE2048_ORDER as Q, FFDHE2048_P as P, validate_ffdhe2048
from qsploit.models import FFDLogProblem, FFDLogSecret, QSploitError, RSAFactors, TCPConnection
from qsploit.pcap import read_connections
from qsploit.tls import _dhe_key_exchange, parse_tls, problem_for
from qsploit.tls12 import decrypt_tls12, derive_key_block, derive_master_secret, recover_premaster

FIXTURES = Path(__file__).parent / "fixtures"
REGISTRY = Path(__file__).parents[1] / "qsploit/demo/dlog.json"
NAMES = [f"tls12-dhe-aes{bits}-{ems}" for bits in (128, 256) for ems in ("ems", "noems")]


def fixture(name=NAMES[0]):
    connection = read_connections((FIXTURES / f"{name}.pcap").read_bytes()).connections[0]
    session = parse_tls(connection)
    expected = json.loads((FIXTURES / f"{name}.expected.json").read_text())
    entry = json.loads(REGISTRY.read_text())[expected["recovery_registry_key"]]
    return session, FFDLogSecret(int(entry["x"], 16)), expected


def protected_indices(session, direction=None):
    active, indices = set(), []
    for i, record in enumerate(session.records):
        if record.content_type == 20:
            active.add(record.direction)
        elif record.direction in active and direction in (None, record.direction):
            indices.append(i)
    return indices


@pytest.mark.parametrize("name", NAMES)
def test_genuine_dhe_keylogs_plaintext_and_both_finished(name):
    session, secret, expected = fixture(name)
    assert session.blockers == ()
    assert session.kex == "dhe" and session.authentication == "RSA" and session.selected_group == 256
    assert session.rsa is None and session.ems is expected["ems"]
    problem = problem_for(session)
    assert isinstance(problem, FFDLogProblem)
    assert {key: format(getattr(problem, key), "x") for key in ("p", "g", "y", "order")} == expected["public_problem"]
    assert problem.y == session.dhe.server_public  # the peer share stays local
    assert derive_master_secret(session, secret).hex() == expected["master_secret_hex"]
    output = decrypt_tls12(session, secret)
    assert output.c2s == base64.b64decode(expected["c2s_base64"])
    assert output.s2c == base64.b64decode(expected["s2c_base64"])
    assert output.client_finished_verified and output.server_finished_verified
    assert output.authenticated_records == len(protected_indices(session))


def test_ffdhe_exact_group_and_subgroup_checks():
    assert P.bit_length() == 2048 and 2 * Q + 1 == P and G == 2
    validate_ffdhe2048(P, G, Q, 2, pow(2, 123, P))
    for parameters in ((P - 2, G, Q), (P, 3, Q), (P, G, Q - 1), (True, G, Q)):
        with pytest.raises(QSploitError, match="ffdhe2048"):
            validate_ffdhe2048(*parameters, 2)
    for value in (0, 1, P - 1, P, P - 2, True):
        with pytest.raises(QSploitError) as exc:
            validate_ffdhe2048(P, G, Q, value)
        assert exc.value.code == "INVALID_DH_PUBLIC"


@pytest.mark.parametrize("name", [NAMES[0], NAMES[2]])
def test_wrong_exponent_wrong_result_type_and_wrong_peer_never_release(name):
    session, secret, _ = fixture(name)
    for scalar in (0, Q, -1, True, secret.x + 1):
        with pytest.raises(QSploitError) as exc:
            decrypt_tls12(session, FFDLogSecret(scalar))
        assert exc.value.code == "INVALID_DLOG_RESULT"
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(session, RSAFactors(3, 5))
    assert exc.value.code == "INVALID_RECOVERY_RESULT"
    # A different valid peer share passes mathematical validation but changes Z.
    changed = replace(session, dhe=replace(session.dhe, client_public=pow(G, 7, P)))
    with pytest.raises(QSploitError) as exc:
        decrypt_tls12(changed, secret)
    assert exc.value.code == "AEAD_AUTH_FAILED"


def test_premaster_strips_leading_zeros_and_revalidates_parameters():
    session, _, _ = fixture()
    synthetic = replace(session, dhe=replace(session.dhe, server_public=2, client_public=2))
    assert recover_premaster(synthetic, FFDLogSecret(1)) == b"\x02"
    for field, value in (("p", P - 2), ("g", 3), ("order", Q - 1), ("server_public", 1), ("client_public", P - 2)):
        with pytest.raises(QSploitError):
            recover_premaster(replace(synthetic, dhe=replace(synthetic.dhe, **{field: value})), FFDLogSecret(1))


@pytest.mark.parametrize("variant", ["missing", "duplicate", "reordered"])
def test_parser_rejects_incomplete_or_inconsistent_server_key_exchange(variant):
    session, secret, _ = fixture()
    client = [h.wire for h in session.clear_handshakes if h.direction == "c2s"]
    server = [h.wire for h in session.clear_handshakes if h.direction == "s2c"]
    index = next(i for i, wire in enumerate(server) if wire[0] == 12)
    if variant == "missing":
        del server[index]
    elif variant == "duplicate":
        server.insert(index, server[index])
    else:
        server[index], server[index - 1] = server[index - 1], server[index]

    def record(wire, kind=22, version=0x0303):
        return bytes([kind]) + version.to_bytes(2, "big") + len(wire).to_bytes(2, "big") + wire

    def stream(direction, clear):
        captured = [r for r in session.records if r.direction == direction]
        ccs = next(i for i, r in enumerate(captured) if r.content_type == 20)
        return record(b"".join(clear)) + b"".join(record(r.fragment, r.content_type, r.version) for r in captured[ccs:])

    parsed = parse_tls(TCPConnection("synthetic-dhe-flight", session.client, session.server,
                                    stream("c2s", client), stream("s2c", server), True, True, (), ()))
    assert "INCOMPLETE_HANDSHAKE" in parsed.blockers
    with pytest.raises(QSploitError):
        decrypt_tls12(parsed, secret)


@pytest.mark.parametrize("name", [NAMES[0], NAMES[2]])
def test_every_dhe_record_authenticates_including_alerts(name):
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
def test_dhe_valid_aead_with_wrong_finished_still_rejected(name, direction):
    session, secret, _ = fixture(name)
    block = derive_key_block(derive_master_secret(session, secret), session.client_random, session.server_random, session.cipher_suite)
    key_length = 16 if session.cipher_suite == 0x009e else 32
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


def vec(data, width=2):
    return len(data).to_bytes(width, "big") + data


def hs(kind, data):
    return bytes([kind]) + vec(data, 3)


@pytest.fixture(scope="module")
def signing_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Synthetic signature test")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                   .sign(key, hashes.SHA256()).public_bytes(Encoding.DER))
    return key, hs(11, vec(vec(certificate, 3), 3))


def signed_exchange(signing_key, scheme=0x0401):
    key, certificate = signing_key
    parameters = b"".join(vec(v.to_bytes((v.bit_length() + 7) // 8, "big")) for v in (P, G, pow(G, 123, P)))
    digest = {0x0401: hashes.SHA256, 0x0501: hashes.SHA384, 0x0601: hashes.SHA512,
              0x0804: hashes.SHA256, 0x0805: hashes.SHA384, 0x0806: hashes.SHA512}[scheme]()
    pad = padding.PKCS1v15() if scheme < 0x0800 else padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size)
    signature = key.sign(b"c" * 32 + b"s" * 32 + parameters, pad, digest)
    return [hs(12, parameters + scheme.to_bytes(2, "big") + vec(signature)), hs(16, vec(b"\x02")),
            certificate, b"c" * 32, b"s" * 32, {13: vec(scheme.to_bytes(2, "big")), 10: vec(b"\x01\x00")}]


@pytest.mark.parametrize("scheme", [0x0401, 0x0501, 0x0601, 0x0804, 0x0805, 0x0806])
def test_synthetic_server_signature_schemes_verified(signing_key, scheme):
    result = _dhe_key_exchange(*signed_exchange(signing_key, scheme))
    assert result.server_public == pow(G, 123, P) and result.client_public == 2


@pytest.mark.parametrize("variant,code", [("signature", "SERVER_SIGNATURE_FAILED"), ("random", "SERVER_SIGNATURE_FAILED"),
    ("unoffered_signature", "INVALID_TLS"), ("unoffered_group", "INVALID_TLS"), ("missing_signature_offer", "UNSUPPORTED_SIGNATURE"),
    ("empty_client_share", "INVALID_TLS"), ("invalid_client_share", "INVALID_DH_PUBLIC"), ("signature_length", "INCOMPLETE_HANDSHAKE")])
def test_dhe_signed_parameter_failures(signing_key, variant, code):
    fields = signed_exchange(signing_key)
    if variant == "signature":
        fields[0] = fields[0][:-1] + bytes([fields[0][-1] ^ 1])
    elif variant == "random":
        fields[3] = b"x" * 32
    elif variant == "unoffered_signature":
        fields[5][13] = vec(b"\x05\x01")
    elif variant == "unoffered_group":
        fields[5][10] = vec(b"\x01\x01")
    elif variant == "missing_signature_offer":
        del fields[5][13]
    elif variant == "empty_client_share":
        fields[1] = hs(16, vec(b""))
    elif variant == "invalid_client_share":
        fields[1] = hs(16, vec(b"\x01"))
    else:
        fields[0] = fields[0][:-1]
    with pytest.raises(QSploitError) as exc:
        _dhe_key_exchange(*fields)
    assert exc.value.code == code
