"""Strict TLS 1.3 full-handshake AES-GCM decryption (RFC 8446).

All application bytes remain local and quarantined until CertificateVerify,
both Finished messages, and every captured protected record authenticate.
"""
from __future__ import annotations

import hashlib
import hmac

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keyexchange import ecdhe_shared_secret
from .models import ApplicationStreams, ParsedTLS, QSploitError, Record, RecoveredSecret
from .tls import MAX_HANDSHAKE_BYTES, MAX_HANDSHAKE_MESSAGES, MAX_RSA_BITS, _Reader, _alpn, _extensions, _hello, problem_for

MAX_KEY_UPDATES = 32
CIPHER_PARAMETERS = {0x1301: ("sha256", 32, 16), 0x1302: ("sha384", 48, 32)}


def cipher_parameters(cipher_suite: int) -> tuple[str, int, int]:
    try:
        return CIPHER_PARAMETERS[cipher_suite]
    except KeyError:
        raise QSploitError("UNSUPPORTED_CIPHER", "This TLS 1.3 cipher suite is not implemented.") from None


def hkdf_extract(salt: bytes, ikm: bytes, cipher_suite: int = 0x1301) -> bytes:
    hash_name, _, _ = cipher_parameters(cipher_suite)
    return hmac.digest(salt, ikm, hash_name)


def hkdf_expand_label(secret: bytes, label: str | bytes, context: bytes, length: int, cipher_suite: int = 0x1301) -> bytes:
    hash_name, hash_length, _ = cipher_parameters(cipher_suite)
    label = b"tls13 " + (label.encode("ascii") if isinstance(label, str) else label)
    if not 0 <= length <= 255 * hash_length or not 7 <= len(label) <= 255 or len(context) > 255:
        raise ValueError("invalid TLS 1.3 HKDF label/output size")
    info = length.to_bytes(2, "big") + bytes([len(label)]) + label + bytes([len(context)]) + context
    output, block = b"", b""
    for counter in range(1, (length + hash_length - 1) // hash_length + 1):
        block = hmac.digest(secret, block + info + bytes([counter]), hash_name)
        output += block
    return output[:length]


def derive_secret(secret: bytes, label: str | bytes, transcript: bytes, cipher_suite: int = 0x1301) -> bytes:
    hash_name, hash_length, _ = cipher_parameters(cipher_suite)
    return hkdf_expand_label(secret, label, hashlib.new(hash_name, transcript).digest(), hash_length, cipher_suite)


def traffic_key_iv(secret: bytes, cipher_suite: int = 0x1301) -> tuple[bytes, bytes]:
    _, _, key_length = cipher_parameters(cipher_suite)
    return hkdf_expand_label(secret, "key", b"", key_length, cipher_suite), hkdf_expand_label(secret, "iv", b"", 12, cipher_suite)


def finished_verify_data(traffic_secret: bytes, transcript: bytes, cipher_suite: int = 0x1301) -> bytes:
    hash_name, hash_length, _ = cipher_parameters(cipher_suite)
    key = hkdf_expand_label(traffic_secret, "finished", b"", hash_length, cipher_suite)
    return hmac.digest(key, hashlib.new(hash_name, transcript).digest(), hash_name)


def handshake_secrets(shared: bytes, hello_transcript: bytes, cipher_suite: int = 0x1301) -> tuple[bytes, bytes, bytes]:
    _, hash_length, _ = cipher_parameters(cipher_suite)
    early = hkdf_extract(bytes(hash_length), bytes(hash_length), cipher_suite)
    handshake = hkdf_extract(derive_secret(early, "derived", b"", cipher_suite), shared, cipher_suite)
    master = hkdf_extract(derive_secret(handshake, "derived", b"", cipher_suite), bytes(hash_length), cipher_suite)
    return derive_secret(handshake, "c hs traffic", hello_transcript, cipher_suite), derive_secret(handshake, "s hs traffic", hello_transcript, cipher_suite), master


def decrypt_record(record: Record, traffic_secret: bytes, sequence: int, cipher_suite: int = 0x1301) -> tuple[int, bytes]:
    if record.content_type != 23 or record.version != 0x0303 or not 17 <= len(record.fragment) <= 16384 + 256:
        raise QSploitError("INVALID_TLS", "A protected TLS 1.3 record has an invalid outer header or size.")
    if not 0 <= sequence < 2**64:
        raise QSploitError("RESOURCE_LIMIT", "The TLS record sequence number is exhausted.")
    key, iv = traffic_key_iv(traffic_secret, cipher_suite)
    nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, "big")))
    aad = b"\x17\x03\x03" + len(record.fragment).to_bytes(2, "big")
    try:
        plaintext = AESGCM(key).decrypt(nonce, record.fragment, aad)
    except InvalidTag:
        raise QSploitError("AEAD_AUTH_FAILED", "A TLS 1.3 record failed authentication; no session plaintext was released.") from None
    if len(plaintext) > 16385:
        raise QSploitError("INVALID_TLS", "TLSInnerPlaintext including padding exceeds its protocol limit.")
    unpadded = plaintext.rstrip(b"\x00")
    if not unpadded or unpadded[-1] not in (21, 22, 23):
        raise QSploitError("INVALID_TLS", "TLSInnerPlaintext has no supported content type after its padding.")
    if len(unpadded) == 1 and unpadded[-1] != 23:
        raise QSploitError("INVALID_TLS", "TLS 1.3 handshake and alert records cannot have empty content.")
    if len(unpadded) - 1 > 16384:
        raise QSploitError("INVALID_TLS", "The TLS 1.3 inner content exceeds the plaintext record limit.")
    return unpadded[-1], unpadded[:-1]


def _certificate_key(wire: bytes):
    reader = _Reader(wire[4:])
    if reader.vector(1):
        raise QSploitError("INVALID_TLS", "The initial server Certificate has a nonempty request context.")
    chain = _Reader(reader.vector(3)); reader.end()
    if not chain.data:
        raise QSploitError("INVALID_TLS", "The server Certificate list is empty.")
    leaf = None
    while chain.pos < len(chain.data):
        der = chain.vector(3)
        if not der:
            raise QSploitError("INVALID_TLS", "A Certificate entry is empty.")
        extensions = _Reader(chain.vector(2))
        seen = set()
        while extensions.pos < len(extensions.data):
            kind = extensions.number(2); extensions.vector(2)
            if kind in seen:
                raise QSploitError("INVALID_TLS", "A Certificate entry contains duplicate extensions.")
            seen.add(kind)
        if leaf is None:
            try:
                leaf = x509.load_der_x509_certificate(der).public_key()
            except (ValueError, UnsupportedAlgorithm):
                raise QSploitError("INVALID_TLS", "The TLS 1.3 certificate key is invalid or unsupported.") from None
    if not isinstance(leaf, rsa.RSAPublicKey) or leaf.key_size > MAX_RSA_BITS:
        raise QSploitError("UNSUPPORTED_SIGNATURE", "TLS 1.3 currently verifies RSA-PSS server authentication only.")
    return leaf


def _certificate_verify(wire: bytes, key, transcript: bytes, client_extensions: dict[int, bytes], cipher_suite: int = 0x1301) -> None:
    hash_name, _, _ = cipher_parameters(cipher_suite)
    reader = _Reader(wire[4:])
    scheme, signature = reader.number(2), reader.vector(2); reader.end()
    digest_types = {0x0804: hashes.SHA256, 0x0805: hashes.SHA384, 0x0806: hashes.SHA512}
    if scheme not in digest_types:
        raise QSploitError("UNSUPPORTED_SIGNATURE", "This TLS 1.3 CertificateVerify signature scheme is unsupported.")
    offers = _Reader(client_extensions.get(13, b""))
    algorithms = offers.vector(2); offers.end()
    if not algorithms or len(algorithms) % 2 or scheme not in [int.from_bytes(algorithms[i:i+2], "big") for i in range(0, len(algorithms), 2)]:
        raise QSploitError("INVALID_TLS", "The CertificateVerify signature scheme was not offered by the client.")
    digest = digest_types[scheme]()
    signed = b" " * 64 + b"TLS 1.3, server CertificateVerify\x00" + hashlib.new(hash_name, transcript).digest()
    try:
        key.verify(signature, signed, padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size), digest)
    except (InvalidSignature, ValueError):
        raise QSploitError("SERVER_SIGNATURE_FAILED", "TLS 1.3 CertificateVerify does not authenticate the captured handshake.") from None


def _encrypted_extensions(wire: bytes, client_extensions: dict[int, bytes]) -> str | None:
    reader = _Reader(wire[4:])
    if len(reader.data) < 2:
        raise QSploitError("INVALID_TLS", "EncryptedExtensions is missing its extension vector.")
    extensions = _extensions(reader)
    if 42 in extensions:
        raise QSploitError("EARLY_DATA_UNSUPPORTED", "TLS 1.3 early data is not implemented.")
    if any(kind in extensions for kind in (41, 43, 51, 13)):
        raise QSploitError("INVALID_TLS", "A TLS 1.3 extension appears in the wrong handshake message.")
    if 16 not in extensions:
        return None
    selected = _alpn(extensions[16])
    offered_reader = _Reader(client_extensions.get(16, b""))
    offered = _Reader(offered_reader.vector(2)); offered_reader.end()
    protocols = []
    while offered.pos < len(offered.data):
        protocols.append(offered.vector(1))
    if selected.encode("ascii", "replace") not in protocols:
        raise QSploitError("INVALID_TLS", "The encrypted ALPN selection was not offered by the client.")
    return selected


def _new_session_ticket(wire: bytes) -> None:
    reader = _Reader(wire[4:])
    lifetime = reader.number(4); reader.number(4); reader.vector(1)
    ticket = reader.vector(2)
    if lifetime > 604800 or not ticket:
        raise QSploitError("INVALID_TLS", "The TLS 1.3 session ticket has an invalid lifetime or empty ticket.")
    if reader.pos + 2 > len(reader.data):
        raise QSploitError("INVALID_TLS", "The session ticket is missing its extension vector.")
    extensions = _extensions(reader)
    if any(kind != 42 for kind in extensions) or (42 in extensions and len(extensions[42]) != 4):
        raise QSploitError("INVALID_TLS", "The session ticket contains unsupported or malformed extensions.")


def _direction(session: ParsedTLS, direction: str, handshake_secret: bytes, master: bytes,
               initial_transcript: bytes, client_extensions: dict[int, bytes], application_secret: bytes | None = None):
    suite = session.cipher_suite
    _, hash_length, _ = cipher_parameters(suite)
    transcript = initial_transcript
    secret, sequence, count, updates = handshake_secret, 0, 0, 0
    pending, application = bytearray(), bytearray()
    finished, active, closed = False, False, False
    expected = [8, 11, 15, 20] if direction == "s2c" else [20]
    certificate_key, alpn = None, None
    warnings, handshake_count = [], 0
    for record in (r for r in session.records if r.direction == direction):
        if record.content_type == 20:
            if finished or record.fragment != b"\x01" or pending:
                raise QSploitError("INVALID_TLS", "A TLS 1.3 compatibility ChangeCipherSpec is misplaced or malformed.")
            continue
        if record.content_type == 22 and not active:
            continue  # parsed and checked as exactly CH or SH before this function
        if record.content_type != 23:
            raise QSploitError("INVALID_TLS", "A TLS 1.3 protected epoch contains a cleartext or unsupported record.")
        active = True
        kind, payload = decrypt_record(record, secret, sequence, suite)
        sequence += 1; count += 1
        if closed:
            raise QSploitError("INVALID_TLS", "A record follows this direction's TLS close_notify.")
        if kind == 22:
            pending.extend(payload)
            while len(pending) >= 4:
                size = int.from_bytes(pending[1:4], "big")
                if size > MAX_HANDSHAKE_BYTES or handshake_count >= MAX_HANDSHAKE_MESSAGES:
                    raise QSploitError("RESOURCE_LIMIT", "TLS 1.3 handshake processing exceeds the configured limit.")
                if len(pending) < 4 + size:
                    break
                wire = bytes(pending[:4 + size]); del pending[:4 + size]
                handshake_count += 1
                message = wire[0]
                if not finished:
                    if message in (13, 11) and (direction == "c2s" or message == 13):
                        raise QSploitError("CLIENT_AUTH_UNSUPPORTED", "TLS 1.3 client authentication is not implemented.")
                    if not expected or message != expected.pop(0):
                        raise QSploitError("INCOMPLETE_HANDSHAKE", "The encrypted TLS 1.3 handshake has an unsupported message order.")
                    if message == 8:
                        alpn = _encrypted_extensions(wire, client_extensions)
                    elif message == 11:
                        certificate_key = _certificate_key(wire)
                    elif message == 15:
                        _certificate_verify(wire, certificate_key, transcript, client_extensions, suite)
                    elif message == 20:
                        if size != hash_length or not hmac.compare_digest(wire[4:], finished_verify_data(handshake_secret, transcript, suite)):
                            raise QSploitError("FINISHED_VERIFY_FAILED", "A TLS 1.3 Finished does not authenticate the captured transcript.")
                        if pending:
                            raise QSploitError("INVALID_TLS", "A handshake crosses the TLS 1.3 Finished key boundary.")
                        finished = True
                    transcript += wire
                    if finished:
                        secret = (derive_secret(master, "s ap traffic", transcript, suite) if direction == "s2c" else application_secret)
                        sequence = 0
                else:
                    if message == 4 and direction == "s2c":
                        _new_session_ticket(wire)
                    elif message == 24:
                        if wire[4:] not in (b"\x00", b"\x01") or pending:
                            raise QSploitError("INVALID_TLS", "A TLS 1.3 KeyUpdate has invalid framing or crosses its key boundary.")
                        updates += 1
                        if updates > MAX_KEY_UPDATES:
                            raise QSploitError("RESOURCE_LIMIT", "The capture exceeds the TLS 1.3 KeyUpdate limit.")
                        secret = hkdf_expand_label(secret, "traffic upd", b"", hash_length, suite)
                        sequence = 0
                    elif message == 13:
                        raise QSploitError("CLIENT_AUTH_UNSUPPORTED", "Post-handshake client authentication is unsupported.")
                    else:
                        raise QSploitError("UNSUPPORTED_TLS_HANDSHAKE", "This TLS 1.3 post-handshake message is unsupported.")
        elif kind == 23:
            if not finished or pending:
                raise QSploitError("FINISHED_VERIFY_FAILED", "Application bytes precede a complete authenticated handshake.")
            application.extend(payload)
        else:
            if pending or len(payload) != 2:
                raise QSploitError("INVALID_TLS", "A TLS 1.3 alert has invalid framing.")
            if payload[1] == 0:
                closed = True
            elif payload[1] == 90:
                warnings.append("TLS_WARNING_ALERT")
            else:
                raise QSploitError("TLS_FATAL_ALERT", "The TLS 1.3 capture contains a terminating error alert.")
    if not finished or pending:
        raise QSploitError("INCOMPLETE_HANDSHAKE", "A TLS 1.3 Finished or post-handshake message is incomplete.")
    return bytes(application), transcript, count, closed, alpn, warnings


def decrypt_tls13(session: ParsedTLS, secret: RecoveredSecret) -> ApplicationStreams:
    problem_for(session)
    if session.tls_version != 0x0304 or session.cipher_suite not in CIPHER_PARAMETERS or session.ecdhe is None:
        raise QSploitError("UNSUPPORTED_CIPHER", "This TLS 1.3 schedule supports AES-128-GCM/SHA-256 and AES-256-GCM/SHA-384 only.")
    client = [h.wire for h in session.clear_handshakes if h.direction == "c2s"]
    server = [h.wire for h in session.clear_handshakes if h.direction == "s2c"]
    if len(client) != 1 or client[0][0] != 1 or len(server) != 1 or server[0][0] != 2:
        raise QSploitError("HRR_UNSUPPORTED", "TLS 1.3 HelloRetryRequest and repeated hellos are not implemented.")
    hello_transcript = client[0] + server[0]
    client_extensions = _hello(client[0], True)["ext"]
    if 42 in client_extensions:
        raise QSploitError("EARLY_DATA_UNSUPPORTED", "TLS 1.3 early data is not implemented.")
    chs, shs, master = handshake_secrets(ecdhe_shared_secret(session.ecdhe, secret), hello_transcript, session.cipher_suite)
    server_result = _direction(session, "s2c", shs, master, hello_transcript, client_extensions)
    client_application = derive_secret(master, "c ap traffic", server_result[1], session.cipher_suite)
    client_result = _direction(session, "c2s", chs, master, server_result[1], client_extensions, client_application)
    warnings = list(session.warnings) + server_result[5] + client_result[5]
    if not (server_result[3] and client_result[3]):
        warnings.append("CONNECTION_END_NOT_CAPTURED")
    return ApplicationStreams(client_result[0], server_result[0], True, True, client_result[2] + server_result[2],
                              client_result[3], server_result[3], tuple(dict.fromkeys(warnings)),
                              negotiated_alpn=server_result[4], authentication="RSA")
