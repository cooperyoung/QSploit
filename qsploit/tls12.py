"""The supported TLS 1.2 RSA/DHE/ECDHE AES-GCM schedules and verification.

RFC 5246 sections 5, 6.3, 7.4.9; RFC 5288 section 3; RFC 7627 section 4.
Application bytes are returned only after both Finished messages and every
captured protected record have authenticated. No fixture or oracle is read here.
"""
from __future__ import annotations

import hashlib
import hmac
import math

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .groups import P256_ORDER, validate_p256_point
from .models import ApplicationStreams, ECDLogSecret, FFDLogSecret, ParsedTLS, QSploitError, RecoveredSecret, RSAFactors
from .tls import MAX_HANDSHAKE_BYTES, problem_for


# RFC 5288: SHA-384 changes the PRF/transcript hash, not GCM tag/nonce sizes.
CIPHER_PARAMETERS = {
    0x009c: ("sha256", 16), 0x009d: ("sha384", 32),
    0x009e: ("sha256", 16), 0x009f: ("sha384", 32),
    0xc02f: ("sha256", 16), 0xc030: ("sha384", 32),
}


def cipher_parameters(cipher_suite: int) -> tuple[str, int]:
    try:
        return CIPHER_PARAMETERS[cipher_suite]
    except KeyError:
        raise QSploitError("UNSUPPORTED_CIPHER", "This TLS cipher suite has no implemented AES-GCM schedule.") from None


def prf(secret: bytes, label: bytes | str, seed: bytes, length: int, hash_name: str = "sha256") -> bytes:
    if hash_name not in {"sha256", "sha384"}:
        raise ValueError("unsupported TLS PRF hash")
    if isinstance(label, str):
        label = label.encode("ascii")
    if length < 0 or length > 1024 * 1024:
        raise ValueError("invalid PRF output length")
    seed = label + seed
    a = seed
    result = bytearray()
    while len(result) < length:
        a = hmac.digest(secret, a, hash_name)
        result.extend(hmac.digest(secret, a + seed, hash_name))
    return bytes(result[:length])


def _transcript(session: ParsedTLS) -> tuple[bytes, tuple[bytes, ...]]:
    client = [h.wire for h in session.clear_handshakes if h.direction == "c2s"]
    server = [h.wire for h in session.clear_handshakes if h.direction == "s2c"]
    if [m[0] for m in client] != [1, 16]:
        raise QSploitError("INCOMPLETE_HANDSHAKE", "A full ClientHello and ClientKeyExchange flight is required.")
    kinds = [m[0] for m in server]
    if kinds.count(14) != 1:
        raise QSploitError("INCOMPLETE_HANDSHAKE", "Exactly one ServerHelloDone is required.")
    done = kinds.index(14)
    allowed = ([2, 11, 14], [2, 11, 22, 14]) if session.kex == "rsa_transport" else ([2, 11, 12, 14], [2, 11, 22, 12, 14])
    if kinds[:done + 1] not in allowed:
        raise QSploitError("INCOMPLETE_HANDSHAKE", "The server handshake flight has unsupported or inconsistent ordering.")
    if server[done][4:]:
        raise QSploitError("INVALID_TLS", "ServerHelloDone must have an empty body.")
    tickets = tuple(server[done + 1:])
    if len(tickets) > 1 or any(m[0] != 4 for m in tickets):
        raise QSploitError("RENEGOTIATION_UNSUPPORTED", "An unexpected later cleartext handshake was captured.")
    for ticket in tickets:
        if len(ticket) < 10 or int.from_bytes(ticket[8:10], "big") != len(ticket) - 10:
            raise QSploitError("INVALID_TLS", "The NewSessionTicket message has an invalid length.")
    # Causal TLS flight order, independent of packet capture timestamp/order.
    through_cke = client[0] + b"".join(server[:done + 1]) + client[1]
    return through_cke, tickets


def recover_premaster(session: ParsedTLS, factors: RecoveredSecret) -> bytes:
    problem_for(session)
    if session.kex == "ecdhe":
        key = session.ecdhe
        assert key is not None
        if not isinstance(factors, ECDLogSecret):
            raise QSploitError("INVALID_RECOVERY_RESULT", "P-256 ECDHE recovery requires a verified scalar result.")
        if type(factors.x) is not int or not 1 <= factors.x < P256_ORDER:
            raise QSploitError("INVALID_DLOG_RESULT", "The recovered P-256 scalar is outside the valid group range.")
        private = ec.derive_private_key(factors.x, ec.SECP256R1())
        public = private.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        if not hmac.compare_digest(public, key.server_public):
            raise QSploitError("INVALID_DLOG_RESULT", "The recovered scalar does not reproduce the captured server point.")
        # RFC 8422 section 5.10: P-256 uses the full 32-byte x-coordinate,
        # preserving leading zeros (unlike finite-field TLS 1.2 DH).
        return private.exchange(ec.ECDH(), validate_p256_point(key.client_public))
    if session.kex == "dhe":
        key = session.dhe
        assert key is not None
        if not isinstance(factors, FFDLogSecret):
            raise QSploitError("INVALID_RECOVERY_RESULT", "DHE recovery requires a verified discrete logarithm result.")
        x = factors.x
        if type(x) is not int or not 1 <= x < key.order or pow(key.g, x, key.p) != key.server_public:
            raise QSploitError("INVALID_DLOG_RESULT", "The recovered exponent does not reproduce the captured server public share.")
        shared = pow(key.client_public, x, key.p)
        # RFC 5246 section 8.1.2: leading zero bytes of Z are stripped.
        return shared.to_bytes((shared.bit_length() + 7) // 8, "big")
    if not isinstance(factors, RSAFactors):
        raise QSploitError("INVALID_RECOVERY_RESULT", "RSA transport recovery requires a verified factor pair.")
    key = session.rsa
    assert key is not None
    p, q = factors.p, factors.q
    if not isinstance(p, int) or not isinstance(q, int) or p <= 1 or q <= 1 or p == q or p * q != key.n:
        raise QSploitError("INVALID_FACTOR_PAIR", "The recovery result is not a nontrivial, distinct factor pair for the captured modulus.")
    lam = math.lcm(p - 1, q - 1)
    if key.e <= 1 or key.e % 2 == 0 or math.gcd(key.e, lam) != 1:
        raise QSploitError("INVALID_RSA_KEY", "The captured RSA exponent is incompatible with the recovered factors.")
    try:
        d = pow(key.e, -1, lam)
        private = rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p),
                                       rsa.RSAPublicNumbers(key.e, key.n)).private_key()
    except (ValueError, TypeError, OverflowError):
        raise QSploitError("INVALID_RSA_KEY", "The recovered factors do not form a valid two-prime RSA private key.") from None
    ciphertext = key.encrypted_premaster
    if len(ciphertext) != (key.n.bit_length() + 7) // 8 or int.from_bytes(ciphertext, "big") >= key.n:
        raise QSploitError("INVALID_PREMASTER", "The captured RSA ciphertext has an invalid width or value.")
    try:
        premaster = private.decrypt(ciphertext, padding.PKCS1v15())
    except ValueError:
        raise QSploitError("INVALID_PREMASTER", "RSA PKCS#1 v1.5 premaster recovery failed.") from None
    if len(premaster) != 48 or session.client_hello_version is None or premaster[:2] != session.client_hello_version.to_bytes(2, "big"):
        raise QSploitError("INVALID_PREMASTER", "The recovered premaster length or ClientHello version is invalid.")
    return premaster


def derive_master_secret(session: ParsedTLS, factors: RecoveredSecret) -> bytes:
    """Internal schedule helper; secret result is never projected into the API."""
    premaster = recover_premaster(session, factors)
    transcript, _ = _transcript(session)
    if session.client_random is None or session.server_random is None or len(session.client_random) != 32 or len(session.server_random) != 32:
        raise QSploitError("INCOMPLETE_HANDSHAKE", "Both complete TLS hello randoms are required.")
    hash_name, _ = cipher_parameters(session.cipher_suite)
    if session.ems:
        return prf(premaster, b"extended master secret", hashlib.new(hash_name, transcript).digest(), 48, hash_name)
    return prf(premaster, b"master secret", session.client_random + session.server_random, 48, hash_name)


def derive_key_block(master: bytes, client_random: bytes, server_random: bytes, cipher_suite: int = 0x009c) -> bytes:
    hash_name, key_length = cipher_parameters(cipher_suite)
    return prf(master, b"key expansion", server_random + client_random, 2 * key_length + 8, hash_name)


def _decrypt_direction(session: ParsedTLS, direction: str, key: bytes, salt: bytes):
    cipher = AESGCM(key)
    active, sequence, finished, close_notify = False, 0, None, False
    pending, application = bytearray(), bytearray()
    warnings = []
    for record in (r for r in session.records if r.direction == direction):
        if not active:
            if record.content_type == 20:
                if record.fragment != b"\x01":
                    raise QSploitError("INVALID_TLS", "ChangeCipherSpec must contain one byte with value one.")
                active = True
            elif record.content_type != 22:
                raise QSploitError("INCOMPLETE_HANDSHAKE", "A non-handshake record precedes the initial ChangeCipherSpec.")
            continue
        if record.content_type == 20:
            raise QSploitError("RENEGOTIATION_UNSUPPORTED", "A second ChangeCipherSpec epoch is unsupported.")
        if record.version != 0x0303:
            raise QSploitError("INVALID_TLS", "Protected TLS 1.2 records must use the negotiated record version.")
        fragment = record.fragment
        if not 24 <= len(fragment) <= 16384 + 24:
            raise QSploitError("INVALID_TLS", "An AES-GCM record has an invalid plaintext/ciphertext length.")
        length = len(fragment) - 24
        aad = sequence.to_bytes(8, "big") + bytes([record.content_type]) + record.version.to_bytes(2, "big") + length.to_bytes(2, "big")
        try:
            plaintext = cipher.decrypt(salt + fragment[:8], fragment[8:], aad)
        except InvalidTag:
            raise QSploitError("AEAD_AUTH_FAILED", "A captured TLS record failed AES-GCM authentication; no session plaintext was released.") from None
        sequence += 1
        if close_notify:
            raise QSploitError("INVALID_TLS", "A protected record follows this direction's close_notify.")
        if record.content_type == 22:
            if finished is not None:
                raise QSploitError("RENEGOTIATION_UNSUPPORTED", "A later protected handshake is unsupported.")
            pending.extend(plaintext)
            while len(pending) >= 4:
                size = int.from_bytes(pending[1:4], "big")
                if size > MAX_HANDSHAKE_BYTES:
                    raise QSploitError("RESOURCE_LIMIT", "A protected handshake exceeds the configured limit.")
                if len(pending) < size + 4:
                    break
                wire = bytes(pending[:size + 4]); del pending[:size + 4]
                if wire[0] != 20 or size != 12 or finished is not None:
                    raise QSploitError("FINISHED_VERIFY_FAILED", "The initial protected handshake is not one complete TLS Finished message.")
                finished = wire
            if finished is not None and pending:
                raise QSploitError("RENEGOTIATION_UNSUPPORTED", "Additional bytes follow the initial Finished message.")
        elif record.content_type == 23:
            if finished is None or pending:
                raise QSploitError("FINISHED_VERIFY_FAILED", "Application data precedes a complete Finished message.")
            application.extend(plaintext)
        elif record.content_type == 21:
            if pending or not plaintext or len(plaintext) % 2:
                raise QSploitError("INVALID_TLS", "A captured TLS alert has invalid framing.")
            for i in range(0, len(plaintext), 2):
                level, description = plaintext[i:i + 2]
                if level not in (1, 2):
                    raise QSploitError("INVALID_TLS", "A TLS alert contains an invalid severity.")
                if level == 2:
                    raise QSploitError("TLS_FATAL_ALERT", "The captured TLS connection terminates with a fatal alert.")
                if description == 0:
                    close_notify = True
                else:
                    warnings.append("TLS_WARNING_ALERT")
        else:
            raise QSploitError("UNSUPPORTED_TLS_RECORD", "This TLS record content type is not supported.")
    if not active or finished is None or pending:
        raise QSploitError("INCOMPLETE_HANDSHAKE", "The capture does not contain a complete protected Finished message in both directions.")
    return bytes(application), finished, sequence, close_notify, warnings


def decrypt_tls12(session: ParsedTLS, factors: RecoveredSecret) -> ApplicationStreams:
    problem_for(session)
    transcript, tickets = _transcript(session)
    master = derive_master_secret(session, factors)
    hash_name, key_length = cipher_parameters(session.cipher_suite)
    block = derive_key_block(master, session.client_random, session.server_random, session.cipher_suite)
    salt_offset = 2 * key_length
    client = _decrypt_direction(session, "c2s", block[:key_length], block[salt_offset:salt_offset + 4])
    server = _decrypt_direction(session, "s2c", block[key_length:salt_offset], block[salt_offset + 4:salt_offset + 8])
    expected_client = prf(master, b"client finished", hashlib.new(hash_name, transcript).digest(), 12, hash_name)
    if not hmac.compare_digest(client[1][4:], expected_client):
        raise QSploitError("FINISHED_VERIFY_FAILED", "The client's Finished does not authenticate the captured handshake transcript.")
    transcript += client[1] + b"".join(tickets)
    expected_server = prf(master, b"server finished", hashlib.new(hash_name, transcript).digest(), 12, hash_name)
    if not hmac.compare_digest(server[1][4:], expected_server):
        raise QSploitError("FINISHED_VERIFY_FAILED", "The server's Finished does not authenticate the captured handshake transcript.")
    warnings = list(session.warnings) + client[4] + server[4]
    if not (client[3] and server[3]):
        warnings.append("CONNECTION_END_NOT_CAPTURED")
    return ApplicationStreams(client[0], server[0], True, True, client[2] + server[2], client[3], server[3], tuple(dict.fromkeys(warnings)))
