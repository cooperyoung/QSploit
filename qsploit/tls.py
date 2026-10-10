"""TLS framing and negotiated public metadata; no secret material leaves here.

Registry: IANA TLS Parameters, RFC 8446 and RFC 10024 (2026-10-10).
Unknown numeric suites/groups stay unknown; offers never establish a selection.
"""
from __future__ import annotations

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .models import ECDHEKeyExchange, ECDLogProblem, FFDHEKeyExchange, FFDLogProblem, Handshake, ParsedTLS, PublicProblem, QSploitError, Record, RSAKeyTransport, RSAProblem, TCPConnection
from .groups import FFDHE2048_G, FFDHE2048_ORDER, FFDHE2048_P, normalize_x25519_point, validate_ffdhe2048, validate_p256_point, validate_x25519_point

MAX_HANDSHAKE_BYTES = 1024 * 1024
MAX_RECORDS = 200_000
MAX_HANDSHAKE_MESSAGES = 4096
MAX_RSA_BITS = 16384
SUPPORTED_RSA_SUITES = frozenset({0x009c, 0x009d})
SUPPORTED_DHE_SUITES = frozenset({0x009e, 0x009f, 0xccaa})
SUPPORTED_ECDHE_SUITES = frozenset({0xc02f, 0xc030, 0xcca8})
SUPPORTED_TLS12_SUITES = SUPPORTED_RSA_SUITES | SUPPORTED_DHE_SUITES | SUPPORTED_ECDHE_SUITES

SUITES = {
    0x002f: ("TLS_RSA_WITH_AES_128_CBC_SHA", "rsa_transport", "RSA"),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "rsa_transport", "RSA"),
    0x009c: ("TLS_RSA_WITH_AES_128_GCM_SHA256", "rsa_transport", "RSA"),
    0x009d: ("TLS_RSA_WITH_AES_256_GCM_SHA384", "rsa_transport", "RSA"),
    0x009e: ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "dhe", "RSA"),
    0x009f: ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "dhe", "RSA"),
    0xccaa: ("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "dhe", "RSA"),
    0xcca8: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ecdhe", "RSA"),
    0xc02f: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ecdhe", "RSA"),
    0xc030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ecdhe", "RSA"),
    0xc02b: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ecdhe", "ECDSA"),
    0xc02c: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ecdhe", "ECDSA"),
    0x00a8: ("TLS_PSK_WITH_AES_128_GCM_SHA256", "psk", "PSK"),
    0x00aa: ("TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", "psk_dhe", "PSK"),
    0x1301: ("TLS_AES_128_GCM_SHA256", "unknown", None),
    0x1302: ("TLS_AES_256_GCM_SHA384", "unknown", None),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "unknown", None),
}
GROUPS = {
    23: ("secp256r1", "ecdhe"), 24: ("secp384r1", "ecdhe"),
    25: ("secp521r1", "ecdhe"), 29: ("X25519", "ecdhe"), 30: ("X448", "ecdhe"),
    **{i: (f"ffdhe{bits}", "dhe") for i, bits in zip(range(256, 261), (2048, 3072, 4096, 6144, 8192))},
    512: ("ML-KEM-512", "pq"), 513: ("ML-KEM-768", "pq"), 514: ("ML-KEM-1024", "pq"),
    4587: ("SecP256r1MLKEM768", "hybrid_pq"), 4588: ("X25519MLKEM768", "hybrid_pq"),
    4589: ("SecP384r1MLKEM1024", "hybrid_pq"),
    25497: ("X25519Kyber768Draft00 (obsolete)", "hybrid_pq"),
    25498: ("SecP256r1Kyber768Draft00 (obsolete)", "hybrid_pq"),
}
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def cipher_suite_name(value: int | None) -> str | None:
    return None if value is None else SUITES.get(value, (f"Unknown (0x{value:04x})",))[0]


def group_name(value: int | None) -> str | None:
    return None if value is None else GROUPS.get(value, (f"Unknown ({value})",))[0]


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.pos + size > len(self.data):
            raise QSploitError("INCOMPLETE_HANDSHAKE", "A TLS handshake field has an invalid or truncated length.")
        value = self.data[self.pos:self.pos + size]
        self.pos += size
        return value

    def number(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")

    def vector(self, width: int) -> bytes:
        return self.take(self.number(width))

    def end(self):
        if self.pos != len(self.data):
            raise QSploitError("INVALID_TLS", "Unexpected trailing bytes in a TLS structure.")


def frame_records(stream: bytes, direction: str, *, allow_incomplete: bool = False) -> tuple[Record, ...]:
    records, pos = [], 0
    while pos < len(stream):
        if len(records) >= MAX_RECORDS:
            raise QSploitError("RESOURCE_LIMIT", "A TCP direction exceeds the TLS record limit.")
        if len(stream) - pos < 5:
            if allow_incomplete:
                break
            raise QSploitError("INCOMPLETE_HANDSHAKE", "The capture ends inside a TLS record header.")
        kind, version, size = stream[pos], int.from_bytes(stream[pos + 1:pos + 3], "big"), int.from_bytes(stream[pos + 3:pos + 5], "big")
        if kind not in (20, 21, 22, 23, 24) or not 0x0300 <= version <= 0x0304:
            if allow_incomplete:
                break
            raise QSploitError("INVALID_TLS", "The TCP stream contains an invalid TLS record header.")
        if size > 18432:
            if allow_incomplete:
                break
            raise QSploitError("INVALID_TLS", "A TLS record exceeds the protocol ciphertext limit.")
        if pos + 5 + size > len(stream):
            if allow_incomplete:
                break
            raise QSploitError("INCOMPLETE_HANDSHAKE", "The capture ends inside a TLS record.")
        records.append(Record(direction, pos, kind, version, stream[pos + 5:pos + 5 + size]))
        pos += 5 + size
    return tuple(records)


def clear_handshakes(records: tuple[Record, ...], *, tls13: bool = False) -> tuple[Handshake, ...]:
    pending = bytearray()
    first_offset = 0
    messages = []
    for record in records:
        if tls13 and record.content_type == 20 and record.fragment == b"\x01" and not pending:
            continue
        if record.content_type in (20, 23):
            break
        if record.content_type != 22:
            if pending:
                raise QSploitError("INCOMPLETE_HANDSHAKE", "A handshake message was interrupted by a different record type.")
            continue
        if len(record.fragment) > 16384:
            raise QSploitError("INVALID_TLS", "A cleartext TLS record exceeds the protocol plaintext limit.")
        if not pending:
            first_offset = record.offset
        pending.extend(record.fragment)
        while len(pending) >= 4:
            size = int.from_bytes(pending[1:4], "big")
            if size > MAX_HANDSHAKE_BYTES:
                raise QSploitError("RESOURCE_LIMIT", "A TLS handshake exceeds the 1 MiB limit.")
            if len(pending) < size + 4:
                break
            wire = bytes(pending[:size + 4])
            del pending[:size + 4]
            if len(messages) >= MAX_HANDSHAKE_MESSAGES:
                raise QSploitError("RESOURCE_LIMIT", "A TCP direction exceeds the handshake message limit.")
            messages.append(Handshake(record.direction, first_offset, wire))
            first_offset = record.offset
    if pending:
        raise QSploitError("INCOMPLETE_HANDSHAKE", "The capture has an incomplete cleartext handshake message.")
    return tuple(messages)


def _extensions(reader: _Reader) -> dict[int, bytes]:
    if reader.pos == len(reader.data):
        return {}
    ext_reader = _Reader(reader.vector(2))
    reader.end()
    result = {}
    while ext_reader.pos < len(ext_reader.data):
        kind, value = ext_reader.number(2), ext_reader.vector(2)
        if kind in result:
            raise QSploitError("INVALID_TLS", "A hello contains duplicate TLS extensions.")
        result[kind] = value
    return result


def _hello(wire: bytes, client: bool) -> dict:
    r = _Reader(wire[4:])
    version, random, session_id = r.number(2), r.take(32), r.vector(1)
    if len(session_id) > 32:
        raise QSploitError("INVALID_TLS", "A TLS session ID exceeds its protocol limit.")
    if client:
        suites, compression = r.vector(2), r.vector(1)
        if not suites or len(suites) % 2 or not compression:
            raise QSploitError("INVALID_TLS", "A ClientHello has invalid cipher/compression offers.")
        selected = None
    else:
        selected, compression = r.number(2), r.number(1)
    ext = _extensions(r)
    if 23 in ext and ext[23] != b"":
        raise QSploitError("INVALID_TLS", "The extended-master-secret extension must be empty.")
    return dict(version=version, random=random, session_id=session_id,
                suites=suites if client else None, compression=compression, suite=selected, ext=ext)


def _sni(data: bytes) -> str | None:
    r = _Reader(data)
    entries = _Reader(r.vector(2))
    r.end()
    names = []
    while entries.pos < len(entries.data):
        kind, name = entries.number(1), entries.vector(2)
        if kind == 0:
            if names:
                raise QSploitError("INVALID_TLS", "Duplicate host_name in SNI.")
            try:
                names.append(name.decode("ascii"))
            except UnicodeDecodeError:
                raise QSploitError("INVALID_TLS", "The SNI host_name is not ASCII.") from None
    return names[0] if names else None


def _alpn(data: bytes) -> str:
    r = _Reader(data)
    protocols = _Reader(r.vector(2))
    r.end()
    selected = protocols.vector(1)
    protocols.end()
    if not selected:
        raise QSploitError("INVALID_TLS", "The selected ALPN value is empty.")
    return selected.decode("ascii", "replace")


def _leaf_key(wire: bytes):
    r = _Reader(wire[4:])
    certs = _Reader(r.vector(3))
    r.end()
    leaf = certs.vector(3)
    while certs.pos < len(certs.data):
        certs.vector(3)
    try:
        return x509.load_der_x509_certificate(leaf).public_key()
    except (ValueError, UnsupportedAlgorithm):
        raise QSploitError("INVALID_TLS", "The captured leaf certificate or its public key is unsupported or invalid.") from None


def _dhe_key_exchange(server_wire: bytes, client_wire: bytes, certificate_wire: bytes,
                      client_random: bytes, server_random: bytes, client_extensions: dict[int, bytes]) -> FFDHEKeyExchange:
    reader = _Reader(server_wire[4:])
    p_bytes, g_bytes, y_bytes = reader.vector(2), reader.vector(2), reader.vector(2)
    if not p_bytes or not g_bytes or not y_bytes:
        raise QSploitError("INVALID_TLS", "The DH ServerKeyExchange contains an empty public parameter.")
    parameters_wire = reader.data[:reader.pos]
    p, g, server_public = (int.from_bytes(value, "big") for value in (p_bytes, g_bytes, y_bytes))
    client_reader = _Reader(client_wire[4:])
    client_bytes = client_reader.vector(2)
    client_reader.end()
    if not client_bytes:
        raise QSploitError("INVALID_TLS", "The DH ClientKeyExchange contains an empty public share.")
    client_public = int.from_bytes(client_bytes, "big")
    validate_ffdhe2048(p, g, FFDHE2048_ORDER, server_public, client_public)
    if 10 in client_extensions:
        groups_reader = _Reader(client_extensions[10])
        group_bytes = groups_reader.vector(2)
        groups_reader.end()
        if not group_bytes or len(group_bytes) % 2:
            raise QSploitError("INVALID_TLS", "The client's supported groups have invalid framing.")
        offered_groups = [int.from_bytes(group_bytes[i:i + 2], "big") for i in range(0, len(group_bytes), 2)]
        if any(256 <= group <= 511 for group in offered_groups) and 256 not in offered_groups:
            raise QSploitError("INVALID_TLS", "The selected ffdhe2048 group was not offered by the client.")
    _verify_server_signature(reader, parameters_wire, certificate_wire, client_random, server_random, client_extensions)
    return FFDHEKeyExchange(p, g, server_public, client_public, FFDHE2048_ORDER)


def _verify_server_signature(reader: _Reader, parameters_wire: bytes, certificate_wire: bytes,
                             client_random: bytes, server_random: bytes, client_extensions: dict[int, bytes]) -> None:
    scheme, signature = reader.number(2), reader.vector(2)
    reader.end()
    offered = client_extensions.get(13)
    if offered is None:
        raise QSploitError("UNSUPPORTED_SIGNATURE", "Ephemeral key exchange requires an explicit client signature-algorithms offer.")
    algorithms = _Reader(offered)
    offered_bytes = algorithms.vector(2)
    algorithms.end()
    if not offered_bytes or len(offered_bytes) % 2:
        raise QSploitError("INVALID_TLS", "The offered signature algorithms have invalid framing.")
    if scheme not in [int.from_bytes(offered_bytes[i:i + 2], "big") for i in range(0, len(offered_bytes), 2)]:
        raise QSploitError("INVALID_TLS", "The server's signature algorithm was not offered by the client.")
    digest_types = {0x0401: hashes.SHA256, 0x0501: hashes.SHA384, 0x0601: hashes.SHA512,
                    0x0804: hashes.SHA256, 0x0805: hashes.SHA384, 0x0806: hashes.SHA512}
    if scheme not in digest_types:
        raise QSploitError("UNSUPPORTED_SIGNATURE", "This ServerKeyExchange signature scheme is not implemented.")
    key = _leaf_key(certificate_wire)
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size > MAX_RSA_BITS:
        raise QSploitError("INVALID_RSA_KEY", "This ephemeral exchange requires a supported RSA certificate signing key.")
    digest = digest_types[scheme]()
    signature_padding = padding.PKCS1v15() if scheme < 0x0800 else padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size)
    if len(signature) != (key.key_size + 7) // 8:
        raise QSploitError("SERVER_SIGNATURE_FAILED", "The captured server signature has an invalid width.")
    try:
        key.verify(signature, client_random + server_random + parameters_wire, signature_padding, digest)
    except (InvalidSignature, ValueError):
        raise QSploitError("SERVER_SIGNATURE_FAILED", "The certificate key does not verify the captured parameters and hello randoms.") from None


def _ecdhe_key_exchange(server_wire: bytes, client_wire: bytes, certificate_wire: bytes,
                        client_random: bytes, server_random: bytes, client_extensions: dict[int, bytes],
                        server_extensions: dict[int, bytes]) -> ECDHEKeyExchange:
    reader = _Reader(server_wire[4:])
    if reader.number(1) != 3:
        raise QSploitError("UNSUPPORTED_GROUP", "Only named-curve ECDHE is supported.")
    group, server_public = reader.number(2), reader.vector(1)
    parameters_wire = reader.data[:reader.pos]
    if group not in (23, 29):
        raise QSploitError("UNSUPPORTED_GROUP", "ECDHE recovery currently supports secp256r1 and X25519 only.")
    client_reader = _Reader(client_wire[4:])
    client_public = client_reader.vector(1)
    client_reader.end()
    validate_point = validate_p256_point if group == 23 else validate_x25519_point
    validate_point(server_public)
    validate_point(client_public)
    if 10 in client_extensions:
        groups_reader = _Reader(client_extensions[10])
        offered = groups_reader.vector(2)
        groups_reader.end()
        if not offered or len(offered) % 2:
            raise QSploitError("INVALID_TLS", "The client's supported groups have invalid framing.")
        if group not in [int.from_bytes(offered[i:i + 2], "big") for i in range(0, len(offered), 2)]:
            raise QSploitError("INVALID_TLS", "The selected ECDHE group was not offered by the client.")
    for extensions in (client_extensions, server_extensions):
        if 11 in extensions:
            formats_reader = _Reader(extensions[11])
            formats = formats_reader.vector(1)
            formats_reader.end()
            if not formats:
                raise QSploitError("INVALID_TLS", "The EC point-formats extension must contain a nonempty list.")
            if group == 23 and 0 not in formats:
                raise QSploitError("UNSUPPORTED_POINT_FORMAT", "P-256 ECDHE recovery requires negotiated uncompressed points.")
    if 11 in server_extensions and 11 not in client_extensions:
        raise QSploitError("INVALID_TLS", "The server returned an unoffered EC point-formats extension.")
    _verify_server_signature(reader, parameters_wire, certificate_wire, client_random, server_random, client_extensions)
    return ECDHEKeyExchange(group, server_public, client_public)


def parse_tls(connection: TCPConnection) -> ParsedTLS:
    state = dict(id=connection.id, protocol="tcp", client=None, server=None,
                 tls_version=None, cipher_suite=None, compression=None, sni=None, alpn=None,
                 authentication=None, kex="unknown", selected_group=None, psk_selected=False,
                 resumed=False, ems=None, client_hello_version=None, client_random=None,
                 server_random=None, rsa=None, records=(), clear_handshakes=(), dhe=None, ecdhe=None)
    blockers, warnings = list(connection.blockers), list(connection.warnings)
    a, b = connection.a_to_b, connection.b_to_a
    looks_tls = lambda s: len(s) >= 3 and s[0] in (20, 21, 22, 23, 24) and s[1] == 3 and s[2] <= 4
    if not (looks_tls(a) or looks_tls(b)):
        return ParsedTLS(**state, blockers=tuple(blockers), warnings=tuple(warnings))
    state["protocol"] = "tls"
    try:
        def framed(stream, direction):
            try:
                return frame_records(stream, direction)
            except QSploitError as exc:
                if exc.code == "RESOURCE_LIMIT":
                    raise
                blockers.append(exc.code)
                return frame_records(stream, direction, allow_incomplete=True)
        ar, br = framed(a, "c2s"), framed(b, "s2c")
        ah, bh = clear_handshakes(ar), clear_handshakes(br)
        a_client = any(h.wire[0] == 1 for h in ah)
        b_client = any(h.wire[0] == 1 for h in bh)
        if a_client and b_client:
            raise QSploitError("AMBIGUOUS_CONNECTION", "Both TCP directions contain a ClientHello.")
        if b_client or (not a_client and any(h.wire[0] == 2 for h in ah)):
            ar, br = framed(b, "c2s"), framed(a, "s2c")
            ah, bh = clear_handshakes(ar), clear_handshakes(br)
            state.update(client=connection.b, server=connection.a)
        else:
            state.update(client=connection.a, server=connection.b)
        if any(h.wire[0] == 2 and h.wire[6:38] == HRR_RANDOM for h in bh):
            ah, bh = clear_handshakes(ar, tls13=True), clear_handshakes(br, tls13=True)
        state.update(records=ar + br, clear_handshakes=ah + bh)
        client_hellos = [h for h in ah if h.wire[0] == 1]
        server_hellos = [h for h in bh if h.wire[0] == 2]
        if not client_hellos:
            raise QSploitError("INCOMPLETE_HANDSHAKE", "The aligned ClientHello was not captured.")
        if not ah or ah[0].wire[0] != 1:
            raise QSploitError("INCOMPLETE_HANDSHAKE", "The stream does not begin with a complete ClientHello.")
        ch = _hello(client_hellos[-1].wire, True)
        state.update(client_hello_version=ch["version"], client_random=ch["random"])
        if 0 in ch["ext"]:
            state["sni"] = _sni(ch["ext"][0])
        if not server_hellos:
            raise QSploitError("INCOMPLETE_HANDSHAKE", "The final ServerHello was not captured.")
        servers = [_hello(h.wire, False) for h in server_hellos]
        final = [hello for hello in servers if hello["random"] != HRR_RANDOM]
        if not final:
            raise QSploitError("INCOMPLETE_HANDSHAKE", "Only HelloRetryRequest was captured; no exchange is selected yet.")
        sh = final[-1]
        version = sh["version"]
        if 43 in sh["ext"]:
            r = _Reader(sh["ext"][43]); version = r.number(2); r.end()
        state.update(tls_version=version, cipher_suite=sh["suite"], compression=sh["compression"], server_random=sh["random"])
        offered_suites = [int.from_bytes(ch["suites"][i:i + 2], "big") for i in range(0, len(ch["suites"]), 2)]
        if sh["compression"] not in ch["compression"]:
            raise QSploitError("INVALID_TLS", "The selected compression method was not offered by the client.")
        if sh["suite"] not in offered_suites:
            raise QSploitError("INVALID_TLS", "The selected cipher suite was not offered by the client.")
        if version == 0x0304:
            if len(final) != 1:
                blockers.append("RENEGOTIATION_UNSUPPORTED")
            state["ems"] = False
            state["psk_selected"] = 41 in sh["ext"]
            if 41 in sh["ext"] and len(sh["ext"][41]) != 2:
                raise QSploitError("INVALID_TLS", "The selected PSK extension has an invalid length.")
            if 51 in sh["ext"]:
                r = _Reader(sh["ext"][51]); group = r.number(2); share = r.vector(2); r.end()
                if not share:
                    raise QSploitError("INVALID_TLS", "The selected key share is empty.")
                state["selected_group"] = group
                state["kex"] = GROUPS.get(group, ("unknown", "unknown"))[1]
                if state["psk_selected"] and state["kex"] in ("ecdhe", "dhe"):
                    state["kex"] = "psk_" + state["kex"]
            elif state["psk_selected"]:
                state["kex"] = "psk"
            if len(client_hellos) != 1 or len(server_hellos) != 1 or any(hello["random"] == HRR_RANDOM for hello in servers):
                blockers.append("HRR_UNSUPPORTED")
            if state["psk_selected"]:
                blockers.append("PSK_UNSUPPORTED")
            if 42 in ch["ext"]:
                blockers.append("EARLY_DATA_UNSUPPORTED")
            if sh["suite"] not in (0x1301, 0x1302, 0x1303):
                blockers.append("UNSUPPORTED_CIPHER")
            if state["selected_group"] == 256 and sh["suite"] != 0x1301:
                blockers.append("UNSUPPORTED_CIPHER")
            if state["selected_group"] not in (23, 29, 256):
                blockers.append("UNSUPPORTED_GROUP")
            if not blockers:
                if ch["version"] != 0x0303 or sh["version"] != 0x0303 or sh["compression"] != 0 or sh["session_id"] != ch["session_id"]:
                    raise QSploitError("INVALID_TLS", "TLS 1.3 legacy hello fields are inconsistent.")
                versions_reader = _Reader(ch["ext"].get(43, b""))
                versions = versions_reader.vector(1); versions_reader.end()
                if len(versions) % 2 or b"\x03\x04" not in [versions[i:i + 2] for i in range(0, len(versions), 2)]:
                    raise QSploitError("INVALID_TLS", "TLS 1.3 was not offered by the client.")
                if any(extension not in (43, 51) for extension in sh["ext"]):
                    raise QSploitError("INVALID_TLS", "The full TLS 1.3 ServerHello has an invalid extension.")
                if [h.wire[0] for h in ah] != [1] or [h.wire[0] for h in bh] != [2]:
                    raise QSploitError("INCOMPLETE_HANDSHAKE", "Exactly one ClientHello and ServerHello are required.")
                shares_reader = _Reader(ch["ext"].get(51, b""))
                shares = _Reader(shares_reader.vector(2)); shares_reader.end()
                offered_shares = {}
                while shares.pos < len(shares.data):
                    offered_group, offered_share = shares.number(2), shares.vector(2)
                    if offered_group in offered_shares or not offered_share:
                        raise QSploitError("INVALID_TLS", "Client key shares are empty or duplicated.")
                    offered_shares[offered_group] = offered_share
                group = state["selected_group"]
                groups_reader = _Reader(ch["ext"].get(10, b""))
                groups = groups_reader.vector(2); groups_reader.end()
                if not groups or len(groups) % 2 or group not in [int.from_bytes(groups[i:i+2], "big") for i in range(0, len(groups), 2)] or group not in offered_shares:
                    raise QSploitError("INVALID_TLS", "The selected TLS 1.3 group has no matching offered key share.")
                if group == 256:
                    # TLS 1.3 encodes named finite-field shares at modulus width,
                    # including leading zeros (RFC 8446 section 4.2.8.1).
                    if len(share) != 256 or len(offered_shares[group]) != 256:
                        raise QSploitError("INVALID_DH_PUBLIC", "TLS 1.3 ffdhe2048 shares require exactly 256 bytes.")
                    server_public = int.from_bytes(share, "big")
                    client_public = int.from_bytes(offered_shares[group], "big")
                    validate_ffdhe2048(FFDHE2048_P, FFDHE2048_G, FFDHE2048_ORDER, server_public, client_public)
                    state["dhe"] = FFDHEKeyExchange(FFDHE2048_P, FFDHE2048_G, server_public, client_public, FFDHE2048_ORDER)
                else:
                    validate_point = validate_p256_point if group == 23 else validate_x25519_point
                    validate_point(share)
                    validate_point(offered_shares[group])
                    state["ecdhe"] = ECDHEKeyExchange(group, share, offered_shares[group])
                for records in (ar, br):
                    if not any(record.content_type == 23 for record in records):
                        blockers.append("INCOMPLETE_HANDSHAKE")
        else:
            if len(client_hellos) != 1 or len(server_hellos) != 1 or any(h.wire[0] == 0 for h in ah + bh):
                blockers.append("RENEGOTIATION_UNSUPPORTED")
            _, kex, auth = SUITES.get(sh["suite"], (None, "unknown", None))
            state.update(kex=kex, authentication=auth, ems=23 in sh["ext"])
            if state["ems"] and 23 not in ch["ext"]:
                raise QSploitError("INVALID_TLS", "The server selected EMS without a client offer.")
            if 16 in sh["ext"]:
                state["alpn"] = _alpn(sh["ext"][16])
            certs = [h for h in bh if h.wire[0] == 11]
            ckes = [h for h in ah if h.wire[0] == 16]
            has_server_ccs = any(r.content_type == 20 for r in br)
            state["resumed"] = bool((ch["session_id"] and ch["session_id"] == sh["session_id"]) or (not certs and has_server_ccs))
            if state["resumed"]:
                blockers.append("RESUMPTION_UNSUPPORTED")
            if any(h.wire[0] in (11, 15) for h in ah) or any(h.wire[0] == 13 for h in bh):
                blockers.append("CLIENT_AUTH_UNSUPPORTED")
            if kex in ("ecdhe", "psk_ecdhe"):
                skes = [h for h in bh if h.wire[0] == 12]
                if skes and len(skes[0].wire) >= 7 and skes[0].wire[4] == 3:
                    state["selected_group"] = int.from_bytes(skes[0].wire[5:7], "big")
            if kex == "rsa_transport" and certs and ckes:
                if len(certs) != 1 or len(ckes) != 1:
                    raise QSploitError("INVALID_TLS", "The RSA handshake contains duplicate key exchange messages.")
                key = _leaf_key(certs[0].wire)
                if not isinstance(key, rsa.RSAPublicKey):
                    raise QSploitError("INVALID_RSA_KEY", "The selected RSA transport handshake has no RSA leaf public key.")
                r = _Reader(ckes[0].wire[4:]); encrypted = r.vector(2); r.end()
                pub = key.public_numbers()
                if pub.n.bit_length() > MAX_RSA_BITS:
                    raise QSploitError("RESOURCE_LIMIT", "The RSA public key exceeds the configured bit-size limit.")
                state["rsa"] = RSAKeyTransport(pub.n, pub.e, encrypted)
            if kex == "dhe" and sh["suite"] in SUPPORTED_DHE_SUITES:
                skes = [h for h in bh if h.wire[0] == 12]
                if len(certs) == 1 and len(skes) == 1 and len(ckes) == 1:
                    state["dhe"] = _dhe_key_exchange(skes[0].wire, ckes[0].wire, certs[0].wire,
                                                      ch["random"], sh["random"], ch["ext"])
                    state["selected_group"] = 256
                elif not state["resumed"]:
                    blockers.append("INCOMPLETE_HANDSHAKE")
            if kex == "ecdhe" and sh["suite"] in SUPPORTED_ECDHE_SUITES:
                skes = [h for h in bh if h.wire[0] == 12]
                if len(certs) == 1 and len(skes) == 1 and len(ckes) == 1:
                    state["ecdhe"] = _ecdhe_key_exchange(skes[0].wire, ckes[0].wire, certs[0].wire,
                                                          ch["random"], sh["random"], ch["ext"], sh["ext"])
                    state["selected_group"] = state["ecdhe"].group
                elif not state["resumed"]:
                    blockers.append("INCOMPLETE_HANDSHAKE")
            if version != 0x0303:
                blockers.append("UNSUPPORTED_TLS_VERSION")
            if kex not in ("rsa_transport", "dhe", "ecdhe"):
                blockers.append("UNSUPPORTED_KEX")
            if sh["suite"] not in SUPPORTED_TLS12_SUITES:
                blockers.append("UNSUPPORTED_CIPHER")
            if sh["compression"] != 0:
                blockers.append("UNSUPPORTED_COMPRESSION")
            if not state["resumed"] and kex in ("rsa_transport", "dhe", "ecdhe"):
                if not state[{"rsa_transport": "rsa", "dhe": "dhe", "ecdhe": "ecdhe"}[kex]] or not any(h.wire[0] == 14 for h in bh):
                    blockers.append("INCOMPLETE_HANDSHAKE")
                client_kinds = [h.wire[0] for h in ah]
                server_kinds = [h.wire[0] for h in bh]
                if server_kinds and server_kinds[-1] == 4:
                    server_kinds = server_kinds[:-1]
                allowed_server = ([2, 11, 14], [2, 11, 22, 14]) if kex == "rsa_transport" else ([2, 11, 12, 14], [2, 11, 22, 12, 14])
                if client_kinds != [1, 16] or server_kinds not in allowed_server:
                    blockers.append("INCOMPLETE_HANDSHAKE")
                for direction_records in (ar, br):
                    ccs = [i for i, r in enumerate(direction_records) if r.content_type == 20]
                    if not ccs or not any(r.content_type == 22 for r in direction_records[ccs[0] + 1:]):
                        blockers.append("INCOMPLETE_HANDSHAKE")
                    if len(ccs) > 1:
                        blockers.append("RENEGOTIATION_UNSUPPORTED")
                    if ccs and direction_records[ccs[0]].fragment != b"\x01":
                        blockers.append("INVALID_TLS")
                    if ccs and len(direction_records) > ccs[0] + 1 and direction_records[ccs[0] + 1].content_type != 22:
                        blockers.append("INCOMPLETE_HANDSHAKE")
    except QSploitError as exc:
        blockers.append(exc.code)
    return ParsedTLS(**state, blockers=tuple(dict.fromkeys(blockers)), warnings=tuple(dict.fromkeys(warnings)))


def problem_for(session: ParsedTLS) -> PublicProblem:
    if session.blockers:
        code = session.blockers[0]
        raise QSploitError(code, f"This capture cannot enter recovery: {code.replace('_', ' ').lower()}.")
    if session.protocol == "tls" and session.tls_version == 0x0304:
        if session.cipher_suite not in (0x1301, 0x1302, 0x1303):
            raise QSploitError("UNSUPPORTED_CIPHER", "TLS 1.3 currently supports AES-GCM and ChaCha20-Poly1305 only.")
        if session.psk_selected:
            raise QSploitError("PSK_UNSUPPORTED", "Selected TLS 1.3 PSKs are not recoverable from the ephemeral share alone.")
        if session.kex == "dhe" and session.dhe is not None:
            if session.cipher_suite != 0x1301:
                raise QSploitError("UNSUPPORTED_CIPHER", "TLS 1.3 ffdhe2048 currently supports AES-128-GCM only.")
            key = session.dhe
            validate_ffdhe2048(key.p, key.g, key.order, key.server_public, key.client_public)
            return FFDLogProblem(key.p, key.g, key.server_public, key.order)
        if session.ecdhe is None or session.ecdhe.group not in (23, 29):
            raise QSploitError("UNSUPPORTED_GROUP", "TLS 1.3 currently supports P-256, X25519, and ffdhe2048 only.")
        if session.ecdhe.group == 23:
            validate_p256_point(session.ecdhe.server_public)
            validate_p256_point(session.ecdhe.client_public)
            return ECDLogProblem("secp256r1", session.ecdhe.server_public)
        validate_x25519_point(session.ecdhe.server_public)
        validate_x25519_point(session.ecdhe.client_public)
        return ECDLogProblem("x25519", normalize_x25519_point(session.ecdhe.server_public))
    if session.protocol != "tls" or session.tls_version != 0x0303:
        raise QSploitError("UNSUPPORTED_TLS_VERSION", "Recovery currently supports full TLS 1.2 RSA or supported ephemeral sessions only.")
    if session.cipher_suite not in SUPPORTED_TLS12_SUITES:
        raise QSploitError("UNSUPPORTED_CIPHER", "This TLS 1.2 cipher suite is outside the implemented AES-GCM and ChaCha20-Poly1305 paths.")
    if session.compression != 0 or session.ems is None or session.resumed:
        raise QSploitError("INCOMPLETE_HANDSHAKE", "The full uncompressed TLS negotiation is required.")
    if session.kex == "rsa_transport" and session.rsa is not None and session.cipher_suite in SUPPORTED_RSA_SUITES:
        return RSAProblem(session.rsa.n)
    if session.kex == "dhe" and session.dhe is not None and session.cipher_suite in SUPPORTED_DHE_SUITES:
        key = session.dhe
        validate_ffdhe2048(key.p, key.g, key.order, key.server_public, key.client_public)
        return FFDLogProblem(key.p, key.g, key.server_public, key.order)
    if session.kex == "ecdhe" and session.ecdhe is not None and session.cipher_suite in SUPPORTED_ECDHE_SUITES:
        key = session.ecdhe
        if key.group == 23:
            validate_p256_point(key.server_public)
            validate_p256_point(key.client_public)
            return ECDLogProblem("secp256r1", key.server_public)
        if key.group == 29:
            validate_x25519_point(key.server_public)
            validate_x25519_point(key.client_public)
            return ECDLogProblem("x25519", normalize_x25519_point(key.server_public))
        raise QSploitError("UNSUPPORTED_GROUP", "ECDHE recovery currently supports secp256r1 and X25519 only.")
    raise QSploitError("UNSUPPORTED_KEX", "The selected key exchange or its captured public parameters are unsupported.")
