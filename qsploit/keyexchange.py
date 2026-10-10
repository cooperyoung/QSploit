"""Local ephemeral shared-secret computation independent of TLS schedules."""
import hmac
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from .groups import P256_ORDER, normalize_x25519_point, validate_ffdhe2048, validate_p256_point, validate_x25519_point
from .models import ECDHEKeyExchange, ECDLogSecret, FFDHEKeyExchange, FFDLogSecret, QSploitError, RecoveredSecret, X25519Secret


def ffdhe_shared_secret(key: FFDHEKeyExchange, secret: RecoveredSecret, *, padded: bool = False) -> bytes:
    validate_ffdhe2048(key.p, key.g, key.order, key.server_public, key.client_public)
    if not isinstance(secret, FFDLogSecret):
        raise QSploitError("INVALID_RECOVERY_RESULT", "DHE recovery requires a verified discrete logarithm result.")
    x = secret.x
    if type(x) is not int or not 1 <= x < key.order or pow(key.g, x, key.p) != key.server_public:
        raise QSploitError("INVALID_DLOG_RESULT", "The recovered exponent does not reproduce the captured server public share.")
    shared = pow(key.client_public, x, key.p)
    # RFC 8446 section 7.4.1 preserves modulus-width leading zeros; RFC 5246
    # section 8.1.2 strips them. The caller explicitly chooses its protocol.
    width = (key.p.bit_length() + 7) // 8 if padded else (shared.bit_length() + 7) // 8
    return shared.to_bytes(width, "big")


def ecdhe_shared_secret(key: ECDHEKeyExchange, secret: RecoveredSecret) -> bytes:
    if key.group not in (23, 29):
        raise QSploitError("UNSUPPORTED_GROUP", "Only P-256 and X25519 shared secrets are implemented.")
    if key.group == 29:
        if not isinstance(secret, X25519Secret):
            raise QSploitError("INVALID_RECOVERY_RESULT", "X25519 recovery requires a byte-encoded private scalar result.")
        if type(secret.scalar) is not bytes or len(secret.scalar) != 32:
            raise QSploitError("INVALID_DLOG_RESULT", "The recovered X25519 scalar must have exactly 32 bytes.")
        private = x25519.X25519PrivateKey.from_private_bytes(secret.scalar)
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if not hmac.compare_digest(public, normalize_x25519_point(key.server_public)):
            raise QSploitError("INVALID_DLOG_RESULT", "The recovered scalar does not reproduce the captured server X25519 share.")
        try:
            shared = private.exchange(validate_x25519_point(key.client_public))
        except ValueError:
            raise QSploitError("INVALID_PREMASTER", "The X25519 exchange produced an invalid all-zero secret.") from None
        if shared == bytes(32):
            raise QSploitError("INVALID_PREMASTER", "The X25519 exchange produced an all-zero secret.")
        return shared  # fixed 32-byte little-endian RFC 7748 output
    if not isinstance(secret, ECDLogSecret):
        raise QSploitError("INVALID_RECOVERY_RESULT", "P-256 ECDHE recovery requires a verified scalar result.")
    if type(secret.x) is not int or not 1 <= secret.x < P256_ORDER:
        raise QSploitError("INVALID_DLOG_RESULT", "The recovered P-256 scalar is outside the valid group range.")
    private = ec.derive_private_key(secret.x, ec.SECP256R1())
    public = private.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    if not hmac.compare_digest(public, key.server_public):
        raise QSploitError("INVALID_DLOG_RESULT", "The recovered scalar does not reproduce the captured server point.")
    # RFC 8422 section 5.10: P-256 uses the full 32-byte x-coordinate,
    # preserving leading zeros (unlike finite-field TLS 1.2 DH).
    return private.exchange(ec.ECDH(), validate_p256_point(key.client_public))
