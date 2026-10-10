"""Local ECDHE shared-secret computation independent of TLS key schedules."""
import hmac
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from .groups import P256_ORDER, normalize_x25519_point, validate_p256_point, validate_x25519_point
from .models import ECDHEKeyExchange, ECDLogSecret, QSploitError, RecoveredSecret, X25519Secret


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
