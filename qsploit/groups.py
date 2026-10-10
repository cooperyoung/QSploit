"""Public mathematical parameters shared by classical and quantum components.

The implemented groups are RFC 7919 ffdhe2048 and secp256r1. No capture,
handshake, provider, or secret-fixture data belongs in this module.
Source: https://www.rfc-editor.org/rfc/rfc7919#appendix-A.1
"""
from cryptography.hazmat.primitives.asymmetric import ec

from .models import QSploitError

P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def validate_p256_point(public_point: bytes) -> ec.EllipticCurvePublicKey:
    """Require a finite on-curve uncompressed point; P-256's cofactor is one."""
    if type(public_point) is not bytes or len(public_point) != 65 or public_point[0] != 4:
        raise QSploitError("INVALID_EC_PUBLIC", "P-256 recovery requires a 65-byte uncompressed public point.")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_point)
    except ValueError:
        raise QSploitError("INVALID_EC_PUBLIC", "The captured P-256 public point is not on the selected curve.") from None

FFDHE2048_P = int("""
FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
886B4238 61285C97 FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", ""), 16)
FFDHE2048_G = 2
FFDHE2048_ORDER = (FFDHE2048_P - 1) // 2


def validate_ffdhe2048(p: int, g: int, order: int, *public_values: int) -> None:
    """Require the approved group and nontrivial shares in its prime subgroup."""
    if (type(p) is not int or type(g) is not int or type(order) is not int or
            (p, g, order) != (FFDHE2048_P, FFDHE2048_G, FFDHE2048_ORDER)):
        raise QSploitError("UNSUPPORTED_GROUP", "Finite-field recovery currently supports the exact RFC 7919 ffdhe2048 group only.")
    for value in public_values:
        if type(value) is not int or not 2 <= value <= p - 2 or pow(value, order, p) != 1:
            raise QSploitError("INVALID_DH_PUBLIC", "A captured DH public share is outside the supported group's nontrivial prime-order subgroup.")
