"""Independent finite-field encoding answers for TLS 1.3 (RFC 8446 7.4.1).

The fixed public RFC7919 group and deterministic 256-bit test exponents yield
a shared value whose leading byte is zero. Both exchange directions were
crosschecked against OpenSSL through cryptography47.0.0. The optional SHA256
KDF answers were generated using tlslite-ng0.8.2 and synthetic opaque transcript
bytes. Neither the fixture nor this test claims to be a captured handshake.
"""
import json
from pathlib import Path

import pytest

from qsploit.keyexchange import ffdhe_shared_secret
from qsploit.models import FFDHEKeyExchange, FFDLogSecret, QSploitError
from qsploit.tls13 import handshake_secrets


V = json.loads((Path(__file__).parent / "fixtures" / "ffdhe2048-leading-zero.json").read_text())
P, G, ORDER = (int(V[name], 16) for name in ("p", "g", "order"))
PADDED = bytes.fromhex(V["tls13_shared_256"])
MINIMAL = bytes.fromhex(V["tls12_shared_minimal"])


def exchange(side):
    peer = "client" if side == "server" else "server"
    key = FFDHEKeyExchange(P, G, int(V[side + "_y"], 16), int(V[peer + "_y"], 16), ORDER)
    return key, FFDLogSecret(int(V[side + "_x"], 16))


@pytest.mark.parametrize("side", ["server", "client"])
def test_tls13_ffdhe_preserves_leading_zero_in_both_exchange_directions(side):
    key, secret = exchange(side)
    assert len(PADDED) == 256 and PADDED[:1] == b"\x00" and PADDED[1] != 0
    assert ffdhe_shared_secret(key, secret, padded=True) == PADDED


@pytest.mark.parametrize("side", ["server", "client"])
def test_tls12_ffdhe_still_uses_minimal_shared_secret_encoding(side):
    key, secret = exchange(side)
    assert len(MINIMAL) == 255 and PADDED == b"\x00" + MINIMAL
    assert ffdhe_shared_secret(key, secret) == MINIMAL


def test_tls13_ffdhe_padded_secret_matches_independent_sha256_kdf_answers():
    key, secret = exchange("server")
    shared = ffdhe_shared_secret(key, secret, padded=True)
    transcript = bytes.fromhex(V["hello_transcript"])
    expected = tuple(bytes.fromhex(V[name]) for name in (
        "client_handshake_secret", "server_handshake_secret", "master_secret"))
    assert handshake_secrets(shared, transcript) == expected
    # Removing even one zero changes Extract; successful TLS12 DH arithmetic
    # alone is insufficient evidence of TLS13 HKDF input correctness.
    assert handshake_secrets(MINIMAL, transcript) != expected


@pytest.mark.parametrize("scalar", [False, 0, ORDER])
def test_ffdhe_local_exchange_revalidates_scalar_range(scalar):
    key, _ = exchange("server")
    with pytest.raises(QSploitError) as error:
        ffdhe_shared_secret(key, FFDLogSecret(scalar), padded=True)
    assert error.value.code == "INVALID_DLOG_RESULT"


def test_ffdhe_local_exchange_rejects_valid_range_but_wrong_private_scalar():
    key, secret = exchange("server")
    with pytest.raises(QSploitError) as error:
        ffdhe_shared_secret(key, FFDLogSecret(secret.x + 1), padded=True)
    assert error.value.code == "INVALID_DLOG_RESULT"
