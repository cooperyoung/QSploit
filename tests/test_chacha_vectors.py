"""Independent ChaCha20-Poly1305 vectors; TLS 1.2 DHE gate only.

RFC 8439 section 2.8.2 is a published primitive known answer. The separate
TLS record and 88-byte key block are static synthetic test vectors generated
once by tlslite-ng 0.8.2 pure-Python ChaCha/PRF, crosschecked with cryptography
47.0.0 AEAD. They are not represented as captured network traffic. No runtime
QSploit helper was used to produce the expected bytes.
"""
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from qsploit.models import QSploitError, Record
from qsploit.tls12 import derive_key_block, decrypt_record

SUITE = 0xCCAA
_REFERENCE = {'source': 'RFC8439 section2.8.2; custom TLS vectors generated once using tlslite-ng 0.8.2 pure Python ChaCha+HKDF/PRF '
           'and cross-checked cryptography AEAD. No production QSploit helper used.',
 'rfc8439': {'key': '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
             'nonce': '070000004041424344454647',
             'aad': '50515253c0c1c2c3c4c5c6c7',
             'plaintext': '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e',
             'ciphertext_tag': 'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691'},
 'tls12': {'sequence': 72623859790382856,
           'master': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f',
           'client_random': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
           'server_random': '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
           'key_block': 'fbe0dbb71e9097fcfe644317a16d334fac721a5f822730468a366a4ef2f2206848092b65ca8b00c356742cd5bae70ed8ac35e70945a53033866a9b3abca98806f6ba1048b7cd53eb2f2584955a68b87c9d198ce2c55c204f',
           'key': 'fbe0dbb71e9097fcfe644317a16d334fac721a5f822730468a366a4ef2f22068',
           'iv': 'f6ba1048b7cd53eb2f258495',
           'nonce': 'f6ba1048b6cf50ef2a23839d',
           'aad': '0102030405060708170303003f',
           'plaintext': '474554202f6368616368612d766563746f723f636865636b65643d79657320485454502f312e310d0a486f73743a206578616d706c652e746573740d0a0d0a',
           'record': '170303004f159f119a8769f46882d569e3b49008936866c0a0a88cb07010ed89055a5d07941c840e2ecbf8e50ff476febc517706408ff2f1d32681079baf986c9510a2b02f6b9da6339e34daef8c775dd7f3c211'}}
R = {key: bytes.fromhex(value) for key, value in _REFERENCE["rfc8439"].items()}
T = {key: bytes.fromhex(value) for key, value in _REFERENCE["tls12"].items() if key != "sequence"}
SEQUENCE = _REFERENCE["tls12"]["sequence"]


def test_rfc8439_published_chacha20_poly1305_primitive_answer():
    cipher = ChaCha20Poly1305(R["key"])
    assert cipher.encrypt(R["nonce"], R["plaintext"], R["aad"]) == R["ciphertext_tag"]
    assert cipher.decrypt(R["nonce"], R["ciphertext_tag"], R["aad"]) == R["plaintext"]


def test_tls12_chacha_key_block_has_two_32_byte_keys_and_two_12_byte_ivs():
    block = derive_key_block(T["master"], T["client_random"], T["server_random"], cipher_suite=SUITE)
    assert block == T["key_block"]
    assert len(block) == 88
    assert block[:32] == T["key"] and block[64:76] == T["iv"]


def sample_record():
    wire = T["record"]
    assert int.from_bytes(wire[3:5], "big") == len(wire) - 5
    return Record("c2s", 0, wire[0], int.from_bytes(wire[1:3], "big"), wire[5:])


def test_static_tls12_record_implicit_nonce_and_plaintext_length_aad():
    assert len(sample_record().fragment) == len(T["plaintext"]) + 16
    assert decrypt_record(sample_record(), T["key"], T["iv"], SEQUENCE, cipher_suite=SUITE) == T["plaintext"]


@pytest.mark.parametrize("mutation", ["sequence", "direction-key", "iv", "version", "type", "ciphertext", "tag", "explicit-nonce"])
def test_tls12_record_tampering_or_wrong_nonce_construction_rejected(mutation):
    record, key, iv, sequence = sample_record(), T["key"], T["iv"], SEQUENCE
    if mutation == "sequence":
        sequence += 1
    elif mutation == "direction-key":
        key = T["key_block"][32:64]
    elif mutation == "iv":
        iv = T["key_block"][76:88]
    elif mutation == "version":
        record = replace(record, version=0x0302)
    elif mutation == "type":
        record = replace(record, content_type=22)
    elif mutation == "explicit-nonce":
        record = replace(record, fragment=bytes(8) + record.fragment)
    else:
        fragment = bytearray(record.fragment)
        fragment[0 if mutation == "ciphertext" else -1] ^= 1
        record = replace(record, fragment=bytes(fragment))
    with pytest.raises(QSploitError):
        decrypt_record(record, key, iv, sequence, cipher_suite=SUITE)


@pytest.mark.parametrize("sequence", [-1, 2**64])
def test_tls12_chacha_sequence_never_wraps(sequence):
    with pytest.raises(QSploitError):
        decrypt_record(sample_record(), T["key"], T["iv"], sequence, cipher_suite=SUITE)


@pytest.mark.parametrize("length", [0, 15, 16384 + 17])
def test_tls12_chacha_ciphertext_bounds(length):
    with pytest.raises(QSploitError):
        decrypt_record(replace(sample_record(), fragment=bytes(length)), T["key"], T["iv"], SEQUENCE, cipher_suite=SUITE)
