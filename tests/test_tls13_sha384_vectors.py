"""Independent synthetic SHA-384/AES-256 TLS 1.3 schedule known answers.

These are not published RFC 8448 values or a captured handshake. Fixed opaque
transcript inputs isolate hash selection; genuine-capture tests are separate.
Generated once with tlslite-ng 0.8.2 HMAC/HKDF and pure-Python AES-GCM. HMAC,
HKDF, and AEAD results were crosschecked with cryptography; no QSploit helper
participated. The reference RSA private key was discarded after signing.
"""
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.serialization import load_der_public_key

from qsploit.models import QSploitError, Record
from qsploit.tls13 import (hkdf_extract, hkdf_expand_label, derive_secret,
                           traffic_key_iv, finished_verify_data, handshake_secrets,
                           decrypt_record, _certificate_verify)

SUITE = 0x1302
_REFERENCE = {'provenance': 'Independent synthetic schedule-only KAT, not a published RFC8448 SHA384 trace. Generated with '
               'tlslite-ng0.8.2 HKDF/HMAC/pure-Python AESGCM; HKDF/HMAC/AES crosschecked cryptography. Arbitrary fixed '
               'transcript bytes test hash selection; genuine captured handshake coverage is separate. Ephemeral RSA '
               'private key discarded after producing RSA-PSS-SHA256 signature over SHA384 transcript.',
 'record_sequence': 72623859790382856,
 'shared_secret': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
 'hello_transcript': '5153706c6f6974206669786564205348413338342068656c6c6f207472616e73637269707400',
 'server_auth_transcript': '5153706c6f6974206669786564205348413338342068656c6c6f207472616e736372697074005153706c6f6974206669786564207365727665722061757468656e7469636174696f6e207472616e73637269707400',
 'early_secret': '7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5',
 'early_derived': '1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b',
 'handshake_secret': '03e67b8797b8868b32c737ad09d2454266b47b828fe83999484501c1d0f12bfefdecf2341ab055c50f8f81a4d91610dd',
 'handshake_derived': '888c5abde4d54b2ac1684e8eb7ab0219176f165a36dc0d3c670e14ae38456f8a5bff9aefac5d68c98ae40fed5f861c28',
 'master_secret': '16d23b35c31232dd08cf8189bfb64942b4232e1b8787e94fa3fbf16413dc38ed5a7b3410e633a2cc9c790e22541ffae7',
 'client_handshake_secret': 'fd00a1a10678027cc82f94ba11b8ab89efcbc47f7163e3b0f2a0a2a63119abb8f0014d0f9e79341acef13b0353680553',
 'server_handshake_secret': '33609af4a01a11ee40e38d356b0f40ce208aea48c9ec1c06c3798f27fd8e9a02e88484e624b2ecdad34dd74610b7ad3e',
 'server_finished': '1400003038c5b9e03863bead4d10240fde1ab9bd7d667ce041dec43f97e93d8ed7109dcfe242040ec4173691a0c877387fda8587',
 'client_finished': '14000030c8c0d085f09ec60798af0cc304163fe2ecb06ae0f7f7c1d6b3e1b3ebe7e6f68f897a3c10c47bf7197185cf51b20b416f',
 'client_application_secret': '27f4fa776fc5c0de8c37174858cb817f8df0ef8673269e9078367e48aeff100c4a107c77b9033d8757d343d23db4e1b2',
 'server_application_secret': '2048686638fa6864fdb3abdf94f05a977f9d1898946cc88612e1ea38c6ec632b25cbb3f2a5d2e6a33da42e65246b39d2',
 'client_finished_key': '02822b6bb6ebba93647a6d9c064a8fa90d40da77eeaa2ab8af8f311c7027ab3fd670263d7709cbad90dde841dd2b4da5',
 'server_finished_key': '59707ebc38dada979de0957e3a9950af65219e23188d07049ea79bfc369d87ea32b58eb45be6663881dc98143799004c',
 'resumption_master_secret': '3b58b54bbbffe86e044a1f047f1d6be292b0ad9dae8ccbaf2cc20d99fd508db0918d1b5f15b53ba0f28f58329d092c8c',
 'exporter_master_secret': 'eedfb92262a1d872e346609e9345447bcabfbbff6f7143958898315170dc6d52cd5b2150043a773181c3c7868d27beb1',
 'server_updated_secret': '7459190733d5c5ec8f52944bb25ea0e9ce15a8da3640241de8c7667ab3aa9181a1d704140d98f3a8033d642af76dc8ce',
 'client_handshake_key': '3cd5b94a0e617b0b703746280cfef003e55cb8489a17f40c9fc06d311b659a1c',
 'client_handshake_iv': '571ff65843ad80b51102966d',
 'server_handshake_key': '98cc44d0c8fa8a1d6d88515617a84f2f3b7d6c4f6477c1cac38d827b0769d1ad',
 'server_handshake_iv': '2ac79adf513f04b23ec7db30',
 'client_application_key': 'dbf8bca6bdd429137a92d3ba49b56721ea028331e0c5f3521062863f9877ce22',
 'client_application_iv': 'e6a5aa89521b6f491bd60e6e',
 'server_application_key': '47584b84896ec2415e57afc8f9f73c6df4bd9f5570aac6ab2c5646c3c3c14563',
 'server_application_iv': 'e80a2b8180b201da1c3ffc46',
 'server_updated_key': 'df50f1f4c2f3f4fbb96da20b70c8b522471fab5aad4456ef3ffb11ffe3ab52cf',
 'server_updated_iv': '15e7df26d0dd1e0737f9ca4f',
 'application_plaintext': '485454502f312e3120323030204f4b0d0a436f6e74656e742d4c656e6774683a20390d0a0d0a534841333834204f4b',
 'application_record': '1703030043ec186868c520eb65786a81a20b836cfd435b15ba6d25becf86f832e65ce935797f622cd0eebabc78204e6a7560f5eea19b673c8933d57da235cb025ee8c06f20f6118a',
 'certificate_verify_public_der': '30820122300d06092a864886f70d01010105000382010f003082010a028201010098e4fc976b882c7945de032111172781b3be09e438d39ac4805b92423fedd45014b613b4a181b0a766a0dc21f83a244decd30462dcd9e7899daab1893ae86db91e83659797a6f700bbcb966ac7304a4732125e4f24c9d51f2f40db0e28111b86a0a32fa288cc8b191b994adc4add6eea0126e8a99b59f26b8167a47fb5aa84d98d2b619b9d0291e28c65fef15dfb51f36676e58a723017aea6d53e8c180f5f6ad4370c6676efacca108a508d0084743b3397fa69f13540f510c6752d425dfdfb8276f06cb177edfc3de18a111504f523e5527813df4be26b5912c70e818fd9904e0a56352cdd643d7b2fa0175a0e897036947ed565f467d58a0a6b8a89a471010203010001',
 'certificate_verify': '0f0001040804010044fa48d688a3345e25b55b781b6b3869f28461f8e0f3062a721f2665176d2245cdfef5038b3994b3464d81caa1b51ffea1f13578ce01883c017ed6698d4ea1e9ecb428ccf24fa4fe68d2491c2190050737091bbc61b57c1e88bc971a9d84a79b386f5d63e791196f45c8dbbe1ed0051f386587542d95145ce6fb45e4515a9e9a206a215293ae21d8c7bfd6e22d21487565eddfcf96dde5dc1646f93d6e483d864a95de895f3c8ed4f9e6b3a53276fcf848f8d04f2df1a2a83616d96aed3ec1ee59ce9739c48990ee5f42090a1bfec3527ee6b682cccbaa3e65259feadaab634dfefc239e8e32a87bb9494f21a1fe9def6656a034be3b83726890b87d61ca2358'}
V = {key: bytes.fromhex(value) for key, value in _REFERENCE.items() if key not in {"provenance", "record_sequence"}}
THROUGH_SERVER_FINISHED = V["server_auth_transcript"] + V["server_finished"]
THROUGH_CLIENT_FINISHED = THROUGH_SERVER_FINISHED + V["client_finished"]


def test_independent_sha384_extract_and_derived_secrets():
    early = hkdf_extract(bytes(48), bytes(48), cipher_suite=SUITE)
    assert early == V["early_secret"]
    assert len(early) == 48
    derived = derive_secret(early, "derived", b"", cipher_suite=SUITE)
    assert derived == V["early_derived"]
    assert hkdf_expand_label(early, "derived", b"", 48, cipher_suite=SUITE) != derived
    handshake = hkdf_extract(derived, V["shared_secret"], cipher_suite=SUITE)
    assert handshake == V["handshake_secret"]
    handshake_derived = derive_secret(handshake, "derived", b"", cipher_suite=SUITE)
    assert handshake_derived == V["handshake_derived"]
    assert hkdf_extract(handshake_derived, bytes(48), cipher_suite=SUITE) == V["master_secret"]
    assert hkdf_extract(handshake_derived, bytes(32), cipher_suite=SUITE) != V["master_secret"]


def test_independent_sha384_handshake_schedule_wrapper():
    assert handshake_secrets(V["shared_secret"], V["hello_transcript"], cipher_suite=SUITE) == (
        V["client_handshake_secret"], V["server_handshake_secret"], V["master_secret"])


@pytest.mark.parametrize("label,expected", [("c hs traffic", "client_handshake_secret"),
                                           ("s hs traffic", "server_handshake_secret")])
def test_independent_sha384_handshake_traffic(label, expected):
    assert derive_secret(V["handshake_secret"], label, V["hello_transcript"], cipher_suite=SUITE) == V[expected]


@pytest.mark.parametrize("label,expected", [("c ap traffic", "client_application_secret"),
                                           ("s ap traffic", "server_application_secret"),
                                           ("exp master", "exporter_master_secret")])
def test_independent_sha384_application_traffic(label, expected):
    assert derive_secret(V["master_secret"], label, THROUGH_SERVER_FINISHED, cipher_suite=SUITE) == V[expected]
    assert derive_secret(V["master_secret"], label, THROUGH_CLIENT_FINISHED, cipher_suite=SUITE) != V[expected]


def test_independent_sha384_resumption_and_key_update():
    assert derive_secret(V["master_secret"], "res master", THROUGH_CLIENT_FINISHED, cipher_suite=SUITE) == V["resumption_master_secret"]
    assert hkdf_expand_label(V["server_application_secret"], "traffic upd", b"", 48, cipher_suite=SUITE) == V["server_updated_secret"]


@pytest.mark.parametrize("side,transcript", [("server", V["server_auth_transcript"]),
                                            ("client", THROUGH_SERVER_FINISHED)])
def test_independent_sha384_finished_keys_and_48_byte_verify_data(side, transcript):
    secret = V[side + "_handshake_secret"]
    assert hkdf_expand_label(secret, "finished", b"", 48, cipher_suite=SUITE) == V[side + "_finished_key"]
    answer = finished_verify_data(secret, transcript, cipher_suite=SUITE)
    assert len(answer) == 48
    assert answer == V[side + "_finished"][4:]


@pytest.mark.parametrize("epoch", ["client_handshake", "server_handshake", "client_application", "server_application", "server_updated"])
def test_independent_aes256_key_and_iv(epoch):
    key, iv = traffic_key_iv(V[epoch + "_secret"], cipher_suite=SUITE)
    assert (key, iv) == (V[epoch + "_key"], V[epoch + "_iv"])
    assert len(key) == 32 and len(iv) == 12


def application_record():
    wire = V["application_record"]
    assert int.from_bytes(wire[3:5], "big") == len(wire) - 5
    return Record("s2c", 0, wire[0], int.from_bytes(wire[1:3], "big"), wire[5:])


def test_independent_aes256_record_authenticates_with_full_sequence_and_padding():
    assert decrypt_record(application_record(), V["server_application_secret"], _REFERENCE["record_sequence"], cipher_suite=SUITE) == (23, V["application_plaintext"])


@pytest.mark.parametrize("mutation", ["default-sha256", "wrong-sequence", "tag"])
def test_aes256_reference_fails_for_wrong_schedule_or_record(mutation):
    record, suite, sequence = application_record(), SUITE, _REFERENCE["record_sequence"]
    if mutation == "default-sha256":
        suite = 0x1301
    elif mutation == "wrong-sequence":
        sequence += 1
    else:
        record = replace(record, fragment=record.fragment[:-1] + bytes([record.fragment[-1] ^ 1]))
    with pytest.raises(QSploitError):
        decrypt_record(record, V["server_application_secret"], sequence, cipher_suite=suite)


def test_certificate_verify_uses_suite_hash_independently_of_signature_hash():
    # RSA-PSS-SHA256 signs context || SHA384(transcript), not SHA256(transcript).
    key = load_der_public_key(V["certificate_verify_public_der"])
    offers = {13: bytes.fromhex("00020804")}
    _certificate_verify(V["certificate_verify"], key, V["server_auth_transcript"], offers, cipher_suite=SUITE)
    with pytest.raises(QSploitError) as exc:
        _certificate_verify(V["certificate_verify"], key, V["server_auth_transcript"], offers, cipher_suite=0x1301)
    assert exc.value.code == "SERVER_SIGNATURE_FAILED"


def test_sha384_hkdf_expand_limit_uses_48_byte_blocks():
    assert len(hkdf_expand_label(V["master_secret"], "test", b"", 8161, cipher_suite=SUITE)) == 8161
    with pytest.raises(ValueError):
        hkdf_expand_label(V["master_secret"], "test", b"", 255 * 48 + 1, cipher_suite=SUITE)
