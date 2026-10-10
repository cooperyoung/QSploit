"""Integrity of committed, independently generated real traffic evidence."""
import base64
import hashlib
import io
import json
from pathlib import Path

import dpkt
import pytest

FIXTURES = Path(__file__).parent / 'fixtures'
DEMO = FIXTURES.parents[1] / 'qsploit' / 'demo'
MANIFEST = json.loads((FIXTURES / 'manifest.json').read_text())


@pytest.mark.parametrize('record', MANIFEST['captures'], ids=lambda r: r['file'])
def test_capture_matches_immutable_provenance(record):
    wire = (FIXTURES / record['file']).read_bytes()
    assert hashlib.sha256(wire).hexdigest() == record['sha256']
    assert len(wire) == record['size']
    reader = dpkt.pcap.Reader(io.BytesIO(wire))
    assert reader.datalink() == record['linktype']
    packets = list(reader)
    assert len(packets) == record['packet_count'] > 0
    assert MANIFEST['generator']['packet_provenance'].startswith('Unmodified OS packets')


@pytest.mark.parametrize('name', ['tls12-rsa-ems', 'tls12-rsa-noems'])
def test_independent_endpoint_oracles_are_consistent(name):
    expected = json.loads((FIXTURES / f'{name}.expected.json').read_text())
    assert expected['sha256'] == hashlib.sha256((FIXTURES / f'{name}.pcap').read_bytes()).hexdigest()
    for direction, field in [('c2s', 'request'), ('s2c', 'response')]:
        stream = base64.b64decode(expected[f'{direction}_base64'])
        messages = b''.join(base64.b64decode(exchange[f'{field}_base64']) for exchange in expected['exchanges'])
        assert stream == messages
        side = 'server_received_sha256' if direction == 'c2s' else 'client_received_sha256'
        assert hashlib.sha256(stream).hexdigest() == expected['endpoint_observations'][side]
    assert len(bytes.fromhex(expected['master_secret_hex'])) == 48
    assert len(bytes.fromhex(expected['client_random_hex'])) == 32
    assert expected['cipher'] == 'AES128-GCM-SHA256'
    assert expected['version'] == 'TLSv1.2'
    assert expected['ems'] == name.endswith('-ems')
    assert expected['server_shutdown_complete']


def test_runtime_assets_have_only_pcaps_and_explicit_recovery_fixtures():
    expected_names = {'factors.json', 'qsploit-demo.pcap', 'tls12-rsa-ems.pcap', 'mixed-discovery.pcap', 'tls12-rsa-aes256.pcap', 'tls12-rsa-aes256-noems.pcap', 'dlog.json', 'tls12-dhe-aes128-ems.pcap', 'tls12-dhe-aes128-noems.pcap', 'tls12-dhe-aes256-ems.pcap', 'tls12-dhe-aes256-noems.pcap'}
    expected_names |= {'ec_dlog.json'} | {f'tls12-ecdhe-p256-aes{bits}-{ems}.pcap' for bits in (128,256) for ems in ('ems','noems')}
    expected_names |= {f'tls12-ecdhe-x25519-aes{bits}-{ems}.pcap' for bits in (128,256) for ems in ('ems','noems')}
    expected_names |= {'tls13-p256-aes128.pcap'}
    assert {p.name for p in DEMO.iterdir() if p.is_file()} == expected_names
    factors = json.loads((DEMO / 'factors.json').read_text())
    assert len(factors) == 2
    for n, pair in factors.items():
        assert set(pair) == {'p', 'q'}
        assert int(n, 16).bit_length() == 2048
        assert int(pair['p'], 16) * int(pair['q'], 16) == int(n, 16)
    assert (DEMO / 'qsploit-demo.pcap').read_bytes() == (FIXTURES / 'tls12-rsa-ems.pcap').read_bytes()
    assert (DEMO / 'mixed-discovery.pcap').read_bytes() == (FIXTURES / 'mixed-discovery.pcap').read_bytes()
    assert not list(FIXTURES.glob('*.key'))
    assert not list(FIXTURES.glob('*.keys'))
    assert MANIFEST['temporary_private_key_and_keylogs_deleted']
