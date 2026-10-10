"""Mixed genuine sessions preserve independent recovery and inspector state."""
from collections import Counter
import base64
import hashlib
import io
import json
from pathlib import Path
import time

import dpkt
from fastapi.testclient import TestClient

from qsploit.app import Settings, create_app

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures'
TOUR = ROOT / 'qsploit/demo/protocol-tour.pcap'
HEADERS = {'X-QSploit': '1'}


def evidence():
    return json.loads((FIXTURES / 'protocol-tour.sources.json').read_text())


def test_tour_contains_only_unmodified_independent_capture_packets():
    report = evidence()
    wire = TOUR.read_bytes()
    assert hashlib.sha256(wire).hexdigest() == report['capture_sha256']
    original = Counter()
    for item in report['sessions']:
        source = (FIXTURES / item['fixture']).read_bytes()
        assert hashlib.sha256(source).hexdigest() == item['sha256']
        original.update(dpkt.pcap.Reader(io.BytesIO(source)))
    actual = Counter(dpkt.pcap.Reader(io.BytesIO(wire)))
    assert actual == original
    assert sum(actual.values()) == report['packets']


def test_mixed_capture_recovers_every_session_and_retains_exact_inspector_results():
    report = evidence()
    def address(item):
        return f"{item['ip']}:{item['port']}"
    expected = {(address(item['client']), address(item['server'])): json.loads(
        (FIXTURES / item['fixture'].replace('.pcap', '.expected.json')).read_text())
        for item in report['sessions']}
    assert len(expected) == len(report['sessions'])
    with TestClient(create_app(Settings(backend='fixture', demo_delay_seconds=0, port=8765)),
                    base_url='http://127.0.0.1:8765') as client:
        assert client.get('/api/config').json()['protocol_tour_available']
        downloaded = client.get('/api/protocol-tour')
        assert downloaded.content == TOUR.read_bytes()
        upload = client.post('/api/captures', content=downloaded.content, headers=HEADERS)
        assert upload.status_code == 201, upload.text
        sessions = upload.json()['sessions']
        assert len(sessions) == len(expected)
        seen = set()
        for session in sessions:
            key = session['client'], session['server']
            assert key in expected and key not in seen
            seen.add(key)
            assert session['implementation'] == 'supported', session
            assert session['recovery_modes'] == ['fixture']
            fields = set(session['recovery_parameters'])
            assert fields == {'rsa_factor': {'n'}, 'ff_dlog': {'p', 'g', 'y', 'order'},
                              'ec_dlog': {'curve', 'public_point'}}[session['recovery_problem']]
            assert session['decrypt_state'] == 'not_started'
            sid = session['id']
            response = client.post(f'/api/sessions/{sid}/recover', json={}, headers=HEADERS)
            assert response.status_code == 202, response.text
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                job = client.get(f"/api/jobs/{response.json()['id']}").json()
                if job['state'] in {'succeeded', 'failed', 'timed_out'}:
                    break
                time.sleep(.02)
            assert job['state'] == 'succeeded', job
            assert job['client_finished_verified'] and job['server_finished_verified']
            assert job['recovery_verified'] and job['authenticated_records'] > 0
        # Validate again after all other sessions have run: no selected-session mix-ups.
        for session in sessions:
            sid = session['id']
            oracle = expected[session['client'], session['server']]
            listing = client.get(f'/api/sessions/{sid}/http').json()
            assert len(listing) == len(oracle['exchanges'])
            for index, exchange in enumerate(oracle['exchanges']):
                view = client.get(f'/api/sessions/{sid}/http/{index}').json()
                assert view['request']['raw_b64'] == exchange['request_base64']
                assert view['response']['raw_b64'] == exchange['response_base64']
            for direction in ('c2s', 's2c'):
                assert client.get(f'/api/sessions/{sid}/application/{direction}').content == base64.b64decode(oracle[f'{direction}_base64'])
            preview = client.get(f'/api/sessions/{sid}/http/0/preview')
            assert preview.status_code == 200
            assert 'Welcome back, Cooper.' in preview.text and '<script' not in preview.text
        assert all(s['decrypt_state'] == 'verified' for s in client.get('/api/captures/current').json()['sessions'])
