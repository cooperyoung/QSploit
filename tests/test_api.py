"""Full local API workflow and failures; real child-process recovery for success tests."""
from __future__ import annotations

import asyncio
import base64
import io
import json
from pathlib import Path
import threading
import time

import dpkt
from fastapi.testclient import TestClient
import pytest

from qsploit.app import Settings, create_app
from qsploit.models import QSploitError

FIXTURES = Path(__file__).parent / 'fixtures'
HEADERS = {'X-QSploit':'1'}
BASE = 'http://127.0.0.1:8765'


@pytest.fixture
def client():
    with TestClient(create_app(Settings(backend='fixture',demo_delay_seconds=0,port=8765)),base_url=BASE) as instance:
        yield instance


def upload(client, name='tls12-rsa-ems'):
    result = client.post('/api/captures',content=(FIXTURES/f'{name}.pcap').read_bytes(),headers=HEADERS)
    assert result.status_code == 201,result.text
    return result.json()


def wait_job(client, job_id, timeout=12):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        result = client.get(f'/api/jobs/{job_id}')
        assert result.status_code == 200,result.text
        job = result.json()
        if job['state'] in {'succeeded','failed','timed_out'}:
            return job
        time.sleep(.025)
    pytest.fail('Recovery did not finish within bounded test deadline')


def recover(client, sid):
    result = client.post(f'/api/sessions/{sid}/recover',json={},headers=HEADERS)
    assert result.status_code == 202,result.text
    return wait_job(client,result.json()['id'])


def assert_no_plaintext(client,sid):
    for route in (f'/api/sessions/{sid}/http',f'/api/sessions/{sid}/http/0',f'/api/sessions/{sid}/http/0/preview',f'/api/sessions/{sid}/application/c2s',f'/api/sessions/{sid}/application/s2c'):
        result = client.get(route)
        assert result.status_code == 409,(route,result.text)
        assert result.json()['error']['code'] == 'NOT_READY'


@pytest.mark.parametrize('name', ['tls12-rsa-ems','tls12-rsa-noems','tls12-rsa-ticket'])
def test_pcaps_to_verified_http_via_actual_spawned_recovery(client,name):
    expected = json.loads((FIXTURES/f'{name}.expected.json').read_text())
    capture = upload(client,name)
    assert len(capture['sessions']) == 1
    session = capture['sessions'][0]
    sid = session['id']
    assert session['tls_version'] == '1.2'
    assert session['cipher_suite_id'] == 0x009c
    assert session['key_exchange'] == 'rsa_transport'
    assert session['ems'] is expected['ems']
    assert session['rsa']['bits'] == 2048
    assert session['recovery_modes'] == ['fixture']
    assert_no_plaintext(client,sid)
    job = recover(client,sid)
    assert job['state'] == 'succeeded',job
    assert job['method'] == 'fixture_lookup'
    assert job['execution'] == 'none'
    assert job['factor_pair_verified']
    assert job['client_finished_verified'] and job['server_finished_verified']
    assert job['authenticated_records'] == 19
    assert job['demo_factors'] is None
    assert not job['provider_job_ids']
    assert job['circuit_sha256'] is None
    assert client.get(f'/api/sessions/{sid}/job').json() == job
    assert client.get('/api/captures/current').json()['sessions'][0]['decrypt_state'] == 'verified'
    messages = client.get(f'/api/sessions/{sid}/http').json()
    assert [m['method'] for m in messages] == ['GET','POST']
    returned = [capture,job,messages]
    for index,oracle in enumerate(expected['exchanges']):
        result = client.get(f'/api/sessions/{sid}/http/{index}')
        assert result.status_code == 200
        msg = result.json()
        assert msg['request']['raw_b64'] == oracle['request_base64']
        assert msg['response']['raw_b64'] == oracle['response_base64']
        returned.append(msg)
    assert returned[-1]['response']['decoded_body_b64'] == expected['json_body_base64']
    for direction in ('c2s','s2c'):
        result = client.get(f'/api/sessions/{sid}/application/{direction}')
        assert result.status_code == 200
        assert result.content == base64.b64decode(expected[f'{direction}_base64'])
        assert result.headers['content-disposition'].startswith('attachment;')
    preview = client.get(f'/api/sessions/{sid}/http/0/preview')
    assert preview.status_code == 200
    assert 'Welcome back, Cooper.' in preview.text
    assert 'untrusted.qsploit.test' not in preview.text
    assert '__capturedScriptExecuted' not in preview.text
    assert '<script' not in preview.text
    assert 'type="hidden"' in preview.text
    assert 'sandbox;' in preview.headers['content-security-policy']
    assert "default-src 'none'" in preview.headers['content-security-policy']
    assert preview.headers['cache-control'] == 'no-store'
    assert preview.headers['referrer-policy'] == 'no-referrer'
    assert preview.headers['x-content-type-options'] == 'nosniff'
    public = json.dumps(returned)
    pair = json.loads((FIXTURES.parents[1]/'qsploit/demo/factors.json').read_text())[expected['rsa_modulus_hex']]
    for secret in (expected['master_secret_hex'],pair['p'],pair['q']):
        assert secret not in public
    assert 'master_secret' not in public and 'premaster' not in public


def test_unknown_modulus_is_honestly_unavailable(client):
    capture = upload(client,'unknown-rsa')
    sid = capture['sessions'][0]['id']
    assert capture['sessions'][0]['recovery_modes'] == []
    job = recover(client,sid)
    assert job['state'] == 'failed'
    assert job['error']['code'] == 'FIXTURE_NOT_FOUND'
    assert not job['client_finished_verified']
    assert job['execution'] == 'none'
    assert_no_plaintext(client,sid)


def corrupted_capture():
    # Alter one genuine captured application ciphertext, preserving framing/sequence.
    source = dpkt.pcap.Reader(io.BytesIO((FIXTURES/'tls12-rsa-ems.pcap').read_bytes()))
    output = io.BytesIO()
    writer = dpkt.pcap.Writer(output,linktype=source.datalink(),snaplen=262144)
    changed = False
    for timestamp,wire in source:
        ip = dpkt.loopback.Loopback(wire).data
        tcp = ip.data
        if not changed and isinstance(tcp,dpkt.tcp.TCP) and tcp.data[:1] == b'\x17':
            tcp.data = tcp.data[:-1]+bytes([tcp.data[-1]^1])
            wire = wire[:4]+bytes(ip)
            changed = True
        writer.writepkt(wire,timestamp)
    assert changed
    return output.getvalue()


def test_corrupted_authenticated_record_never_publishes_plaintext(client):
    result = client.post('/api/captures',content=corrupted_capture(),headers=HEADERS)
    assert result.status_code == 201,result.text
    sid = result.json()['sessions'][0]['id']
    job = recover(client,sid)
    assert job['state'] == 'failed',job
    assert job['error']['code'] == 'AEAD_AUTH_FAILED'
    assert client.get('/api/captures/current').json()['sessions'][0]['decrypt_state'] == 'failed'
    assert_no_plaintext(client,sid)


def test_security_boundary_rejects_wrong_host_origin_and_mutation_header(client):
    data = (FIXTURES/'tls12-rsa-ems.pcap').read_bytes()
    assert client.post('/api/captures',content=data).status_code == 403
    result = client.post('/api/captures',content=data,headers={**HEADERS,'Origin':'https://evil.example'})
    assert result.status_code == 403
    assert result.json()['error']['code'] == 'ORIGIN_REJECTED'
    for host in ('evil.example','127.0.0.1:8000','localhost.evil.example:8765'):
        result = client.get('/api/config',headers={'Host':host})
        assert result.status_code == 403
        assert result.json()['error']['code'] == 'HOST_REJECTED'
    assert client.post('/api/captures',content=data,headers={**HEADERS,'Origin':BASE}).status_code == 201
    assert client.get('/api/config',headers={'Host':'localhost:8765'}).status_code == 200


def test_failed_upload_preserves_previous_capture_and_bounds_upload(client):
    original = upload(client)
    result = client.post('/api/captures',content=b'not a pcap',headers=HEADERS)
    assert result.status_code == 400
    assert client.get('/api/captures/current').json() == original
    result = client.post('/api/captures',content=b'\x0a\x0d\x0d\x0a',headers=HEADERS)
    assert result.status_code == 415
    assert result.json()['error']['code'] == 'PCAPNG_UNSUPPORTED'
    with TestClient(create_app(Settings(backend='fixture',port=8765,max_upload_bytes=64)),base_url=BASE) as limited:
        result = limited.post('/api/captures',content=b'x'*65,headers=HEADERS)
        assert result.status_code == 413
        assert result.json()['error']['code'] == 'RESOURCE_LIMIT'


def test_active_job_prevents_replacement_delete_and_second_job(client,monkeypatch):
    entered = threading.Event()
    released = threading.Event()
    async def blocked_backend(problem,options,report):
        entered.set()
        while not released.is_set():
            await asyncio.sleep(.01)
        raise QSploitError('BACKEND_UNAVAILABLE','Controlled test failure; no fallback.')
    monkeypatch.setattr('qsploit.app.run_recovery',blocked_backend)
    capture = upload(client)
    sid = capture['sessions'][0]['id']
    result = client.post(f'/api/sessions/{sid}/recover',json={},headers=HEADERS)
    assert result.status_code == 202
    assert entered.wait(2)
    for result in (client.post('/api/captures',content=(FIXTURES/'tls12-rsa-noems.pcap').read_bytes(),headers=HEADERS),client.delete(f"/api/captures/{capture['id']}",headers=HEADERS),client.post(f'/api/sessions/{sid}/recover',json={},headers=HEADERS)):
        assert result.status_code == 409
        assert result.json()['error']['code'] == 'JOB_ACTIVE'
    released.set()
    job = wait_job(client,client.get(f'/api/sessions/{sid}/job').json()['id'])
    assert job['state'] == 'failed'
    assert job['error']['code'] == 'BACKEND_UNAVAILABLE'
    assert_no_plaintext(client,sid)
    assert client.delete(f"/api/captures/{capture['id']}",headers=HEADERS).status_code == 204
    assert client.get('/api/captures/current').status_code == 404


def test_failed_retry_clears_previous_plaintext(client,monkeypatch):
    capture = upload(client)
    sid = capture['sessions'][0]['id']
    assert recover(client,sid)['state'] == 'succeeded'
    async def broken(problem,options,report):
        raise QSploitError('BACKEND_UNAVAILABLE','Controlled outage; no fallback.')
    monkeypatch.setattr('qsploit.app.run_recovery',broken)
    retry = recover(client,sid)
    assert retry['state'] == 'failed'
    assert retry['method'] is None
    assert_no_plaintext(client,sid)


def test_mixed_discovery_separates_classical_kex_and_non_tls(client):
    capture = upload(client,'mixed-discovery')
    assert len(capture['sessions']) == 4
    assert sorted(s['key_exchange'] for s in capture['sessions']) == ['ecdhe','ecdhe','rsa_transport','unknown']
    assert len([s for s in capture['sessions'] if s['protocol']=='tcp']) == 1
    tls13 = next(s for s in capture['sessions'] if s['tls_version']=='1.3')
    assert tls13['selected_group_id'] == 29
    assert tls13['authentication'] is None
    assert not tls13['recovery_modes']
    result = client.post(f"/api/sessions/{tls13['id']}/recover",json={},headers=HEADERS)
    assert result.status_code == 422
    assert result.json()['error']['code'].startswith('UNSUPPORTED')


def test_configuration_timing_disabled_mode_and_request_validation(client):
    config = client.get('/api/config').json()
    assert config['mode'] == 'demo'
    assert config['demo_delay_seconds'] == 0
    assert config['timing_kind'] == 'illustrative_delay'
    assert 'not an estimate' in config['timing_assumptions']
    assert client.get('/api/demo-capture').content == (FIXTURES/'tls12-rsa-ems.pcap').read_bytes()
    assert all(not entry['connection_verified'] for entry in client.get('/api/capabilities').json())
    capture = upload(client)
    sid = capture['sessions'][0]['id']
    result = client.post(f'/api/sessions/{sid}/recover',json={'backend':'ionq_qpu'},headers=HEADERS)
    assert result.status_code == 422
    assert result.json()['error']['code'] == 'INVALID_REQUEST'
    result = client.post('/api/quantum-demo',json={'n':2048,'backend':'aer'},headers=HEADERS)
    assert result.status_code == 422
    with TestClient(create_app(Settings(port=8765)),base_url=BASE) as disabled:
        disabled_capture = upload(disabled)
        assert disabled.get('/api/config').json()['mode'] == 'disabled'
        result = disabled.post(f"/api/sessions/{disabled_capture['sessions'][0]['id']}/recover",json={},headers=HEADERS)
        assert result.status_code == 422
        assert result.json()['error']['code'] == 'BACKEND_UNAVAILABLE'


@pytest.mark.parametrize('delay',[-1,float('inf'),float('nan'),3601])
def test_bad_timing_is_rejected_at_startup(delay):
    with pytest.raises(ValueError):
        Settings(demo_delay_seconds=delay)


def test_replacing_capture_invalidates_old_jobs_and_plaintext(client):
    original = upload(client)
    sid = original['sessions'][0]['id']
    job = recover(client,sid)
    assert job['state']=='succeeded'
    replacement = upload(client,'tls12-rsa-noems')
    assert replacement['id'] != original['id']
    assert client.get(f"/api/captures/{original['id']}").status_code == 404
    assert client.get(f"/api/jobs/{job['id']}").status_code == 404
    assert client.get(f'/api/sessions/{sid}/http').status_code == 404
    assert replacement['sessions'][0]['decrypt_state']=='not_started'
