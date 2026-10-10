"""Path 4: real TLS 1.3 P-256 captures through the local API and inspector."""
from __future__ import annotations

import base64
from dataclasses import asdict
import hashlib
import io
import json
from pathlib import Path
import time

import dpkt
from fastapi.testclient import TestClient
import pytest

from qsploit.app import Settings, create_app
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from qsploit.groups import P256_ORDER
from qsploit.models import ECDLogProblem, ECDLogSecret, Recovery, RSAFactors
from qsploit.pcap import read_connections
from qsploit.tls import parse_tls

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT/'tests/fixtures'
DEMO = ROOT/'qsploit/demo'
NAMES = ('tls13-p256-aes128',)
HEADERS = {'X-QSploit':'1'}


def fixture(name):
    return (FIXTURES/f'{name}.pcap').read_bytes(),json.loads((FIXTURES/f'{name}.expected.json').read_text())


def secrets():
    return json.loads((DEMO/'ec_dlog.json').read_text())


@pytest.fixture
def client():
    with TestClient(create_app(Settings(backend='fixture',demo_delay_seconds=0,port=8765)),base_url='http://127.0.0.1:8765') as instance:
        yield instance


def upload(client,wire):
    response=client.post('/api/captures',content=wire,headers=HEADERS)
    assert response.status_code==201,response.text
    assert len(response.json()['sessions'])==1
    return response.json()['sessions'][0]


def recover(client,sid):
    response=client.post(f'/api/sessions/{sid}/recover',json={},headers=HEADERS)
    assert response.status_code==202,response.text
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        job=client.get(f"/api/jobs/{response.json()['id']}").json()
        if job['state'] in ('succeeded','failed','timed_out'):
            return job
        time.sleep(.025)
    pytest.fail('Recovery exceeded its bounded test deadline')


def no_plaintext(client,sid):
    for endpoint in ('http','http/0','http/0/preview','application/c2s','application/s2c'):
        response=client.get(f'/api/sessions/{sid}/{endpoint}')
        assert response.status_code==409
        assert response.json()['error']['code']=='NOT_READY'


@pytest.mark.parametrize('name',NAMES)
def test_tls13_real_capture_registry_has_only_exact_public_problem_and_observed_x(name):
    wire,expected=fixture(name)
    assert hashlib.sha256(wire).hexdigest()==expected['sha256']
    assert (DEMO/f'{name}.pcap').read_bytes()==wire
    assert expected['generator']['server']=='tlslite-ng 0.8.2'
    assert 'RNG and returned exponent unchanged' in expected['endpoint_observations']['recovery_oracle']
    public=expected['public_problem']
    assert set(public)=={'curve','public_point'} and public['curve']=='secp256r1'
    point=bytes.fromhex(public['public_point'])
    assert len(point)==65 and point[0]==4
    canonical=public['curve']+':'+point.hex()
    assert canonical==expected['recovery_registry_key']
    entry=secrets()[canonical]
    assert set(entry)=={'x'}
    x=int(entry['x'],16)
    assert 1<=x<P256_ORDER
    reconstructed=ec.derive_private_key(x,ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
    assert reconstructed==point
    assert expected['certificate_verify_signature_scheme']==0x0804
    assert expected['new_session_ticket_count']==1
    assert expected['tls13_secrets']['CLIENT_TRAFFIC_SECRET_0']==expected['client_application_traffic_secret_0_hex']
    assert expected['tls13_secrets']['SERVER_TRAFFIC_SECRET_0']==expected['server_application_traffic_secret_0_hex']
    assert len(bytes.fromhex(expected['client_handshake_traffic_secret_hex']))==32
    assert 'x' not in expected['public_problem']
    assert not any(key in expected for key in ('private_key','server_private','x','premaster_secret'))


@pytest.mark.parametrize('name',NAMES)
def test_tls13_upload_worker_recovery_exact_http_and_safe_preview(client,name,monkeypatch):
    wire,expected=fixture(name)
    import qsploit.app as app_module
    original=app_module.run_recovery
    observed=[]
    async def public_only(problem,options,report):
        assert isinstance(problem,ECDLogProblem)
        assert set(asdict(problem))=={'kind','curve','public_point'}
        assert problem.kind=='ec_dlog'
        assert problem.curve==expected['public_problem']['curve']
        assert problem.public_point.hex()==expected['public_problem']['public_point']
        observed.append(problem)
        return await original(problem,options,report)
    monkeypatch.setattr(app_module,'run_recovery',public_only)
    session=upload(client,wire)
    sid=session['id']
    assert session['key_exchange']=='ecdhe' and session['authentication'] is None
    assert session['rsa'] is None  # The RSA certificate is authentication, not a recovery problem.
    assert session['tls_version']=='1.3' and session['cipher_suite_id']==expected['cipher_suite_id']
    assert session['selected_group_id']==23 and session['selected_group_name']=='secp256r1'
    assert not session['ems']
    assert not session['psk_selected'] and not session['resumed']
    assert session['recovery_problem']=='ec_dlog'
    assert session['recovery_modes']==['fixture']
    no_plaintext(client,sid)
    job=recover(client,sid)
    assert len(observed)==1
    assert job['state']=='succeeded',job
    assert job['recovery_problem']=='ec_dlog' and job['recovery_verified']
    assert not job['factor_pair_verified']
    assert job['method']=='fixture_lookup' and job['execution']=='none'
    assert job['demo_factors'] is None and not job['provider_job_ids']
    assert job['client_finished_verified'] and job['server_finished_verified']
    parsed=parse_tls(read_connections(wire).connections[0])
    assert job['authenticated_records']==sum(record.content_type==23 for record in parsed.records)
    listing=client.get(f'/api/sessions/{sid}/http').json()
    assert [(m['method'],m['status']) for m in listing]==[('GET',200),('POST',200)]
    public=[session,job,listing]
    for index,oracle in enumerate(expected['exchanges']):
        message=client.get(f'/api/sessions/{sid}/http/{index}').json()
        assert message['request']['raw_b64']==oracle['request_base64']
        assert message['response']['raw_b64']==oracle['response_base64']
        public.append(message)
    assert message['response']['decoded_body_b64']==expected['json_body_base64']
    assert ['note','hello world'] in message['form_parameters']
    for direction in ('c2s','s2c'):
        response=client.get(f'/api/sessions/{sid}/application/{direction}')
        assert response.content==base64.b64decode(expected[f'{direction}_base64'])
    preview=client.get(f'/api/sessions/{sid}/http/0/preview')
    assert preview.status_code==200 and 'Welcome back, Cooper.' in preview.text
    assert '<script' not in preview.text and 'untrusted.qsploit.test' not in preview.text
    assert 'sandbox;' in preview.headers['content-security-policy']
    assert "default-src 'none'" in preview.headers['content-security-policy']
    for value in (secrets()[expected['recovery_registry_key']]['x'],expected['tls13_master_secret_hex'],*expected['tls13_secrets'].values()):
        assert value not in json.dumps(public)


def test_unknown_ephemeral_share_fails_without_using_same_group_or_certificate(client):
    wire,expected=fixture('tls13-p256-unknown')
    assert expected['recovery_registry_key'] not in secrets()
    session=upload(client,wire)
    assert session['implementation']=='supported' and not session['recovery_modes']
    job=recover(client,session['id'])
    assert job['state']=='failed' and job['error']['code']=='FIXTURE_NOT_FOUND'
    assert not job['recovery_verified']
    no_plaintext(client,session['id'])


def alter(wire,mode):
    """Synthetic mutation of genuine packets for negative API tests."""
    source=dpkt.pcap.Reader(io.BytesIO(wire))
    output=io.BytesIO()
    writer=dpkt.pcap.Writer(output,linktype=source.datalink(),snaplen=262144)
    marker=None
    if mode=='handshake':
        parsed=parse_tls(read_connections(wire).connections[0])
        marker=next(r.fragment[-32:] for r in parsed.records if r.content_type==23 and r.direction=='s2c')
    changed=False
    for timestamp,packet in source:
        ip=dpkt.loopback.Loopback(packet).data
        tcp=ip.data
        eligible=isinstance(tcp,dpkt.tcp.TCP) and ((marker in tcp.data) if marker else tcp.data[:1]==b'\x17')
        if not changed and eligible:
            changed=True
            if mode=='missing':
                continue
            offset=tcp.data.find(marker)+len(marker)-1 if marker else len(tcp.data)-1
            tcp.data=tcp.data[:offset]+bytes([tcp.data[offset]^1])+tcp.data[offset+1:]
            packet=packet[:4]+bytes(ip)
        writer.writepkt(packet,timestamp)
    assert changed
    return output.getvalue()


@pytest.mark.parametrize('name',NAMES)
@pytest.mark.parametrize('mode',['ciphertext','handshake'])
def test_tls13_corrupted_record_never_publishes_plaintext(client,name,mode):
    wire,_=fixture(name)
    session=upload(client,alter(wire,mode))
    job=recover(client,session['id'])
    assert job['state']=='failed' and job['error']['code']=='AEAD_AUTH_FAILED'
    no_plaintext(client,session['id'])


@pytest.mark.parametrize('mode,expected_code',[('missing','TCP_GAP')])
def test_tls13_missing_bytes_block_recovery(client,mode,expected_code):
    wire,_=fixture(NAMES[0])
    session=upload(client,alter(wire,mode))
    assert not session['recovery_modes']
    assert expected_code in [issue['code'] for issue in session['blockers']]
    result=client.post(f"/api/sessions/{session['id']}/recover",json={},headers=HEADERS)
    assert result.status_code==400
    assert result.json()['error']['code']==expected_code
    no_plaintext(client,session['id'])


@pytest.mark.parametrize('wrong_type',[False,True])
def test_tls13_wrong_exponent_or_rsa_factors_fail_at_worker_boundary(client,monkeypatch,wrong_type):
    wire,expected=fixture(NAMES[0])
    x=int(secrets()[expected['recovery_registry_key']]['x'],16)
    async def invalid_result(problem,options,report):
        return Recovery(RSAFactors(3,5) if wrong_type else ECDLogSecret(x+1),'fixture_lookup','none',None,())
    monkeypatch.setattr('qsploit.app.run_recovery',invalid_result)
    session=upload(client,wire)
    job=recover(client,session['id'])
    assert job['state']=='failed'
    assert job['error']['code']=='INVALID_DLOG_RESULT'
    assert not job['recovery_verified']
    no_plaintext(client,session['id'])
