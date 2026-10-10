"""Validate an installed wheel through a real localhost server, without test extras.

Run with the clean environment's Python from /private/tmp (outside this repo).
The parent reads independent endpoint oracles. The installed application server
receives only its packaged PCAP through the ordinary upload/recovery HTTP API.
No TestClient, Qiskit, tlslite or traffic-decryption utility is used.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


def main():
    import qsploit
    installed = Path(qsploit.__file__).resolve()
    assert not installed.is_relative_to(ROOT), f'Expected installed wheel, found source checkout: {installed}'
    for name in ('qiskit', 'qiskit_aer', 'qiskit_ionq', 'tlslite', 'pytest', 'httpx'):
        assert importlib.util.find_spec(name) is None, f'Unexpected optional dependency: {name}'
    report = json.loads((ROOT / 'tests/fixtures/protocol-tour.sources.json').read_text())
    def endpoint(value):
        return f"{value['ip']}:{value['port']}"
    oracles = {(endpoint(item['client']), endpoint(item['server'])):
               json.loads((ROOT / 'tests/fixtures' / item['fixture'].replace('.pcap', '.expected.json')).read_text())
               for item in report['sessions']}
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    def request(path, data=None):
        headers = {'X-QSploit': '1'}
        if isinstance(data, dict):
            data = json.dumps(data).encode()
            headers['Content-Type'] = 'application/json'
        with urlopen(Request(origin + path, data=data, headers=headers), timeout=5) as response:
            body = response.read()
            return json.loads(body) if 'application/json' in response.headers.get('Content-Type', '') else body
    with tempfile.TemporaryDirectory(prefix='qsploit-wheel-server-') as directory:
        server = subprocess.Popen([sys.executable, '-m', 'qsploit', '--demo', '--demo-delay-seconds', '0', '--port', str(port)],
                                  cwd=directory, env={**os.environ, 'PYTHONPYCACHEPREFIX': directory + '/pycache'},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise AssertionError(server.communicate()[1])
                try:
                    config = request('/api/config')
                    break
                except (URLError, OSError):
                    time.sleep(.1)
            else:
                raise AssertionError('Installed application did not start')
            assert config['mode'] == 'demo' and config['demo_delay_seconds'] == 0
            assert config['protocol_tour_available']
            assert b'QSploit' in request('/')
            assert b'function' in request('/static/app.js')
            capture = request('/api/captures', request('/api/protocol-tour'))
            assert len(capture['sessions']) == len(oracles)
            combinations = set()
            for session in capture['sessions']:
                sid = session['id']
                expected = oracles[session['client'], session['server']]
                job = request(f'/api/sessions/{sid}/recover', {})
                deadline = time.monotonic() + 25
                while job['state'] in ('running', 'queued') and time.monotonic() < deadline:
                    time.sleep(.025)
                    job = request('/api/jobs/' + job['id'])
                assert job['state'] == 'succeeded', job
                assert job['client_finished_verified'] and job['server_finished_verified']
                assert job['recovery_verified'] and job['execution'] == 'none'
                for direction in ('c2s', 's2c'):
                    actual = request(f'/api/sessions/{sid}/application/{direction}')
                    assert actual == base64.b64decode(expected[f'{direction}_base64'])
                messages = request(f'/api/sessions/{sid}/http')
                assert len(messages) == len(expected['exchanges'])
                for index, exchange in enumerate(expected['exchanges']):
                    view = request(f'/api/sessions/{sid}/http/{index}')
                    assert view['request']['raw_b64'] == exchange['request_base64']
                    assert view['response']['raw_b64'] == exchange['response_base64']
                preview = request(f'/api/sessions/{sid}/http/0/preview')
                assert b'Welcome back, Cooper.' in preview and b'<script' not in preview
                combinations.add((session['tls_version'], session['key_exchange'], session['selected_group_name'] or 'RSA', session['cipher_suite_name']))
            print(json.dumps({'installed_module': str(installed), 'sessions_verified': len(capture['sessions']),
                              'combinations_verified': sorted(combinations), 'optional_dependencies': 'absent',
                              'transport': 'real localhost HTTP with spawned recovery worker',
                              'plaintext': 'exact independent endpoint bytes', 'browser_visual_check': 'not performed'}, indent=2))
        finally:
            if server.poll() is None:
                server.terminate()
            try:
                server.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate(timeout=5)


if __name__ == '__main__':
    main()
