#!/usr/bin/env python3
"""Development only: generate genuine OS TCP/TLS captures and endpoint oracles.

Requires Python project dependencies, OpenSSL >=3.5 and tcpdump capture access.
Run from repository root: .venv/bin/python scripts/make_fixtures.py
No QSploit parser/decryptor is imported. Regeneration replaces randomized captures.
A fresh RSA key and endpoint keylogs live in TemporaryDirectory and are removed.
Only public demonstration factors and explicitly test-only oracles are retained.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

import dpkt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests' / 'fixtures'
DEMO = ROOT / 'qsploit' / 'demo'


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode('ascii')


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def packet_stats(path: Path) -> dict:
    with path.open('rb') as stream:
        reader = dpkt.pcap.Reader(stream)
        linktype = reader.datalink()
        count = sum(1 for _ in reader)
    if linktype not in (0, 1, 108) or count == 0:
        raise RuntimeError(f'Unusable capture: linktype={linktype}, packets={count}')
    return {'packet_count': count, 'linktype': linktype}


def http_payloads() -> tuple[list[bytes], list[bytes], dict]:
    body = b'note=hello+world&token=demo-only'
    requests = [
        b'GET /profile?name=Cooper&tag=a&tag=b&empty= HTTP/1.1\r\nHost: vault.qsploit.test\r\nUser-Agent: QSploit-Fixture/1.0\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n',
        b'POST /echo HTTP/1.1\r\nHost: vault.qsploit.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body,
    ]
    html = '''<!doctype html><html><head><title>Cooper's captured account</title></head>
<body style="background-color:#f4f6fa;font-family:Arial;padding:24px;color:#243047">
<main style="max-width:720px;background-color:white;padding:32px;border:1px solid #dce2ec">
<p style="color:#5265d9;font-size:12px;font-weight:bold">QS / PRIVATE ACCOUNT PORTAL</p>
<h1 style="font-size:32px">Welcome back, Cooper.</h1>
<p>This page was delivered inside the captured HTTPS connection.</p>
<div style="padding:20px;background-color:#edf9f4"><strong>Account verified</strong><p>Account 42 · Demo workspace</p></div>
<h2>Captured profile</h2><table><tr><th>Name</th><td>Cooper</td></tr><tr><th>Plan</th><td>Quantum Explorer</td></tr><tr><th>Region</th><td>us-west</td></tr></table>
<form action="https://untrusted.qsploit.test/submit" method="post"><input type="hidden" name="account_id" value="42"><label>Display name <input name="display_name" value="Cooper"></label><button>Update profile</button></form>
<p><a href="https://untrusted.qsploit.test/account">Account settings</a></p>
<img src="https://untrusted.qsploit.test/tracking.png" onerror="parent.postMessage('unsafe-preview','*')" alt="Linked illustration omitted">
<script>window.__capturedScriptExecuted=true;fetch('https://untrusted.qsploit.test/script');</script>
<p style="color:#637089;font-size:12px">Fixture data only. Linked resources and scripts must remain inert.</p>
</main>'''.encode()
    # Real transmitted padding ensures several TLS records; HTML comments are inert.
    html += b'\n<!-- captured-audit-padding:' + b''.join(hashlib.sha256(str(i).encode()).hexdigest().encode() for i in range(380)) + b' -->\n</body></html>'
    response1 = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ' + str(len(html)).encode() + b'\r\nCache-Control: no-store\r\nX-Capture-Provenance: actual-endpoint-bytes\r\nConnection: keep-alive\r\n\r\n' + html)
    json_value = {'received': {'note': 'hello world', 'token': 'demo-only'}, 'account_id': 42, 'status': 'captured', 'audit': [{'index': i, 'digest': hashlib.sha256(f'qsploit-audit-{i}'.encode()).hexdigest()} for i in range(600)]}
    json_body = json.dumps(json_value, separators=(',', ':')).encode()
    compressed = gzip.compress(json_body, mtime=0)
    chunks = [compressed[i:i+2047] for i in range(0, len(compressed), 2047)]
    chunked = b''.join(f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n' for chunk in chunks) + b'0\r\nX-Fixture-Trailer: complete\r\n\r\n'
    response2 = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nTrailer: X-Fixture-Trailer\r\nConnection: close\r\n\r\n' + chunked
    return requests, [response1, response2], {'html_body_sha256': sha(html), 'json_body_base64': b64(json_body), 'json_body_sha256': sha(json_body)}


def identity(folder: Path, name: str, key=None) -> tuple[Path, Path, rsa.RSAPrivateKey]:
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'vault.qsploit.test')])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(days=1)).not_valid_after(now+dt.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('vault.qsploit.test')]), critical=False)
            .sign(key, hashes.SHA256()))
    key_path, cert_path = folder / f'{name}.key', folder / f'{name}.crt'
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path, key


class PacketCapture:
    def __init__(self, path: Path, interface: str, ports: list[int]):
        self.command = [shutil.which('tcpdump') or 'tcpdump', '-i', interface, '--immediate-mode', '-U', '-s', '0', '-n', '-w', str(path), 'tcp and (' + ' or '.join(f'port {p}' for p in ports) + ')']
        self.process: subprocess.Popen | None = None
        self.log = ''

    def __enter__(self):
        self.process = subprocess.Popen(self.command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        assert self.process.stderr is not None
        line = self.process.stderr.readline().decode()
        if 'listening on' not in line:
            self.process.terminate()
            raise RuntimeError(f'tcpdump failed: {line.strip()}. Run with capture permission.')
        self.log = line
        time.sleep(.15)
        return self

    def __exit__(self, *_):
        assert self.process is not None
        time.sleep(.4)
        self.process.send_signal(signal.SIGINT)
        _, stderr = self.process.communicate(timeout=5)
        self.log += stderr.decode()
        if self.process.returncode != 0 or '0 packets captured' in self.log.splitlines():
            raise RuntimeError(f'tcpdump exited with {self.process.returncode}: {self.log}')


def listener() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 0))
    sock.listen(1)
    sock.settimeout(15)
    return sock


def exchange(sock: socket.socket, key_path: Path, cert_path: Path, temp: Path, mode: str, openssl: str, cipher: str | None = None) -> dict:
    requests, responses, body_oracles = http_payloads()
    server_received = bytearray()
    server_sent = bytearray()
    details: dict = {}
    errors: list[BaseException] = []
    port = sock.getsockname()[1]
    cipher = cipher or ('ECDHE-RSA-AES128-GCM-SHA256' if mode == 'ecdhe' else 'AES128-GCM-SHA256')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    context.set_alpn_protocols(['http/1.1'])
    if mode != 'tickets':
        context.options |= ssl.OP_NO_TICKET
    if mode == 'tls13':
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_ecdh_curve('X25519')
    else:
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(cipher)
    server_log = temp / f'{port}-server.keys'
    client_log = temp / f'{port}-client.keys'
    context.keylog_filename = str(server_log)

    def serve():
        try:
            raw, peer = sock.accept()
            raw.settimeout(15)
            with context.wrap_socket(raw, server_side=True) as conn:
                details.update(client={'ip': peer[0], 'port': peer[1]}, server={'ip': '127.0.0.1', 'port': port}, version=conn.version(), cipher=conn.cipher()[0], alpn=conn.selected_alpn_protocol())
                for request, response in zip(requests, responses):
                    observed = bytearray()
                    while len(observed) < len(request):
                        fragment = conn.recv(len(request)-len(observed))
                        if not fragment:
                            raise RuntimeError('Client closed before request completed')
                        observed.extend(fragment)
                    if bytes(observed) != request:
                        raise RuntimeError('Server did not receive byte-identical request')
                    server_received.extend(observed)
                    # Explicit application writes exercise TLS/TCP record separation.
                    for index in range(0, len(response), 4093):
                        piece = response[index:index+4093]
                        conn.sendall(piece)
                        server_sent.extend(piece)
                # Actual bilateral TLS close_notify; never synthesize alert records.
                raw = conn.unwrap()
                raw.close()
                details['server_shutdown_complete'] = True
        except BaseException as exc:
            errors.append(exc)
        finally:
            sock.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    command = [openssl, 's_client', '-connect', f'127.0.0.1:{port}', '-servername', 'vault.qsploit.test', '-alpn', 'http/1.1', '-quiet', '-no_ign_eof', '-keylogfile', str(client_log)]
    if mode != 'tickets':
        command += ['-no_ticket']
    if mode == 'tls13':
        command += ['-tls1_3', '-groups', 'X25519', '-ciphersuites', 'TLS_AES_128_GCM_SHA256']
    else:
        command += ['-tls1_2', '-cipher', cipher]
        if mode == 'noems':
            command += ['-no_ems']
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdin is not None and process.stdout is not None
    client_received = bytearray()
    expected_length = sum(map(len, responses))
    complete = threading.Event()
    def read_client():
        while True:
            piece = process.stdout.read1(65536)
            if not piece:
                break
            client_received.extend(piece)
            if len(client_received) >= expected_length:
                complete.set()
    reader = threading.Thread(target=read_client, daemon=True)
    reader.start()
    for request in requests:
        process.stdin.write(request)
        process.stdin.flush()
    if not complete.wait(15):
        process.kill()
        raise RuntimeError(f'Client did not receive complete responses ({len(client_received)}/{expected_length}); server errors {errors}')
    try:
        process.stdin.close()
    except BrokenPipeError:
        pass
    process.wait(timeout=15)
    thread.join(timeout=15)
    reader.join(timeout=2)
    if thread.is_alive() or errors:
        raise RuntimeError(f'TLS server failed: {errors}')
    if process.returncode != 0:
        assert process.stderr is not None
        raise RuntimeError(f'OpenSSL client exited with {process.returncode}: {process.stderr.read().decode()}')
    if bytes(client_received) != b''.join(responses):
        raise RuntimeError('Independent OpenSSL client plaintext differs from server bytes')
    server_keys = [line for line in server_log.read_text().splitlines() if line.startswith('CLIENT_RANDOM ')]
    client_keys = [line for line in client_log.read_text().splitlines() if line.startswith('CLIENT_RANDOM ')]
    if mode != 'tls13':
        if len(server_keys) != 1 or server_keys != client_keys:
            raise RuntimeError('Independent endpoint master-secret logs disagree')
        _, client_random, master_secret = server_keys[0].split()
        details.update(client_random_hex=client_random.lower(), master_secret_hex=master_secret.lower())
    details.update(mode=mode, ems=mode != 'noems' if mode != 'tls13' else None,
        c2s_base64=b64(bytes(server_received)), s2c_base64=b64(bytes(client_received)),
        endpoint_observations={'server_received_sha256': sha(bytes(server_received)), 'server_sent_sha256': sha(bytes(server_sent)), 'client_received_sha256': sha(bytes(client_received)), 'client_sent_sha256': sha(b''.join(requests)), 'master_secret_oracle': 'matching independently emitted OpenSSL client and Python ssl server keylogs; generation-only logs deleted' if mode != 'tls13' else None},
        exchanges=[{'request_base64': b64(a), 'response_base64': b64(b)} for a,b in zip(requests,responses)], **body_oracles)
    return details


def plain_exchange(sock: socket.socket) -> dict:
    port = sock.getsockname()[1]
    request = b'GET /ordinary-cleartext HTTP/1.1\r\nHost: local.qsploit.test\r\n\r\n'
    response = b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nplain tcp ok'
    def serve():
        conn, _ = sock.accept()
        with conn:
            assert conn.recv(65536) == request
            conn.sendall(response)
        sock.close()
    thread = threading.Thread(target=serve)
    thread.start()
    with socket.create_connection(('127.0.0.1', port)) as client:
        client.sendall(request)
        actual = b''
        while chunk := client.recv(65536):
            actual += chunk
        assert actual == response
    thread.join()
    return {'mode': 'tcp', 'server': {'ip': '127.0.0.1', 'port': port}, 'c2s_base64': b64(request), 's2c_base64': b64(response)}


def generate_ticket_fixture(args, generator):
    """Use the existing public demo factors to issue a new self-signed test cert."""
    fixtures = json.loads((DEMO / 'factors.json').read_text())
    modulus, factors = next(iter(fixtures.items()))
    n, p, q = int(modulus,16), int(factors['p'],16), int(factors['q'],16)
    d = pow(65537,-1,math.lcm(p-1,q-1))
    key = rsa.RSAPrivateNumbers(p,q,d,d%(p-1),d%(q-1),pow(q,-1,p),rsa.RSAPublicNumbers(65537,n)).private_key()
    with tempfile.TemporaryDirectory(prefix='qsploit-ticket-') as temporary:
        temp = Path(temporary)
        key_path, cert_path, _ = identity(temp,'ticket',key)
        sock = listener()
        path = FIXTURES / 'tls12-rsa-ticket.pcap'
        with PacketCapture(path,args.interface,[sock.getsockname()[1]]) as capture:
            details = exchange(sock,key_path,cert_path,temp,'tickets',args.openssl)
        record = {'capture':path.name,'sha256':sha(path.read_bytes()),'generator':generator,'rsa_modulus_hex':modulus,**details,'tcpdump_log':capture.log}
        (FIXTURES / 'tls12-rsa-ticket.expected.json').write_text(json.dumps(record,indent=2)+'\n')
        manifest = json.loads((FIXTURES / 'manifest.json').read_text())
        manifest['captures'] = [r for r in manifest['captures'] if r['file'] != path.name]
        manifest['captures'].append({'file':path.name,'sha256':record['sha256'],'size':path.stat().st_size,'sessions':1,'mode':'tickets',**packet_stats(path)})
        (FIXTURES / 'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        print('Generated tls12-rsa-ticket.pcap: real NewSessionTicket issuance, independent endpoint oracle',flush=True)


def generate_aes256_fixtures(args, generator):
    """Append an independently captured AES-256/SHA-384 family, preserving baseline."""
    names = [('tls12-rsa-aes256','ems'),('tls12-rsa-aes256-noems','noems')]
    names_set = {name+'.pcap' for name,_ in names}
    manifest = json.loads((FIXTURES / 'manifest.json').read_text())
    preserved = {record['file']:sha((FIXTURES/record['file']).read_bytes())
                 for record in manifest['captures'] if record['file'] not in names_set}
    factors = json.loads((DEMO / 'factors.json').read_text())
    previous_moduli = set()
    for name,_ in names:
        expected_path = FIXTURES / (name+'.expected.json')
        if expected_path.exists():
            previous_moduli.add(json.loads(expected_path.read_text())['rsa_modulus_hex'])
    with tempfile.TemporaryDirectory(prefix='qsploit-aes256-') as temporary:
        temp = Path(temporary)
        key_path, cert_path, key = identity(temp,'aes256')
        numbers = key.private_numbers()
        modulus = format(numbers.public_numbers.n,'x')
        generated = []
        for name,mode in names:
            sock = listener()
            path = temp / (name+'.pcap')
            with PacketCapture(path,args.interface,[sock.getsockname()[1]]) as capture:
                details = exchange(sock,key_path,cert_path,temp,mode,args.openssl,cipher='AES256-GCM-SHA384')
            if details['cipher'] != 'AES256-GCM-SHA384' or details['version'] != 'TLSv1.2':
                raise RuntimeError('AES-256 fixture negotiated an unexpected protocol')
            record = {'capture':path.name,'sha256':sha(path.read_bytes()),'generator':generator,
                      'rsa_modulus_hex':modulus,'cipher_suite_id':0x009d,'prf_hash':'sha384',
                      **details,'tcpdump_log':capture.log}
            (temp/(name+'.expected.json')).write_text(json.dumps(record,indent=2)+'\n')
            generated.append({'file':path.name,'sha256':record['sha256'],'size':path.stat().st_size,
                              'sessions':1,'mode':mode,'cipher_suite_id':0x009d,**packet_stats(path)})
        # Keep all still-referenced test keys on regeneration, and replace only a
        # prior key exclusively associated with these two targeted fixtures.
        retained_moduli = set()
        for expected_path in FIXTURES.glob('*.expected.json'):
            if expected_path.name not in {name+'.expected.json' for name,_ in names}:
                entry = json.loads(expected_path.read_text())
                if 'rsa_modulus_hex' in entry:
                    retained_moduli.add(entry['rsa_modulus_hex'])
        for old in previous_moduli-retained_moduli:
            factors.pop(old,None)
        factors[modulus] = {'p':format(numbers.p,'x'),'q':format(numbers.q,'x')}
        for name,_ in names:
            shutil.copyfile(temp/(name+'.pcap'),FIXTURES/(name+'.pcap'))
            shutil.copyfile(temp/(name+'.pcap'),DEMO/(name+'.pcap'))
            shutil.copyfile(temp/(name+'.expected.json'),FIXTURES/(name+'.expected.json'))
        (DEMO/'factors.json').write_text(json.dumps(factors,indent=2)+'\n')
        manifest['captures'] = [record for record in manifest['captures'] if record['file'] not in names_set]+generated
        (FIXTURES/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    for filename,digest in preserved.items():
        if sha((FIXTURES/filename).read_bytes()) != digest:
            raise RuntimeError(f'Existing capture was unexpectedly modified: {filename}')
    print('Generated AES256-GCM-SHA384 EMS + non-EMS captures; baseline PCAPs unchanged; temporary key/keylogs deleted.',flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--ticket-only', action='store_true', help='Add ticket issuance case using existing public demo factors')
    mode.add_argument('--aes256-only', action='store_true', help='Add AES256-GCM-SHA384 EMS/non-EMS captures without changing baseline captures')
    parser.add_argument('--interface', default='lo0' if sys.platform == 'darwin' else 'lo')
    parser.add_argument('--openssl', default=shutil.which('openssl') or 'openssl')
    args = parser.parse_args()
    FIXTURES.mkdir(parents=True, exist_ok=True)
    DEMO.mkdir(parents=True, exist_ok=True)
    generator = {'script': 'scripts/make_fixtures.py', 'python': platform.python_version(), 'python_ssl': ssl.OPENSSL_VERSION, 'openssl': subprocess.check_output([args.openssl,'version'], text=True).strip(), 'tcpdump': subprocess.check_output([shutil.which('tcpdump') or 'tcpdump','--version'], stderr=subprocess.STDOUT, text=True).splitlines()[0], 'os': platform.platform(), 'interface': args.interface, 'generated_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'packet_provenance': 'Unmodified OS packets captured by tcpdump from a real loopback TCP socket; TLS generated by OpenSSL s_client and Python ssl server.'}
    if args.aes256_only:
        generate_aes256_fixtures(args,generator)
        return
    if args.ticket_only:
        generate_ticket_fixture(args,generator)
        return
    manifest = {'generator': generator, 'captures': []}
    with tempfile.TemporaryDirectory(prefix='qsploit-fixture-') as temporary:
        temp = Path(temporary)
        key_path, cert_path, key = identity(temp, 'demo')
        nums = key.private_numbers()
        modulus = format(nums.public_numbers.n, 'x')
        (DEMO / 'factors.json').write_text(json.dumps({modulus: {'p': format(nums.p,'x'), 'q': format(nums.q,'x')}}, indent=2)+'\n')
        for name, mode in [('tls12-rsa-ems','ems'), ('tls12-rsa-noems','noems')]:
            sock = listener()
            path = FIXTURES / f'{name}.pcap'
            with PacketCapture(path, args.interface, [sock.getsockname()[1]]) as capture:
                details = exchange(sock, key_path, cert_path, temp, mode, args.openssl)
            record = {'capture': path.name, 'sha256': sha(path.read_bytes()), 'generator': generator, 'rsa_modulus_hex': modulus, **details, 'tcpdump_log': capture.log}
            (FIXTURES / f'{name}.expected.json').write_text(json.dumps(record, indent=2)+'\n')
            manifest['captures'].append({'file': path.name, 'sha256': record['sha256'], 'size': path.stat().st_size, 'sessions': 1, 'mode': mode, **packet_stats(path)})
            print(f'Generated {path.name}: {path.stat().st_size} bytes, endpoint plaintext matched', flush=True)
        socks = [listener() for _ in range(4)]
        mixed_path = FIXTURES / 'mixed-discovery.pcap'
        with PacketCapture(mixed_path, args.interface, [sock.getsockname()[1] for sock in socks]) as capture:
            sessions = [exchange(sock, key_path, cert_path, temp, mode, args.openssl) for sock,mode in zip(socks[:3], ['ems','ecdhe','tls13'])]
            sessions.append(plain_exchange(socks[3]))
        mixed = {'capture': mixed_path.name, 'sha256': sha(mixed_path.read_bytes()), 'generator': generator, 'rsa_modulus_hex': modulus, 'sessions': sessions, 'tcpdump_log': capture.log}
        (FIXTURES / 'mixed-discovery.expected.json').write_text(json.dumps(mixed, indent=2)+'\n')
        manifest['captures'].append({'file': mixed_path.name, 'sha256': mixed['sha256'], 'size': mixed_path.stat().st_size, 'sessions': 4, **packet_stats(mixed_path)})
        print(f'Generated {mixed_path.name}: four distinct genuine TCP sessions', flush=True)
        unknown_key, unknown_cert, _ = identity(temp, 'unknown')
        sock = listener()
        path = FIXTURES / 'unknown-rsa.pcap'
        with PacketCapture(path, args.interface, [sock.getsockname()[1]]):
            exchange(sock, unknown_key, unknown_cert, temp, 'ems', args.openssl)
        manifest['captures'].append({'file': path.name, 'sha256': sha(path.read_bytes()), 'size': path.stat().st_size, 'sessions': 1, 'mode': 'ems', 'factors_bundled': False, **packet_stats(path)})
        print('Generated unknown-rsa.pcap: test-key factors deliberately not retained', flush=True)
    shutil.copyfile(FIXTURES / 'tls12-rsa-ems.pcap', DEMO / 'qsploit-demo.pcap')
    shutil.copyfile(FIXTURES / 'tls12-rsa-ems.pcap', DEMO / 'tls12-rsa-ems.pcap')
    shutil.copyfile(FIXTURES / 'mixed-discovery.pcap', DEMO / 'mixed-discovery.pcap')
    manifest['temporary_private_key_and_keylogs_deleted'] = True
    manifest['runtime_recovery_material'] = 'qsploit/demo/factors.json contains modulus-matched factors only; expected JSON files are tests only.'
    (FIXTURES / 'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    generate_ticket_fixture(args,generator)
    generate_aes256_fixtures(args,generator)
    print('Finished: endpoint private keys and keylogs removed; master-secret oracles retained only in tests/fixtures/*.expected.json.', flush=True)


if __name__ == '__main__':
    main()
