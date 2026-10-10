#!/usr/bin/env python3
"""Development-only genuine TLS DHE/ECDHE captures; no QSploit imports.

A tlslite-ng 0.8.2 server and independent OpenSSL client use their normal RNGs
and TLS wire implementations. A temporary observer records the server's random
FFDH/P-256 exponent or X25519 scalar by calling the original random key sampler unchanged.
Only explicit known-test discrete logs are saved in the demo registry. Private
certificate keys and OpenSSL session-key logs live in a TemporaryDirectory.
Requires the project's fixture extra and tcpdump capture access.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

import tlslite
from tlslite.api import HandshakeSettings, TLSConnection, X509, X509CertChain, parsePEMKey
from tlslite.keyexchange import ECDHKeyExchange, FFDHKeyExchange
from tlslite.mathtls import RFC7919_GROUPS
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

from make_fixtures import (DEMO, FIXTURES, PacketCapture, b64, http_payloads,
                           identity, listener, packet_stats, sha)


def exchange(sock, certificate, private_key, temp, cipher_name, ems, openssl, family='dhe', tls13=False, key_update=False):
    requests,responses,body_oracles = http_payloads()
    server_received,server_sent,client_received = bytearray(),bytearray(),bytearray()
    observed_keys,errors = [],[]
    details = {}
    port = sock.getsockname()[1]
    expected_cipher = ({'aes128gcm':0x009e,'aes256gcm':0x009f,'chacha20-poly1305':0xccaa} if family=='dhe'
                       else {'aes128gcm':0xc02f,'aes256gcm':0xc030,'chacha20-poly1305':0xcca8})[cipher_name]
    openssl_cipher = ('DHE' if family=='dhe' else 'ECDHE')+'-RSA-'+{
        'aes128gcm':'AES128-GCM-SHA256','aes256gcm':'AES256-GCM-SHA384','chacha20-poly1305':'CHACHA20-POLY1305'}[cipher_name]
    if tls13:
        expected_cipher = 0x1301 if cipher_name=='aes128gcm' else 0x1302
        openssl_cipher = 'TLS_AES_128_GCM_SHA256' if cipher_name=='aes128gcm' else 'TLS_AES_256_GCM_SHA384'
    keylog = temp/f'{port}-openssl.keys'
    settings = HandshakeSettings()
    version = (3,4) if tls13 else (3,3)
    settings.minVersion = settings.maxVersion = version
    settings.versions = [version]
    settings.keyExchangeNames = ['dhe_rsa' if family=='dhe' else 'ecdhe_rsa']
    settings.cipherNames = [cipher_name]
    settings.macNames = ['aead']
    settings.dhGroups = ['ffdhe2048']
    # Older TLS1.2 clients may omit finite-field group offers; also configure
    # the standard explicit fallback, rather than tlslite's RFC5054 default.
    settings.dhParams = RFC7919_GROUPS[0]
    if family!='dhe':
        group = 'secp256r1' if family=='p256' else 'x25519'
        settings.eccCurves = [group]
        settings.defaultCurve = group
        settings.keyShares = [group]
        settings.ec_point_formats = [0]
    settings.rsaSigHashes = ['sha256']
    settings.rsaSchemes = ['pss' if tls13 else 'pkcs1']
    settings.useExtendedMasterSecret = ems
    settings.requireExtendedMasterSecret = ems
    settings.ticketKeys = [bytearray(os.urandom(32))] if tls13 else []
    settings.ticket_count = 1 if tls13 else 0
    kex_class = FFDHKeyExchange if family=='dhe' else ECDHKeyExchange
    original = kex_class.get_random_private_key

    def observe_generated_exponent(kex):
        # Passive observation only: invoke the library's unmodified random
        # sampler and return exactly the sampled object to the TLS endpoint.
        private = original(kex)
        if family=='dhe':
            p,g = kex.prime,kex.generator
            observed_keys.append({'p':p,'g':g,'y':pow(g,private,p),'order':(p-1)//2,'x':private})
        elif family=='p256':
            if kex.group!=23:
                raise RuntimeError('Observer expected the P-256 named group')
            observed_keys.append({'curve':'secp256r1','public_point':bytes(kex.calc_public_value(private,'uncompressed')),
                                  'x':private.privkey.secret_multiplier})
        else:
            if kex.group!=29 or len(private)!=32:
                raise RuntimeError('Observer expected an X25519 random private encoding')
            # tlslite clamps bytearrays in place during multiplication. Keep
            # the original bytes and compute on a copy so the observer cannot
            # change even the unused bits of the endpoint's random return.
            scalar = bytes(private)
            public = bytes(kex.calc_public_value(bytearray(scalar)))
            if bytes(private)!=scalar:
                raise RuntimeError('Observer changed the endpoint random private encoding')
            observed_keys.append({'curve':'x25519','public_point':public,'scalar':scalar})
        return private

    def serve():
        raw = None
        try:
            raw,peer = sock.accept()
            raw.settimeout(20)
            conn = TLSConnection(raw)
            conn.closeSocket = False
            conn.handshakeServer(certChain=certificate,privateKey=private_key,settings=settings,
                                 alpn=[bytearray(b'http/1.1')])
            if conn.version != version or conn.session.cipherSuite != expected_cipher:
                raise RuntimeError('Endpoint negotiated an unexpected TLS family')
            if not tls13 and conn.extendedMasterSecret is not ems:
                raise RuntimeError('Endpoint negotiated unexpected EMS state')
            details.update(client={'ip':peer[0],'port':peer[1]},server={'ip':'127.0.0.1','port':port},
                           version='TLSv1.3' if tls13 else 'TLSv1.2',cipher=openssl_cipher,cipher_suite_id=conn.session.cipherSuite,
                           alpn=bytes(conn.session.appProto).decode(),ems=None if tls13 else conn.extendedMasterSecret,
                           client_random_hex=bytes(conn._clientRandom).hex())
            if tls13:
                details.update(tls13_master_secret_hex=bytes(conn.session.masterSecret).hex(),
                               client_application_traffic_secret_0_hex=bytes(conn.session.cl_app_secret).hex(),
                               server_application_traffic_secret_0_hex=bytes(conn.session.sr_app_secret).hex(),
                               certificate_verify_signature_scheme=0x0804,new_session_ticket_count=1)
            else:
                details.update(master_secret_hex=bytes(conn.session.masterSecret).hex(),server_key_exchange_signature_scheme=0x0401)
            for index,(request,response) in enumerate(zip(requests,responses)):
                incoming = bytearray()
                while len(incoming)<len(request):
                    piece = conn.recv(len(request)-len(incoming))
                    if not piece:
                        raise RuntimeError('Client closed before complete request')
                    incoming.extend(piece)
                if bytes(incoming) != request:
                    raise RuntimeError('Independent server request bytes differ')
                server_received.extend(incoming)
                for pos in range(0,len(response),4093):
                    piece = response[pos:pos+4093]
                    conn.sendall(piece)
                    server_sent.extend(piece)
                if key_update and index==0:
                    # Normal endpoint API: update server application traffic
                    # keys after the first response, before encrypting the next.
                    for _ in conn.send_keyupdate_request(0):
                        pass
                    details['server_key_update_count'] = 1
                    details['server_application_traffic_secret_1_hex'] = bytes(conn.session.sr_app_secret).hex()
            conn.close()
            details['server_shutdown_complete'] = True
        except BaseException as exc:
            errors.append(exc)
        finally:
            if raw is not None:
                raw.close()
            sock.close()

    # Only this server thread performs TLS in this Python process. The peer is
    # a separate OpenSSL process and cannot use this observer or registry.
    kex_class.get_random_private_key = observe_generated_exponent
    process = None
    thread = threading.Thread(target=serve,daemon=True)
    reader = None
    try:
        thread.start()
        command = [openssl,'s_client','-connect',f'127.0.0.1:{port}','-servername','vault.qsploit.test',
                   '-tls1_3' if tls13 else '-tls1_2','-ciphersuites' if tls13 else '-cipher',openssl_cipher,
                   '-groups',{'dhe':'ffdhe2048','p256':'P-256','x25519':'X25519'}[family],
                   '-sigalgs','rsa_pss_rsae_sha256' if tls13 else 'rsa_pkcs1_sha256',
                   '-alpn','http/1.1','-quiet','-no_ign_eof','-keylogfile',str(keylog)]
        if not tls13:
            command += ['-no_ticket']
        if not tls13 and not ems:
            command += ['-no_ems']
        process = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        complete = threading.Event()
        expected_length = sum(map(len,responses))
        def read_client():
            while True:
                piece = process.stdout.read1(65536)
                if not piece:
                    break
                client_received.extend(piece)
                if len(client_received)>=expected_length:
                    complete.set()
        reader = threading.Thread(target=read_client,daemon=True)
        reader.start()
        for request in requests:
            process.stdin.write(request)
            process.stdin.flush()
        if not complete.wait(20):
            process.kill()
            _,stderr = process.communicate()
            raise RuntimeError(f'OpenSSL response incomplete {len(client_received)}/{expected_length}; endpoint errors {errors}; {stderr.decode()}')
        try:
            process.stdin.close()
        except BrokenPipeError:
            pass
        process.wait(timeout=20)
        thread.join(timeout=20)
        reader.join(timeout=2)
        if process.returncode != 0 or errors or thread.is_alive():
            raise RuntimeError(f'TLS endpoint failed: {errors}; {process.stderr.read().decode()}')
    finally:
        kex_class.get_random_private_key = original
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    if bytes(client_received) != b''.join(responses):
        raise RuntimeError('OpenSSL-received bytes differ from server-sent bytes')
    key_lines = [line.split() for line in keylog.read_text().splitlines() if line and not line.startswith('#')]
    if tls13:
        required = {'CLIENT_HANDSHAKE_TRAFFIC_SECRET','SERVER_HANDSHAKE_TRAFFIC_SECRET',
                    'CLIENT_TRAFFIC_SECRET_0','SERVER_TRAFFIC_SECRET_0','EXPORTER_SECRET'}
        if not required <= {fields[0] for fields in key_lines}:
            raise RuntimeError('Missing independent OpenSSL TLS 1.3 traffic-secret oracle')
        # tlslite's server _clientRandom is populated only on its TLS 1.2
        # return path. Use the independent peer log's connection identifier;
        # the matched application secrets below bind it to this handshake.
        randoms = {fields[1].lower() for fields in key_lines}
        if len(randoms)!=1 or len(bytes.fromhex(next(iter(randoms))))!=32:
            raise RuntimeError('Independent OpenSSL keylog mixes TLS connections')
        details['client_random_hex'] = next(iter(randoms))
        oracles = {label:secret.lower() for label,_,secret in key_lines}
        secret_size = 32 if cipher_name=='aes128gcm' else 48
        if any(len(bytes.fromhex(value))!=secret_size for value in oracles.values()):
            raise RuntimeError('Independent TLS 1.3 secrets have the wrong negotiated hash length')
        for side in ('client','server'):
            if oracles[side.upper()+'_TRAFFIC_SECRET_0']!=details[side+'_application_traffic_secret_0_hex']:
                raise RuntimeError('Independent OpenSSL/tlslite TLS 1.3 application-secret oracles disagree')
            details[side+'_handshake_traffic_secret_hex'] = oracles[side.upper()+'_HANDSHAKE_TRAFFIC_SECRET']
        details['tls13_secrets'] = oracles
        if key_update:
            updates = [value for label,value in oracles.items() if label.startswith('SERVER_TRAFFIC_SECRET_') and label!='SERVER_TRAFFIC_SECRET_0']
            if updates != [details['server_application_traffic_secret_1_hex']]:
                raise RuntimeError('Independent OpenSSL/tlslite updated application-secret oracles disagree')
    else:
        key_lines = [fields for fields in key_lines if fields[0]=='CLIENT_RANDOM']
        if len(key_lines) != 1:
            raise RuntimeError('Missing independent OpenSSL master-secret oracle')
        _,client_random,master_secret = key_lines[0]
        if client_random.lower() != details['client_random_hex'] or master_secret.lower() != details['master_secret_hex']:
            raise RuntimeError('Independent OpenSSL/tlslite master-secret oracles disagree')
    if len(observed_keys) != 1:
        raise RuntimeError('Expected one independently random server ephemeral exponent')
    key = observed_keys[0]
    if family=='dhe':
        if (key['g'],key['p'])!=RFC7919_GROUPS[0] or not 1<key['x']<key['order'] or pow(key['g'],key['x'],key['p'])!=key['y']:
            raise RuntimeError('Invalid observed FFDHE2048 key')
        public = {field:format(key[field],'x') for field in ('p','g','y','order')}
    elif family=='p256':
        independent_public = ec.derive_private_key(key['x'],ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
        if len(key['public_point'])!=65 or key['public_point'][0]!=4 or independent_public!=key['public_point']:
            raise RuntimeError('Invalid observed P-256 key')
        public = {'curve':key['curve'],'public_point':key['public_point'].hex()}
    else:
        independent_public = x25519.X25519PrivateKey.from_private_bytes(key['scalar']).public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        if len(key['public_point'])!=32 or independent_public!=key['public_point']:
            raise RuntimeError('Invalid observed X25519 key')
        if int.from_bytes(key['public_point'],'little')>=2**255-19:
            raise RuntimeError('Expected a canonical X25519 public encoding')
        public = {'curve':key['curve'],'public_point':key['public_point'].hex()}
    details.update(c2s_base64=b64(bytes(server_received)),s2c_base64=b64(bytes(client_received)),
                   mode='tls13_'+family if tls13 else family+('_ems' if ems else '_noems'),prf_hash='sha384' if cipher_name=='aes256gcm' else 'sha256',
                   public_problem=public,
                   endpoint_observations={'server_received_sha256':sha(bytes(server_received)),
                        'server_sent_sha256':sha(bytes(server_sent)),'client_received_sha256':sha(bytes(client_received)),
                        'client_sent_sha256':sha(b''.join(requests)),
                        'master_secret_oracle':('independent OpenSSL TLS 1.3 keylog; both application traffic secrets matched tlslite server session; generation-only logs deleted' if tls13 else
                                                'independent OpenSSL CLIENT_RANDOM keylog matched tlslite server session master; generation-only logs deleted'),
                        'recovery_oracle':f'passive observer of original tlslite-ng {kex_class.__name__}.get_random_private_key; RNG and returned exponent unchanged'},
                   exchanges=[{'request_base64':b64(a),'response_base64':b64(b)} for a,b in zip(requests,responses)],**body_oracles)
    return details,key


def registry_key(public):
    # Canonical registry encoding is coordinated with the quantum component.
    if 'curve' in public:
        return public['curve']+':'+public['public_point']
    return ':'.join(public[field] for field in ('p','g','y','order'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface',default='lo0' if sys.platform=='darwin' else 'lo')
    parser.add_argument('--openssl',default=shutil.which('openssl') or 'openssl')
    parser.add_argument('--family',choices=['dhe','p256','x25519'],default='dhe',help='Generate only this family, preserving other captures')
    parser.add_argument('--tls13',action='store_true',help='Generate only the TLS 1.3 AES-128 baseline and unknown-share case')
    parser.add_argument('--key-update',action='store_true',help='Generate a separate TLS 1.3 capture with a genuine server KeyUpdate')
    parser.add_argument('--aes256',action='store_true',help='Generate the TLS 1.3 AES-256/SHA-384 family only')
    parser.add_argument('--chacha',action='store_true',help='Generate the gated TLS 1.2 DHE ChaCha20-Poly1305 family only')
    args = parser.parse_args()
    if args.key_update and not args.tls13:
        parser.error('--key-update requires --tls13')
    if args.aes256 and (not args.tls13 or args.key_update):
        parser.error('--aes256 requires the baseline TLS 1.3 capture mode')
    if args.chacha and (args.tls13 or args.aes256 or args.family!='dhe'):
        parser.error('The current ChaCha20-Poly1305 gate is TLS 1.2 DHE only')
    if args.tls13 and args.family=='dhe':
        parser.error('TLS 1.3 fixture generation currently supports P-256 and X25519')
    if tlslite.__version__ != '0.8.2':
        raise RuntimeError('The development observer is verified against tlslite-ng 0.8.2 only')
    cases = [('tls12-dhe-aes128-ems','aes128gcm',True,True),
             ('tls12-dhe-aes128-noems','aes128gcm',False,True),
             ('tls12-dhe-aes256-ems','aes256gcm',True,True),
             ('tls12-dhe-aes256-noems','aes256gcm',False,True),
             ('tls12-dhe-unknown','aes128gcm',True,False)]
    if args.family!='dhe':
        cases = [(name.replace('tls12-dhe-','tls12-ecdhe-'+args.family+'-'),cipher,ems,known) for name,cipher,ems,known in cases]
    if args.chacha:
        cases = [('tls12-dhe-chacha-ems','chacha20-poly1305',True,True),
                 ('tls12-dhe-chacha-noems','chacha20-poly1305',False,True),
                 ('tls12-dhe-chacha-unknown','chacha20-poly1305',True,False)]
    if args.tls13:
        bits = 256 if args.aes256 else 128
        cipher = f'aes{bits}gcm'
        unknown_name = f'tls13-{args.family}-aes256-unknown' if args.aes256 else f'tls13-{args.family}-unknown'
        cases = [(f'tls13-{args.family}-aes{bits}',cipher,True,True),
                 (unknown_name,cipher,True,False)]
        if args.key_update:
            cases = [(f'tls13-{args.family}-aes128-keyupdate','aes128gcm',True,True)]
    names = {name+'.pcap' for name,_,_,_ in cases}
    manifest = json.loads((FIXTURES/'manifest.json').read_text())
    preserved = {record['file']:sha((FIXTURES/record['file']).read_bytes())
                 for record in manifest['captures'] if record['file'] not in names}
    registry_path = DEMO/('dlog.json' if args.family=='dhe' else 'ec_dlog.json')
    registry = json.loads(registry_path.read_text()) if registry_path.exists() else {}
    for name,_,_,_ in cases:
        prior = FIXTURES/(name+'.expected.json')
        if prior.exists():
            registry.pop(json.loads(prior.read_text()).get('recovery_registry_key'),None)
    generator = {'script':'scripts/make_ephemeral_fixtures.py','python':platform.python_version(),
                 'server':'tlslite-ng '+tlslite.__version__,
                 'openssl':subprocess.check_output([args.openssl,'version'],text=True).strip(),
                 'tcpdump':subprocess.check_output([shutil.which('tcpdump') or 'tcpdump','--version'],stderr=subprocess.STDOUT,text=True).splitlines()[0],
                 'os':platform.platform(),'interface':args.interface,'generated_at_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
                 'packet_provenance':'Unmodified OS packets captured by tcpdump from real loopback TCP sockets; TLS generated by independent OpenSSL client and tlslite-ng server.',
                 'observer':f'Passive original {args.family} random-exponent return observer; no RNG, record, handshake or packet replacement.'}
    with tempfile.TemporaryDirectory(prefix='qsploit-'+args.family+'-') as temporary:
        temp = Path(temporary)
        _,cert_path,signing_key = identity(temp,args.family+'-signing')
        cert = X509()
        cert.parse(cert_path.read_text())
        chain = X509CertChain([cert])
        key_pem = signing_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()).decode()
        tls_private = parsePEMKey(key_pem,private=True,implementations=['python'])
        generated = []
        for name,cipher,ems,known in cases:
            sock = listener()
            path = temp/(name+'.pcap')
            with PacketCapture(path,args.interface,[sock.getsockname()[1]]) as capture:
                details,key = exchange(sock,chain,tls_private,temp,cipher,ems,args.openssl,args.family,args.tls13,args.key_update)
            lookup = registry_key(details['public_problem'])
            record = {'capture':path.name,'sha256':sha(path.read_bytes()),'generator':generator,
                      'recovery_registry_key':lookup,'recovery_secret_bundled':known,**details,'tcpdump_log':capture.log}
            (temp/(name+'.expected.json')).write_text(json.dumps(record,indent=2)+'\n')
            if known:
                registry[lookup] = {'scalar':key['scalar'].hex()} if args.family=='x25519' else {'x':format(key['x'],'x')}
            generated.append({'file':path.name,'sha256':record['sha256'],'size':path.stat().st_size,'sessions':1,
                              'mode':record['mode'],'cipher_suite_id':record['cipher_suite_id'],
                              'recovery_secret_bundled':known,**packet_stats(path)})
            schedule = 'TLS 1.3' if args.tls13 else f'EMS={ems}'
            print(f'Generated {path.name}: {record["cipher"]}; {schedule}; independent endpoint secrets and plaintext matched',flush=True)
        for name,_,_,known in cases:
            shutil.copyfile(temp/(name+'.pcap'),FIXTURES/(name+'.pcap'))
            shutil.copyfile(temp/(name+'.expected.json'),FIXTURES/(name+'.expected.json'))
            if known:
                shutil.copyfile(temp/(name+'.pcap'),DEMO/(name+'.pcap'))
        registry_path.write_text(json.dumps(registry,indent=2)+'\n')
        manifest['captures'] = [record for record in manifest['captures'] if record['file'] not in names]+generated
        (FIXTURES/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    for filename,digest in preserved.items():
        if sha((FIXTURES/filename).read_bytes())!=digest:
            raise RuntimeError(f'Existing capture changed: {filename}')
    print(f'Complete: previous PCAPs preserved; ephemeral x fixtures only in {registry_path.name}; signing private key and OpenSSL keylogs deleted.',flush=True)


if __name__=='__main__':
    main()
