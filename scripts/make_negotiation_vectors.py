#!/usr/bin/env python3
"""Generate explicitly synthetic TLS hello classification vectors, not PCAPs.

No QSploit code is imported. Layout follows RFC 5246 §7.4.1 and RFC 8446 §4.
Key share/binder bytes are placeholders: these vectors cannot establish TLS.
"""
import json
from pathlib import Path

DESTINATION = Path(__file__).resolve().parents[1] / 'tests/fixtures/negotiation-vectors.json'
HRR = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')


def u16(value):
    return value.to_bytes(2,'big')


def extension(kind, value):
    return u16(kind)+u16(len(value))+value


def record(kind, body):
    return bytes([kind])+b'\x03\x03'+u16(len(body))+body


def handshake(kind, body):
    return bytes([kind])+len(body).to_bytes(3,'big')+body


def client(groups=(29,), suite=0x1301, psk=False, session=b''):
    ext = b''
    if suite == 0x1301:
        ext += extension(43,b'\x02\x03\x04')
        offered = b''.join(u16(g) for g in groups)
        if offered:
            ext += extension(10,u16(len(offered))+offered)
            shares = b''.join(u16(g)+u16(32)+b'C'*32 for g in groups)
            ext += extension(51,u16(len(shares))+shares)
        if psk:
            ext += extension(45,b'\x01\x01')
            identity = b'fixture-identity'
            identity_list = u16(len(identity))+identity+b'\x00'*4
            binder = b'\x20'+b'B'*32
            ext += extension(41,u16(len(identity_list))+identity_list+u16(len(binder))+binder)
    body = b'\x03\x03'+b'R'*32+bytes([len(session)])+session+u16(2)+u16(suite)+b'\x01\x00'+u16(len(ext))+ext
    return record(22,handshake(1,body))


def server(group=29,suite=0x1301,psk=False,hrr=False,session=b''):
    ext = b''
    if suite == 0x1301:
        ext += extension(43,b'\x03\x04')
        if group is not None:
            ext += extension(51,u16(group)+(b'' if hrr else u16(32)+b'S'*32))
        if psk:
            ext += extension(41,b'\x00\x00')
    body = b'\x03\x03'+(HRR if hrr else b'Q'*32)+bytes([len(session)])+session+u16(suite)+b'\x00'+u16(len(ext))+ext
    return record(22,handshake(2,body))


def main():
    vectors = []
    for name,group,psk,kex in [('x25519',29,False,'ecdhe'),('ffdhe2048',256,False,'dhe'),('selected-hybrid',4588,False,'hybrid_pq'),('selected-pq',513,False,'pq'),('selected-unknown',65000,False,'unknown'),('selected-psk-ecdhe',29,True,'psk_ecdhe'),('selected-psk-dhe',256,True,'psk_dhe'),('selected-psk-only',None,True,'psk')]:
        vectors.append({'name':name,'c2s_hex':client(() if group is None else (group,),psk=psk).hex(),'s2c_hex':server(group,psk=psk).hex(),'expected':{'tls_version':772,'kex':kex,'selected_group':group,'psk_selected':psk,'resumed':False}})
    vectors += [
        {'name':'offered-pq-selected-classical','c2s_hex':client((4588,29)).hex(),'s2c_hex':server(29).hex(),'expected':{'tls_version':772,'kex':'ecdhe','selected_group':29,'psk_selected':False}},
        {'name':'hrr-only-no-final-selection','c2s_hex':client((29,23)).hex(),'s2c_hex':server(23,hrr=True).hex(),'expected':{'tls_version':None,'kex':'unknown','selected_group':None,'blockers_contains':['INCOMPLETE_HANDSHAKE']}},
        {'name':'hrr-followed-by-selected-p256','c2s_hex':(client((29,23))+client((23,))).hex(),'s2c_hex':(server(23,hrr=True)+server(23)).hex(),'expected':{'tls_version':772,'kex':'ecdhe','selected_group':23}},
        {'name':'tls12-abbreviated-resumption','c2s_hex':client(suite=0x009c,session=b'resumed').hex(),'s2c_hex':(server(suite=0x009c,session=b'resumed')+record(20,b'\x01')).hex(),'expected':{'tls_version':771,'resumed':True,'blockers_contains':['RESUMPTION_UNSUPPORTED']}},
    ]
    payload = {'provenance':'Explicitly synthetic hello-only classification vectors, independently encoded without QSploit parser imports. Not captured traffic, not cryptographic interoperability evidence. Key shares/binders are dummy bytes.','sources':['https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1','https://www.rfc-editor.org/rfc/rfc8446#section-4','https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8'],'vectors':vectors}
    DESTINATION.write_text(json.dumps(payload,indent=2)+'\n')


if __name__ == '__main__':
    main()
