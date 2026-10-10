"""Combine genuine captured packets into a mixed-protocol demonstration.

This does not synthesize packets, TLS records, keys or application bytes. It
retains original packet bytes/timestamps and records the input provenance.
Run after protocol extensions have passed their individual acceptance tests.
"""
from __future__ import annotations
import hashlib
import io
import json
from pathlib import Path
import dpkt

ROOT = Path(__file__).resolve().parents[1]


def build():
    from qsploit.pcap import read_connections
    from qsploit.tls import parse_tls, problem_for
    from qsploit.quantum.engine import has_known_recovery
    from qsploit.models import QSploitError
    packets, sources = [], []
    linktype = None
    for path in sorted((ROOT/'tests/fixtures').glob('tls*.pcap')):
        oracle = path.with_suffix('.expected.json')
        if not oracle.exists():
            continue
        evidence = json.loads(oracle.read_text())
        if evidence.get('recovery_secret_bundled') is False:
            continue
        wire = path.read_bytes()
        sessions = [parse_tls(c) for c in read_connections(wire).connections]
        if len(sessions) != 1:
            continue
        try:
            public = problem_for(sessions[0])
        except QSploitError:
            continue
        if not has_known_recovery(public):
            continue
        capture = dpkt.pcap.Reader(io.BytesIO(wire))
        if linktype is None:
            linktype = capture.datalink()
        if linktype != capture.datalink():
            raise ValueError('Tour input link layers differ; conversion is intentionally not performed')
        packets.extend(capture)
        sources.append({'fixture':path.name,'sha256':hashlib.sha256(wire).hexdigest(),
                        'client':evidence['client'],'server':evidence['server'],
                        'cipher_suite_id':sessions[0].cipher_suite,
                        'tls_version':sessions[0].tls_version,'key_exchange':sessions[0].kex,
                        'selected_group':sessions[0].selected_group})
    if not sources:
        raise ValueError('No supported genuine fixtures found')
    output = io.BytesIO()
    writer = dpkt.pcap.Writer(output,linktype=linktype,snaplen=262144)
    for timestamp,wire in sorted(packets,key=lambda pair:pair[0]):
        writer.writepkt(wire,timestamp)
    result = output.getvalue()
    destination = ROOT/'qsploit/demo/protocol-tour.pcap'
    destination.write_bytes(result)
    report = {'description':'Original genuine endpoint packets merged by capture timestamp; no packet or TLS bytes changed.',
              'capture_sha256':hashlib.sha256(result).hexdigest(),'sessions':sources,'packets':len(packets)}
    (ROOT/'tests/fixtures/protocol-tour.sources.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'Built {len(sources)} genuine sessions / {len(packets)} packets into {destination.name}')


if __name__ == '__main__':
    build()
