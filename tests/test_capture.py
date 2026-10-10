"""Synthetic packet/framing tests; golden PCAPs separately contain real OS traffic."""
from dataclasses import replace
import ipaddress
import json
from pathlib import Path
import struct

import dpkt
import pytest

from qsploit.models import Endpoint, QSploitError, TCPConnection
from qsploit.pcap import read_connections
from qsploit.tls import HRR_RANDOM, parse_tls, frame_records, clear_handshakes

FIXTURES = Path(__file__).parent / "fixtures"


def packet(seq=100, data=b"", flags=dpkt.tcp.TH_ACK, reverse=False, ack=0, version=4):
    tcp = dpkt.tcp.TCP(sport=443 if reverse else 1234, dport=1234 if reverse else 443,
                        seq=seq % 2**32, ack=ack % 2**32, flags=flags, off=5, data=data)
    src, dst = ("10.0.0.2", "10.0.0.1") if reverse else ("10.0.0.1", "10.0.0.2")
    if version == 4:
        ip = dpkt.ip.IP(src=ipaddress.ip_address(src).packed, dst=ipaddress.ip_address(dst).packed,
                        p=6, ttl=64, data=tcp)
        ip.len = len(ip)
        return bytes(dpkt.ethernet.Ethernet(type=0x0800, data=ip))
    ip = dpkt.ip6.IP6(src=ipaddress.ip_address("::2" if reverse else "::1").packed,
                      dst=ipaddress.ip_address("::1" if reverse else "::2").packed,
                      nxt=6, plen=len(tcp), hlim=64, data=tcp)
    return bytes(dpkt.ethernet.Ethernet(type=0x86dd, data=ip))


def capture(packets, endian="<", nanosecond=False, link=1):
    magic = (b"\x4d\x3c\xb2\xa1" if nanosecond else b"\xd4\xc3\xb2\xa1")
    if endian == ">":
        magic = magic[::-1]
    result = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, link)
    for p in packets:
        result += struct.pack(endian + "IIII", 1, 0, len(p), len(p)) + p
    return result


def hs(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def rec(wire, kind=22):
    return bytes([kind]) + b"\x03\x03" + len(wire).to_bytes(2, "big") + wire


def exts(values):
    data = b"".join(k.to_bytes(2, "big") + len(v).to_bytes(2, "big") + v for k, v in values)
    return len(data).to_bytes(2, "big") + data


def hellos(suite=0x1301, group=29, psk=False, hrr=False, ems=False, client_ext=None, server_ext=None, session_id=b""):
    ce = [(43, b"\x02\x03\x04")] if suite == 0x1301 else []
    se = [(43, b"\x03\x04")] if suite == 0x1301 else []
    if suite == 0x1301 and group is not None:
        se += [(51, group.to_bytes(2, "big") + (b"" if hrr else b"\x00\x01a"))]
    if psk:
        se += [(41, b"\x00\x00")]
    if ems:
        ce += [(23, b"")]; se += [(23, b"")]
    ce = ce if client_ext is None else client_ext
    se = se if server_ext is None else server_ext
    sid = bytes([len(session_id)]) + session_id
    client = hs(1, b"\x03\x03" + b"C" * 32 + sid + b"\x00\x02" + suite.to_bytes(2, "big") + b"\x01\x00" + exts(ce))
    server = hs(2, b"\x03\x03" + (HRR_RANDOM if hrr else b"S" * 32) + sid + suite.to_bytes(2, "big") + b"\x00" + exts(se))
    return client, server


def conn(a, b):
    return TCPConnection("test", Endpoint("127.0.0.1", 5555), Endpoint("127.0.0.1", 443), a, b, False, False, (), ())


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nano", [False, True])
def test_classic_pcap_magic_variants(endian, nano):
    result = read_connections(capture([packet(data=b"hello")], endian, nano))
    assert result.packets_seen == 1
    assert result.connections[0].a_to_b == b"hello"


def test_reordering_retransmission_matching_overlap_and_wrap():
    frames = [packet(seq=0xfffffff9, flags=2), packet(seq=3, data=b"world"),
              packet(seq=0xfffffffa, data=b"hello----"), packet(seq=0xfffffffe, data=b"o----wo"),
              packet(seq=3, data=b"world")]
    result = read_connections(capture(frames)).connections[0]
    assert result.a_to_b == b"hello----world"
    assert not result.blockers


def test_missing_syn_out_of_order():
    result = read_connections(capture([packet(seq=105, data=b"world"), packet(seq=100, data=b"hello")])).connections[0]
    assert result.a_to_b == b"helloworld"
    assert not result.blockers
    assert "TCP_SYN_NOT_CAPTURED" in result.warnings


def test_conflict_and_gap_are_not_guessed():
    conflict = read_connections(capture([packet(data=b"hello"), packet(seq=102, data=b"XX")])).connections[0]
    assert "TCP_OVERLAP_CONFLICT" in conflict.blockers
    gap = read_connections(capture([packet(data=b"hello"), packet(seq=106, data=b"world")])).connections[0]
    assert gap.a_to_b == b"hello"
    assert "TCP_GAP" in gap.blockers


def test_ack_proves_missing_suffix_and_fin_proves_gap():
    result = read_connections(capture([packet(seq=99, flags=2), packet(seq=100, data=b"hello"), packet(reverse=True, ack=109)])).connections[0]
    assert "TCP_GAP" in result.blockers
    result = read_connections(capture([packet(data=b"hello"), packet(seq=106, flags=1)])).connections[0]
    assert "TCP_GAP" in result.blockers


def test_reused_connections_distinct():
    result = read_connections(capture([packet(seq=99, flags=2), packet(seq=100, data=b"old"),
                                       packet(seq=900, flags=2), packet(seq=901, data=b"new")]))
    assert [c.a_to_b for c in result.connections] == [b"old", b"new"]
    assert len({c.id for c in result.connections}) == 2


def test_ipv6_vlan_and_bsd_loopback():
    assert read_connections(capture([packet(data=b"v6", version=6)])).connections[0].a_to_b == b"v6"
    ethernet = packet(data=b"vlan")
    vlan = ethernet[:12] + b"\x81\x00\x00\x01" + ethernet[12:]
    assert read_connections(capture([vlan])).connections[0].a_to_b == b"vlan"
    for endian in ("little", "big"):
        assert read_connections(capture([(2).to_bytes(4, endian) + ethernet[14:]], link=0)).connections[0].a_to_b == b"vlan"


@pytest.mark.parametrize("data,code", [(b"no", "INVALID_PCAP"), (b"\x0a\x0d\x0d\x0a", "PCAPNG_UNSUPPORTED"), (capture([], link=113), "UNSUPPORTED_LINKTYPE")])
def test_invalid_containers(data, code):
    with pytest.raises(QSploitError, match=".") as error:
        read_connections(data)
    assert error.value.code == code


def test_malformed_packet_lengths_and_fragments():
    with pytest.raises(QSploitError):
        read_connections(capture([packet()])[:-1])
    frame = bytearray(packet(data=b"fragment")); frame[20:22] = b"\x20\x00"
    result = read_connections(capture([bytes(frame), packet(data=b"other")]))
    assert "IP_FRAGMENT_UNSUPPORTED" in result.warnings
    assert "IP_FRAGMENT_UNSUPPORTED" in result.connections[0].blockers


def test_tls_record_and_handshake_fragmentation():
    ch, sh = hellos()
    records = frame_records(rec(ch[:7]) + rec(ch[7:] + hs(16, b"key")), "c2s")
    messages = clear_handshakes(records)
    assert [m.wire for m in messages] == [ch, hs(16, b"key")]
    session = parse_tls(conn(rec(ch[:7]) + rec(ch[7:]), rec(sh)))
    assert session.tls_version == 0x0304 and session.kex == "ecdhe"
    with pytest.raises(QSploitError):
        frame_records(rec(ch)[:-1], "c2s")
    with pytest.raises(QSploitError):
        clear_handshakes(frame_records(rec(ch[:-1]), "c2s"))


@pytest.mark.parametrize("group,psk,kind", [(29, False, "ecdhe"), (256, False, "dhe"), (29, True, "psk_ecdhe"), (256, True, "psk_dhe"), (None, True, "psk"), (4588, False, "hybrid_pq"), (513, False, "pq"), (65000, False, "unknown")])
def test_selected_tls13_groups(group, psk, kind):
    ch, sh = hellos(group=group, psk=psk)
    session = parse_tls(conn(rec(ch), rec(sh)))
    assert session.tls_version == 0x0304
    assert session.selected_group == group
    assert session.kex == kind
    assert session.psk_selected is psk
    assert session.authentication is None


def test_hrr_is_not_final_negotiation():
    ch, sh = hellos(group=23, hrr=True)
    session = parse_tls(conn(rec(ch), rec(sh)))
    assert session.selected_group is None and session.kex == "unknown"
    assert "INCOMPLETE_HANDSHAKE" in session.blockers
    _, final = hellos(group=29)
    session = parse_tls(conn(rec(ch) + rec(ch), rec(sh) + rec(final)))
    assert session.selected_group == 29


def test_ecdhe_rsa_not_rsa_transport_and_offered_ems_not_selected():
    ch, sh = hellos(suite=0xc02f, client_ext=[(23, b"")], server_ext=[])
    session = parse_tls(conn(rec(ch), rec(sh) + rec(hs(12, b"\x03\x00\x1d\x01a"))))
    assert session.kex == "ecdhe" and session.authentication == "RSA"
    assert session.rsa is None and session.selected_group == 29 and session.ems is False


def test_selected_ems_without_offer_and_duplicate_extensions_fail():
    ch, sh = hellos(suite=0x009c, client_ext=[], server_ext=[(23, b"")])
    assert "INVALID_TLS" in parse_tls(conn(rec(ch), rec(sh))).blockers
    ch, sh = hellos(client_ext=[(43, b"\x02\x03\x04"), (43, b"\x02\x03\x04")])
    assert "INVALID_TLS" in parse_tls(conn(rec(ch), rec(sh))).blockers


def test_tls12_resumption_is_explicit():
    ch, sh = hellos(suite=0x009c, session_id=b"same")
    session = parse_tls(conn(rec(ch), rec(sh) + rec(b"\x01", 20)))
    assert session.resumed
    assert "RESUMPTION_UNSUPPORTED" in session.blockers


def test_ordinary_tcp_visible():
    assert parse_tls(conn(b"GET / HTTP/1.1\r\n", b"HTTP/1.1 200 OK\r\n")).protocol == "tcp"


def test_real_mixed_capture_classification():
    parsed = [parse_tls(c) for c in read_connections((FIXTURES / "mixed-discovery.pcap").read_bytes()).connections]
    assert any(s.kex == "rsa_transport" and s.rsa for s in parsed)
    assert any(s.kex == "ecdhe" and s.tls_version == 0x0303 and s.authentication == "RSA" for s in parsed)
    assert any(s.kex == "ecdhe" and s.tls_version == 0x0304 and s.selected_group == 29 for s in parsed)
    assert any(s.protocol == "tcp" for s in parsed)


def test_hrr_with_compatibility_ccs_and_second_client_hello():
    ch, retry = hellos(group=23, hrr=True)
    _, selected = hellos(group=29)
    session = parse_tls(conn(rec(ch) + rec(b"\x01", 20) + rec(ch), rec(retry) + rec(b"\x01", 20) + rec(selected)))
    assert session.tls_version == 0x0304
    assert session.selected_group == 29
    assert session.kex == "ecdhe"
    assert "INCOMPLETE_HANDSHAKE" not in session.blockers


def test_truncated_encrypted_suffix_keeps_negotiation_metadata():
    analysis = read_connections((FIXTURES / "tls12-rsa-ems.pcap").read_bytes())
    original = analysis.connections[0]
    session = parse_tls(replace(original, b_to_a=original.b_to_a[:-1]))
    assert session.kex == "rsa_transport"
    assert session.cipher_suite == 0x009c
    assert "INCOMPLETE_HANDSHAKE" in session.blockers


def test_late_syn_does_not_split_first_generation():
    result = read_connections(capture([packet(seq=100, data=b"hello"), packet(seq=99, flags=2)]))
    assert len(result.connections) == 1
    assert result.connections[0].a_to_b == b"hello"
    assert not result.connections[0].blockers


@pytest.mark.parametrize("vector", json.loads((FIXTURES / "negotiation-vectors.json").read_text())["vectors"], ids=lambda v: v["name"])
def test_independently_encoded_negotiation_vectors(vector):
    session = parse_tls(conn(bytes.fromhex(vector["c2s_hex"]), bytes.fromhex(vector["s2c_hex"])))
    for field, expected in vector["expected"].items():
        if field == "blockers_contains":
            assert all(code in session.blockers for code in expected)
        else:
            assert getattr(session, field) == expected


def test_capture_limits_enforced_during_decode(monkeypatch):
    import qsploit.pcap as pcap_module
    monkeypatch.setattr(pcap_module, "MAX_PACKETS", 1)
    with pytest.raises(QSploitError) as exc:
        read_connections(capture([packet(), packet()]))
    assert exc.value.code == "RESOURCE_LIMIT"
    monkeypatch.setattr(pcap_module, "MAX_PACKETS", 100)
    monkeypatch.setattr(pcap_module, "MAX_STREAM_BYTES", 4)
    with pytest.raises(QSploitError) as exc:
        read_connections(capture([packet(data=b"hello")]))
    assert exc.value.code == "RESOURCE_LIMIT"


def test_missing_packet_real_capture_blocks_recovery():
    raw = (FIXTURES / "tls12-rsa-ems.pcap").read_bytes()
    endianness = "<" if raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    pos, frames = 24, []
    while pos < len(raw):
        size = struct.unpack_from(endianness + "I", raw, pos + 8)[0]
        frames.append(raw[pos:pos + 16 + size]); pos += 16 + size
    # Remove an interior full payload packet, preserving subsequent ACKs/data.
    remove = next(i for i, block in enumerate(frames) if len(block) > 8000)
    altered = raw[:24] + b"".join(block for i, block in enumerate(frames) if i != remove)
    result = read_connections(altered)
    assert "TCP_GAP" in result.connections[0].blockers
    assert "TCP_GAP" in parse_tls(result.connections[0]).blockers


def test_reused_overlapping_sequence_windows_are_ambiguous():
    result = read_connections(capture([packet(seq=99, flags=2), packet(seq=100, data=b"old"),
                                       packet(seq=102, flags=2), packet(seq=103, data=b"new")]))
    assert len(result.connections) == 2
    assert all("AMBIGUOUS_CONNECTION" in c.blockers for c in result.connections)


def test_retransmitted_syn_same_isn_stays_in_one_attempt():
    result = read_connections(capture([packet(seq=99, flags=2), packet(seq=100, data=b"old"), packet(seq=99, flags=2)]))
    assert len(result.connections) == 1 and not result.connections[0].blockers


def test_mutated_and_truncated_real_inputs_fail_with_domain_errors_only():
    import random
    rng = random.Random(15)
    raw = (FIXTURES / "tls12-rsa-ems.pcap").read_bytes()
    original = read_connections(raw).connections[0]
    for _ in range(200):
        data = bytearray(raw)
        if rng.randrange(2):
            del data[rng.randrange(len(data)):]
        else:
            data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        try:
            read_connections(bytes(data))
        except QSploitError:
            pass
        a, b = bytearray(original.a_to_b), bytearray(original.b_to_a)
        target = a if rng.randrange(2) else b
        if rng.randrange(2):
            del target[rng.randrange(len(target)):]
        else:
            target[rng.randrange(len(target))] ^= 1 << rng.randrange(8)
        session = parse_tls(replace(original, a_to_b=bytes(a), b_to_a=bytes(b)))
        assert session.protocol == "tls" or session.protocol == "tcp"
