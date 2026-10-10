"""Bounded classic-PCAP decoding and conservative TCP stream reconstruction.

Sequence/flight ordering is not inferred from capture timestamps. Ambiguous or
missing bytes stay blockers; only the maximal contiguous prefix is retained.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import struct

import dpkt

from .models import CaptureAnalysis, Endpoint, QSploitError, TCPConnection

MAX_CAPTURE_BYTES = 32 * 1024 * 1024
MAX_PACKETS = 200_000
MAX_CONNECTIONS = 512
MAX_STREAM_BYTES = 16 * 1024 * 1024
MAX_PAYLOAD_BYTES = 32 * 1024 * 1024


def _signed(value: int) -> int:
    return (value + (1 << 31)) % (1 << 32) - (1 << 31)


@dataclass
class _Stream:
    isn: int | None = None
    chunks: list[tuple[int, bytes]] = field(default_factory=list)
    fin: int | None = None
    acknowledgments: list[int] = field(default_factory=list)
    retained: int = 0

    def assemble(self) -> tuple[bytes, list[str]]:
        issues: list[str] = []
        if self.isn is not None:
            anchor = (self.isn + 1) % (1 << 32)
        elif self.chunks:
            anchor = self.chunks[0][0]
        else:
            return b"", issues
        intervals = [(_signed(seq - anchor), data) for seq, data in self.chunks]
        origin = 0 if self.isn is not None else min((x[0] for x in intervals), default=0)
        intervals.sort(key=lambda x: x[0])
        merged = bytearray()
        for start, data in intervals:
            start -= origin
            if start < 0:
                issues.append("AMBIGUOUS_CONNECTION")
                continue
            if start + len(data) > MAX_STREAM_BYTES:
                raise QSploitError("RESOURCE_LIMIT", "A TCP stream exceeds the configured byte/span limit.")
            if start > len(merged):
                issues.append("TCP_GAP")
                # Keep checking the prefix, but never join bytes across a gap.
                continue
            overlap = min(len(data), len(merged) - start)
            if merged[start:start + overlap] != data[:overlap]:
                issues.append("TCP_OVERLAP_CONFLICT")
            merged.extend(data[overlap:])
        if self.fin is not None:
            end = _signed(self.fin - anchor) - origin
            if end != len(merged):
                issues.append("TCP_GAP" if end > len(merged) else "AMBIGUOUS_CONNECTION")
        for ack in self.acknowledgments:
            acknowledged = _signed(ack - anchor) - origin
            fin_consumed = 1 if self.fin is not None and acknowledged == len(merged) + 1 else 0
            if acknowledged > len(merged) + fin_consumed:
                issues.append("TCP_GAP")
        return bytes(merged), list(dict.fromkeys(issues))


@dataclass
class _Flow:
    id: str
    a: Endpoint
    b: Endpoint
    streams: tuple[_Stream, _Stream] = field(default_factory=lambda: (_Stream(), _Stream()))
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    reset: bool = False

    @property
    def closed(self) -> bool:
        return self.reset or all(s.fin is not None for s in self.streams)


def _network(frame: bytes, link: int) -> tuple[bytes, int]:
    if link in (0, 108):
        if len(frame) < 4:
            raise ValueError("short loopback frame")
        orders = ("big",) if link == 108 else ("little", "big")
        for order in orders:
            family = int.from_bytes(frame[:4], order)
            if family in (2, 10, 24, 28, 30):
                return frame[4:], 4 if family == 2 else 6
        return b"", 0
    if len(frame) < 14:
        raise ValueError("short Ethernet frame")
    kind = int.from_bytes(frame[12:14], "big")
    pos = 14
    for _ in range(4):
        if kind not in (0x8100, 0x88a8, 0x9100):
            break
        if len(frame) < pos + 4:
            raise ValueError("short VLAN frame")
        kind = int.from_bytes(frame[pos + 2:pos + 4], "big")
        pos += 4
    return frame[pos:], {0x0800: 4, 0x86dd: 6}.get(kind, 0)


def _tcp_packet(raw: bytes, version: int):
    """Return IP endpoints, TCP bytes, and fragment/truncation flags."""
    if not version:
        return None
    if version == 4:
        if len(raw) < 20 or raw[0] >> 4 != 4:
            raise ValueError("invalid IPv4 header")
        size = (raw[0] & 15) * 4
        length = int.from_bytes(raw[2:4], "big")
        if size < 20 or length < size or len(raw) < size:
            raise ValueError("invalid IPv4 lengths")
        src, dst = str(ipaddress.ip_address(raw[12:16])), str(ipaddress.ip_address(raw[16:20]))
        fragment = bool(int.from_bytes(raw[6:8], "big") & 0x3fff)
        first = (int.from_bytes(raw[6:8], "big") & 0x1fff) == 0
        if raw[9] != 6:
            return None
        return src, dst, raw[size:min(length, len(raw))], fragment, first, len(raw) < length
    if len(raw) < 40 or raw[0] >> 4 != 6:
        raise ValueError("invalid IPv6 header")
    length = 40 + int.from_bytes(raw[4:6], "big")
    if length == 40:
        raise ValueError("IPv6 jumbograms unsupported")
    src, dst = str(ipaddress.ip_address(raw[8:24])), str(ipaddress.ip_address(raw[24:40]))
    nxt, pos, fragment = raw[6], 40, False
    for _ in range(16):
        if nxt == 6:
            return src, dst, raw[pos:min(length, len(raw))], fragment, True, len(raw) < length
        if nxt == 44:
            # Atomic fragments also require explicit unsupported handling.
            return src, dst, b"", True, False, len(raw) < length
        if nxt not in (0, 43, 60, 51):
            return None
        if pos + 2 > min(length, len(raw)):
            raise ValueError("truncated IPv6 extension")
        extent = (raw[pos + 1] + 2) * 4 if nxt == 51 else (raw[pos + 1] + 1) * 8
        nxt = raw[pos]
        pos += extent
        if pos > min(length, len(raw)):
            raise ValueError("truncated IPv6 extension")
    raise ValueError("too many IPv6 extension headers")


def read_connections(pcap: bytes) -> CaptureAnalysis:
    if len(pcap) > MAX_CAPTURE_BYTES:
        raise QSploitError("RESOURCE_LIMIT", "The capture exceeds the 32 MiB upload limit.")
    if pcap[:4] == b"\x0a\x0d\x0d\x0a":
        raise QSploitError("PCAPNG_UNSUPPORTED", "PCAPNG is not supported; export classic PCAP before uploading.")
    variants = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    endian = variants.get(pcap[:4])
    if not endian or len(pcap) < 24:
        raise QSploitError("INVALID_PCAP", "A complete classic PCAP header is required.")
    major, minor, _, _, snaplen, link_raw = struct.unpack_from(endian + "HHIIII", pcap, 4)
    if (major, minor) != (2, 4) or not 0 < snaplen <= MAX_CAPTURE_BYTES:
        raise QSploitError("INVALID_PCAP", "Unsupported PCAP version or snapshot length.")
    link = link_raw & 0xffff
    if link not in (0, 1, 108):
        raise QSploitError("UNSUPPORTED_LINKTYPE", f"PCAP link type {link} is unsupported; use Ethernet or BSD loopback.")
    flows: list[_Flow] = []
    active: dict[tuple, _Flow] = {}
    history: dict[tuple, list[_Flow]] = {}
    fragments: set[frozenset[str]] = set()
    warnings: list[str] = []
    pos, packets, retained = 24, 0, 0
    while pos < len(pcap):
        if pos + 16 > len(pcap):
            raise QSploitError("INVALID_PCAP", "The final PCAP packet header is truncated.")
        _, _, caplen, original = struct.unpack_from(endian + "IIII", pcap, pos)
        pos += 16
        if caplen > snaplen or caplen > original or pos + caplen > len(pcap):
            raise QSploitError("INVALID_PCAP", "A PCAP packet has invalid or truncated lengths.")
        frame = pcap[pos:pos + caplen]
        pos += caplen
        packets += 1
        if packets > MAX_PACKETS:
            raise QSploitError("RESOURCE_LIMIT", "The capture exceeds the packet limit.")
        try:
            raw, version = _network(frame, link)
            decoded = _tcp_packet(raw, version)
            if decoded is None:
                warnings.append("NON_TCP_TRAFFIC_IGNORED" if version else "NON_IP_TRAFFIC_IGNORED")
                continue
            src, dst, segment, fragment, first, truncated = decoded
            if fragment:
                fragments.add(frozenset((src, dst)))
                warnings.append("IP_FRAGMENT_UNSUPPORTED")
                continue
            if len(segment) < 20:
                raise ValueError("truncated TCP header")
            tcp = dpkt.tcp.TCP(segment)
            if tcp.off < 5 or tcp.off * 4 > len(segment):
                raise ValueError("invalid TCP data offset")
            payload = segment[tcp.off * 4:]
        except (ValueError, dpkt.UnpackError, struct.error):
            # Decoding errors can hide missing suffixes: flag affected capture.
            warnings.append("MALFORMED_PACKET")
            continue
        endpoints = (Endpoint(src, tcp.sport), Endpoint(dst, tcp.dport))
        key = (version, tuple(sorted(((src, tcp.sport), (dst, tcp.dport)))))
        flow = active.get(key)
        syn = bool(tcp.flags & dpkt.tcp.TH_SYN)
        initiating_syn = syn and not tcp.flags & dpkt.tcp.TH_ACK
        new_generation = flow is None
        if flow and initiating_syn:
            direction = 0 if endpoints[0] == flow.a else 1
            known_isn = flow.streams[direction].isn
            if known_isn is not None and known_isn != tcp.seq:
                new_generation = True
                if not flow.closed:
                    flow.warnings.append("CONNECTION_REUSED_BEFORE_CLOSE")
        if new_generation:
            if len(flows) >= MAX_CONNECTIONS:
                raise QSploitError("RESOURCE_LIMIT", "The capture exceeds the TCP connection limit.")
            flow = _Flow(f"session-{len(flows) + 1}", *endpoints)
            if initiating_syn:
                for prior in history.get(key, ()):
                    prior_direction = 0 if endpoints[0] == prior.a else 1
                    prior_isn = prior.streams[prior_direction].isn
                    if prior_isn is not None and abs(_signed(tcp.seq - prior_isn)) <= MAX_STREAM_BYTES:
                        # Overlapping bounded sequence windows cannot reliably
                        # distinguish late packets from different generations.
                        prior.blockers.append("AMBIGUOUS_CONNECTION")
                        flow.blockers.append("AMBIGUOUS_CONNECTION")
            active[key] = flow
            history.setdefault(key, []).append(flow)
            flows.append(flow)
        assert flow is not None
        direction = 0 if endpoints[0] == flow.a else 1
        stream, reverse = flow.streams[direction], flow.streams[1 - direction]
        if syn:
            if stream.isn is not None and stream.isn != tcp.seq:
                flow.blockers.append("AMBIGUOUS_CONNECTION")
            stream.isn = tcp.seq
        data_seq = (tcp.seq + int(syn)) % (1 << 32)
        if payload:
            stream.chunks.append((data_seq, payload))
            stream.retained += len(payload)
            retained += len(payload)
            if stream.retained > MAX_STREAM_BYTES or retained > MAX_PAYLOAD_BYTES:
                raise QSploitError("RESOURCE_LIMIT", "Retained TCP payload exceeds the configured limit.")
        if tcp.flags & dpkt.tcp.TH_FIN:
            stream.fin = (data_seq + len(payload)) % (1 << 32)
        if tcp.flags & dpkt.tcp.TH_ACK:
            reverse.acknowledgments.append(tcp.ack)
        if tcp.flags & dpkt.tcp.TH_RST:
            flow.reset = True
            flow.warnings.append("TCP_RESET")
        if truncated:
            flow.blockers.append("TCP_GAP")
    result: list[TCPConnection] = []
    for flow in flows:
        a_bytes, a_issues = flow.streams[0].assemble()
        b_bytes, b_issues = flow.streams[1].assemble()
        blockers = flow.blockers + a_issues + b_issues
        if frozenset((flow.a.ip, flow.b.ip)) in fragments:
            blockers.append("IP_FRAGMENT_UNSUPPORTED")
        if "MALFORMED_PACKET" in warnings:
            # Cannot safely attribute an undecodable packet to a connection.
            blockers.append("MALFORMED_PACKET")
        flow_warnings = flow.warnings[:]
        if any(s.isn is None for s in flow.streams):
            flow_warnings.append("TCP_SYN_NOT_CAPTURED")
        result.append(TCPConnection(flow.id, flow.a, flow.b, a_bytes, b_bytes,
                                    flow.streams[0].fin is not None, flow.streams[1].fin is not None,
                                    tuple(dict.fromkeys(blockers)), tuple(dict.fromkeys(flow_warnings))))
    return CaptureAnalysis(tuple(result), packets, tuple(dict.fromkeys(warnings)))
