"""HTTP/1.1 framing with h11; raw views always slice original TLS plaintext."""
from __future__ import annotations
import base64
from dataclasses import dataclass
from email.message import Message
from urllib.parse import parse_qsl, urlsplit
import zlib

import h11

from .models import ApplicationStreams, ExchangeView, ExchangeSummary, HTTPMessage, Issue, QSploitError
from .preview import response_fields

BODY_LIMIT = 8 * 1024 * 1024
HEADER_LIMIT = 65536


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def text_body(message: HTTPMessage) -> str:
    data = base64.b64decode(message.decoded_body_b64 if message.decoded_body_b64 is not None else message.body_b64)
    try:
        return data.decode(message.charset or "utf-8", errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def _message(raw, headers, body, trailers, complete):
    pairs = [(k.decode("latin1"), v.decode("latin1")) for k, v in headers]
    meta = Message()
    for k, v in pairs:
        meta[k] = v
    media = meta.get_content_type() if "content-type" in meta else None
    charset = meta.get_content_charset()
    warnings = []
    encoding = str(meta.get("content-encoding", "identity")).lower().strip()
    decoded = body
    if encoding == "gzip":
        try:
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            decoded = decoder.decompress(body, BODY_LIMIT + 1)
            if len(decoded) > BODY_LIMIT or decoder.unconsumed_tail:
                raise QSploitError("RESOURCE_LIMIT", "Decoded gzip body exceeds 8 MiB.")
            if not decoder.eof or decoder.unused_data:
                raise ValueError("Incomplete or multiple gzip members")
        except (zlib.error, ValueError):
            decoded = None
            warnings.append(Issue(code="CONTENT_DECODE_FAILED", message="Gzip data is incomplete or unsupported; the original bytes are preserved."))
    elif encoding not in ("", "identity"):
        decoded = None
        warnings.append(Issue(code="CONTENT_ENCODING_UNSUPPORTED", message=f"Content encoding {encoding[:40]} is not decoded; original bytes are preserved."))
    if not complete:
        warnings.append(Issue(code="HTTP_INCOMPLETE", message="The capture does not establish a complete HTTP message."))
    if decoded is not None and (media and (media.startswith("text/") or "json" in media or media == "application/x-www-form-urlencoded")):
        try:
            decoded.decode(charset or "utf-8", errors="strict")
        except (UnicodeError, LookupError):
            warnings.append(Issue(code="TEXT_REPLACEMENT", message="Readable view replaces invalid text or uses UTF-8 for an unknown charset. Raw bytes remain exact."))
    return HTTPMessage(raw_b64=b64(raw), headers=pairs, trailers=[(k.decode("latin1"),v.decode("latin1")) for k,v in trailers], body_b64=b64(body), decoded_body_b64=b64(decoded) if decoded is not None else None, media_type=media, charset=charset, complete=complete, warnings=warnings)


@dataclass(frozen=True)
class Exchange:
    summary: ExchangeSummary
    view: ExchangeView


def _pairs(value: str) -> list[tuple[str, str]]:
    try:
        return parse_qsl(value, keep_blank_values=True, max_num_fields=2048)
    except ValueError:
        raise QSploitError("RESOURCE_LIMIT", "Too many HTTP parameters.") from None


def parse_http(streams: ApplicationStreams, alpn: str | None = None) -> list[Exchange]:
    if alpn == "h2" or streams.c2s.startswith(b"PRI * HTTP/2.0"):
        raise QSploitError("HTTP2_UNSUPPORTED", "HTTP/2 decoding is not implemented. Authenticated application bytes remain available.")
    requests = h11.Connection(h11.SERVER, max_incomplete_event_size=HEADER_LIMIT)
    responses = h11.Connection(h11.CLIENT, max_incomplete_event_size=HEADER_LIMIT)
    # h11 treats b"" as EOF. Absence of captured bytes is not authenticated EOF.
    if streams.c2s:
        requests.receive_data(streams.c2s)
    if streams.s2c:
        responses.receive_data(streams.s2c)
    offsets = [0, 0]
    sources = [streams.c2s, streams.s2c]
    closed = [streams.client_close_notify, streams.server_close_notify]
    eof_sent = [False, False]

    def read_message(parser, mirror, side):
        start = offsets[side]
        header_end = sources[side].find(b"\r\n\r\n", start)
        if (header_end != -1 and header_end - start > HEADER_LIMIT) or (header_end == -1 and len(sources[side])-start > HEADER_LIMIT):
            raise QSploitError("RESOURCE_LIMIT", "HTTP headers exceed 64 KiB.")
        headers, trailers, data, infos = [], [], bytearray(), []
        first = None
        complete = False
        protocol_switch = False
        while True:
            event = parser.next_event()
            if event is h11.NEED_DATA:
                if closed[side] and not eof_sent[side]:
                    parser.receive_data(b"")
                    eof_sent[side] = True
                    continue
                break
            if event is h11.PAUSED or isinstance(event, h11.ConnectionClosed):
                if event is h11.PAUSED and (parser.our_state is h11.SWITCHED_PROTOCOL or parser.their_state is h11.SWITCHED_PROTOCOL):
                    complete = True
                    protocol_switch = True
                break
            if isinstance(event, h11.InformationalResponse):
                mirror.send(event)
                if event.status_code == 101:
                    first = event
                    headers = list(event.headers.raw_items())
                    complete = True
                    protocol_switch = True
                    break
                infos.append(event.status_code)
                continue
            if isinstance(event, (h11.Request, h11.Response)):
                first = event
                headers = list(event.headers.raw_items())
            elif isinstance(event, h11.Data):
                if len(data) + len(event.data) > BODY_LIMIT:
                    raise QSploitError("RESOURCE_LIMIT", "HTTP body exceeds 8 MiB.")
                data.extend(event.data)
            elif isinstance(event, h11.EndOfMessage):
                trailers = list(event.headers.raw_items())
                complete = True
            # Advance protocol state only. These reserialized bytes never enter Raw.
            mirror.send(event)
            if complete:
                break
        end = len(sources[side]) - len(parser.trailing_data[0])
        offsets[side] = end
        message = _message(sources[side][start:end], headers, bytes(data), trailers, complete)
        if protocol_switch:
            message.warnings.append(Issue(code="HTTP_UPGRADE_UNSUPPORTED", message="The protocol switched after these HTTP headers. Remaining authenticated bytes are available in the stream download."))
        return first, message, infos

    exchanges = []
    try:
        while offsets[0] < len(streams.c2s):
            req, request, _ = read_message(requests, responses, 0)
            if req is None:
                if not exchanges:
                    raise QSploitError("HTTP_PARSE_FAILED", "No complete HTTP request headers were captured; inspect authenticated bytes.")
                break
            res, response, infos = read_message(responses, requests, 1)
            if res is None:
                response = None
            method, target = req.method.decode("latin1"), req.target.decode("latin1")
            try:
                query = urlsplit(target).query
            except ValueError:
                raise QSploitError("HTTP_PARSE_FAILED", "The captured request target is malformed; authenticated bytes remain available.") from None
            forms = _pairs(text_body(request)) if request.media_type == "application/x-www-form-urlencoded" and request.decoded_body_b64 is not None else []
            fields = []
            if response and response.media_type == "text/html" and response.decoded_body_b64 is not None:
                try:
                    fields = response_fields(text_body(response))
                except QSploitError:
                    response.warnings.append(Issue(code="PREVIEW_UNAVAILABLE", message="HTML is too large for safe preview or form-field inventory."))
            index = len(exchanges)
            exchanges.append(Exchange(ExchangeSummary(index=index, method=method, target=target, status=res.status_code if res else None, response_media_type=response.media_type if response else None, complete=request.complete and bool(response and response.complete)), ExchangeView(index=index, request=request, response=response, informational_statuses=infos, query_parameters=_pairs(query), form_parameters=forms, response_form_fields=fields)))
            if not request.complete or not response or not response.complete:
                break
            if requests.our_state is not h11.DONE or requests.their_state is not h11.DONE:
                break
            requests.start_next_cycle()
            responses.start_next_cycle()
            if len(exchanges) >= 4096:
                raise QSploitError("RESOURCE_LIMIT", "Too many HTTP exchanges.")
    except h11.ProtocolError:
        raise QSploitError("HTTP_PARSE_FAILED", "HTTP framing is incomplete, malformed, or unsupported; authenticated bytes remain available.") from None
    return exchanges
