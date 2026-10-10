"""HTTP and inert HTML tests, including real independently recorded endpoint bytes."""
from __future__ import annotations

import base64
import gzip
from html.parser import HTMLParser
import json
from pathlib import Path

import pytest

from qsploit.http1 import parse_http, text_body
from qsploit.models import ApplicationStreams, QSploitError
from qsploit.preview import PREVIEW_CSP, preview_document, response_fields, sanitize_html

FIXTURES = Path(__file__).parent / 'fixtures'


def streams(c2s: bytes, s2c: bytes, closed: bool = True) -> ApplicationStreams:
    return ApplicationStreams(c2s, s2c, True, True, 2, closed, closed, ())


def response(body: bytes, extra: bytes = b'') -> bytes:
    return b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n' + extra + b'\r\n' + body


def get(path: bytes = b'/') -> bytes:
    return b'GET ' + path + b' HTTP/1.1\r\nHost: test\r\n\r\n'


@pytest.mark.parametrize('name', ['tls12-rsa-ems', 'tls12-rsa-noems'])
def test_real_endpoint_http_bytes_exact(name):
    expected = json.loads((FIXTURES / f'{name}.expected.json').read_text())
    exchanges = parse_http(streams(base64.b64decode(expected['c2s_base64']), base64.b64decode(expected['s2c_base64'])))
    assert len(exchanges) == 2
    for actual, oracle in zip(exchanges, expected['exchanges']):
        assert actual.summary.complete
        assert actual.view.request.raw_b64 == oracle['request_base64']
        assert actual.view.response.raw_b64 == oracle['response_base64']
    assert exchanges[0].view.query_parameters == [('name','Cooper'), ('tag','a'), ('tag','b'), ('empty','')]
    assert ('account_id', '42') in exchanges[0].view.response_form_fields
    assert exchanges[1].view.form_parameters == [('note','hello world'), ('token','demo-only')]
    assert exchanges[1].view.response.decoded_body_b64 == expected['json_body_base64']
    assert ('X-Fixture-Trailer', 'complete') in exchanges[1].view.response.trailers


def test_pipelined_head_informational_and_no_body_responses():
    requests = b'HEAD /head HTTP/1.1\r\nHost: test\r\n\r\n' + get(b'/empty') + get(b'/cached') + get(b'/last')
    responses = (b'HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 900\r\n\r\n'
        b'HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 304 Not Modified\r\nContent-Length: 500\r\n\r\n' + response(b'last'))
    exchanges = parse_http(streams(requests, responses))
    assert [e.summary.status for e in exchanges] == [200,204,304,200]
    assert exchanges[0].view.informational_statuses == [103]
    assert all(e.summary.complete for e in exchanges)
    assert all(base64.b64decode(e.view.response.body_b64) == b'' for e in exchanges[:3])
    assert base64.b64decode(exchanges[-1].view.response.body_b64) == b'last'


def test_chunked_raw_preserves_chunk_extensions_and_duplicate_headers():
    wire = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: one\r\nX-A: two\r\n\r\n3;foo=bar\r\nabc\r\n2\r\nde\r\n0\r\nX-End: ok\r\n\r\n'
    exchange = parse_http(streams(get(),wire))[0]
    assert base64.b64decode(exchange.view.response.raw_b64) == wire
    assert base64.b64decode(exchange.view.response.body_b64) == b'abcde'
    assert exchange.view.response.headers[-2:] == [('X-A','one'),('X-A','two')]
    assert exchange.view.response.trailers == [('X-End','ok')]


@pytest.mark.parametrize('closed', [False,True])
def test_close_delimited_body_requires_authenticated_close_notify(closed):
    exchange = parse_http(streams(get(), b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello',closed))[0]
    assert exchange.summary.complete is closed
    assert base64.b64decode(exchange.view.response.body_b64) == b'hello'
    assert bool(exchange.view.response.warnings) is not closed


def test_partial_response_and_missing_response_remain_incomplete():
    exchange = parse_http(streams(get(), b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\npart',False))[0]
    assert not exchange.summary.complete
    assert not exchange.view.response.complete
    missing = parse_http(streams(get(), b'',False))[0]
    assert missing.summary.status is None
    assert missing.view.response is None
    assert not missing.summary.complete


@pytest.mark.parametrize('encoding,body,code', [(b'br',b'bytes','CONTENT_ENCODING_UNSUPPORTED'),(b'gzip',b'not gzip','CONTENT_DECODE_FAILED'),(b'gzip',gzip.compress(b'first')+gzip.compress(b'second'),'CONTENT_DECODE_FAILED')])
def test_unsupported_or_bad_content_encoding_preserves_raw(encoding,body,code):
    wire = response(body, b'Content-Type: text/plain\r\nContent-Encoding: '+encoding+b'\r\n')
    msg = parse_http(streams(get(),wire))[0].view.response
    assert msg.decoded_body_b64 is None
    assert base64.b64decode(msg.body_b64) == body
    assert base64.b64decode(msg.raw_b64) == wire
    assert code in [w.code for w in msg.warnings]


def test_gzip_bomb_is_bounded(monkeypatch):
    monkeypatch.setattr('qsploit.http1.BODY_LIMIT',1024)
    with pytest.raises(QSploitError) as error:
        parse_http(streams(get(),response(gzip.compress(b'x'*10000),b'Content-Encoding: gzip\r\n')))
    assert error.value.code == 'RESOURCE_LIMIT'


@pytest.mark.parametrize('c2s,s2c,alpn',[(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n',b'',None),(get(),b'', 'h2')])
def test_http2_is_explicitly_unsupported(c2s,s2c,alpn):
    with pytest.raises(QSploitError) as error:
        parse_http(streams(c2s,s2c),alpn)
    assert error.value.code == 'HTTP2_UNSUPPORTED'


def test_header_and_parameter_limits():
    with pytest.raises(QSploitError) as error:
        parse_http(streams(get(b'/' + b'x'*70000),b''))
    assert error.value.code == 'RESOURCE_LIMIT'
    with pytest.raises(QSploitError) as error:
        parse_http(streams(get(b'/?'+b'a=1&'*2050),response(b'')))
    assert error.value.code == 'RESOURCE_LIMIT'


def test_invalid_text_charset_reports_replacement():
    msg = parse_http(streams(get(), response(b'\xffhello',b'Content-Type: text/plain; charset=made-up\r\n')))[0].view.response
    assert text_body(msg) == '\ufffdhello'
    assert [w.code for w in msg.warnings] == ['TEXT_REPLACEMENT']


class Tags(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.tags = []
        self.feed(html)
    def handle_starttag(self, tag, attrs):
        self.tags.append((tag,dict(attrs)))


def test_unsafe_markup_has_no_active_tags_urls_handlers_or_css():
    hostile = '''<base href="https://bad.test"><meta http-equiv="refresh" content="0;url=https://bad.test"><link rel="stylesheet" href="https://bad.test/a.css">
<script>parent.pwned=1</script><style>@import 'https://bad.test';</style><iframe srcdoc="<script>alert(1)</script>"></iframe>
<object data="https://bad.test"><embed src="https://bad.test"></object><svg onload="alert(1)"><a href="https://bad.test">SVG</a></svg><math><mi>x</mi></math>
<form action="https://bad.test"><input name="secret" value="captured" formaction="https://bad.test" onfocus="alert(1)"><button type="submit">Send</button></form>
<a href="javascript:alert(1)" ping="https://bad.test" target="_top">Click</a><img src="https://bad.test" srcset="https://bad.test" onerror="alert(1)" alt="illustration">
<div style="background-color:url(https://bad.test);color:red" class="foo" id="bar">Visible</div><div style="color:blue;position:fixed;top:0">Allowed</div>'''
    clean = sanitize_html(hostile)
    parsed = Tags(clean)
    for tag, attrs in parsed.tags:
        assert tag not in {'script','style','iframe','object','embed','svg','math','form','base','meta','link'}
        assert not any(name.startswith('on') or name in {'href','src','srcset','srcdoc','action','formaction','ping','target','id','class'} for name in attrs)
        assert 'url' not in attrs.get('style','').lower()
        if tag in {'input','button','textarea','select'}:
            assert 'disabled' in attrs
        if tag == 'button':
            assert attrs['type'] == 'button'
    assert 'parent.pwned' not in clean
    assert 'https://' not in clean
    assert 'position:' not in clean
    assert 'color:blue' in clean.replace(' ','')


def test_text_preview_escapes_markup_and_csp_blocks_every_resource():
    document = preview_document('<script>bad()</script>', 'text/plain')
    assert '&lt;script&gt;bad()&lt;/script&gt;' in document
    assert "default-src 'none'" in PREVIEW_CSP
    assert "form-action 'none'" in PREVIEW_CSP
    assert PREVIEW_CSP.startswith('sandbox;')


def test_hidden_and_textarea_select_inventory():
    html = '<input type="hidden" name="account_id" value="42"><textarea name="note">hello &amp; world</textarea><select name="plan"><option value="free">Free</option><option value="pro" selected>Pro</option></select>'
    assert response_fields(html) == [('account_id','42'),('note','hello & world'),('plan','pro')]
    assert 'type="hidden"' in sanitize_html(html)


def test_preview_size_limits(monkeypatch):
    monkeypatch.setattr('qsploit.preview.PREVIEW_LIMIT',100)
    with pytest.raises(QSploitError) as error:
        sanitize_html('x'*101)
    assert error.value.code == 'RESOURCE_LIMIT'


@pytest.mark.parametrize('request_bytes,headers,status', [
    (b'GET / HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n', b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n',101),
    (b'CONNECT test:443 HTTP/1.1\r\nHost: test\r\n\r\n', b'HTTP/1.1 200 Connection Established\r\n\r\n',200),
])
def test_protocol_switch_preserves_headers_and_stops_before_tunnel(request_bytes,headers,status):
    exchange = parse_http(streams(request_bytes,headers+b'opaque-tunnel-bytes'))[0]
    assert exchange.summary.status == status
    assert exchange.summary.complete
    assert base64.b64decode(exchange.view.response.raw_b64) == headers
    assert base64.b64decode(exchange.view.response.body_b64) == b''
    assert 'HTTP_UPGRADE_UNSUPPORTED' in [w.code for w in exchange.view.response.warnings]


def test_malformed_target_has_domain_error_not_unhandled_url_exception():
    with pytest.raises(QSploitError) as error:
        parse_http(streams(get(b'http://[invalid'),response(b'')))
    assert error.value.code == 'HTTP_PARSE_FAILED'


def test_early_response_to_incomplete_request_is_retained():
    request = b'POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 99\r\n\r\npart'
    wire = b'HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n'
    exchange = parse_http(streams(request,wire,False))[0]
    assert exchange.summary.status == 413
    assert not exchange.summary.complete
    assert exchange.view.response.complete
    assert base64.b64decode(exchange.view.request.raw_b64) == request


@pytest.mark.parametrize('markup',[
    '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=https://bad.test onerror=alert(1)>">',
    '<svg><style><a id="</style><img src=https://bad.test onerror=alert(1)>">',
    '<noscript><p title="</noscript><img src=https://bad.test onerror=alert(1)>">',
    '<input type=image src=https://bad.test formaction=https://bad.test><button formaction=https://bad.test>Go</button>',
    '<a href="&#106;avascript:alert(1)">x</a><div style="background-color:u\\72l(https://bad.test)">x</div>',
    '<video poster=https://bad.test><source src=https://bad.test></video><audio src=https://bad.test></audio>',
])
def test_malformed_and_obfuscated_html_retains_no_fetch_or_execution_surface(markup):
    parsed = Tags(sanitize_html(markup))
    for tag,attrs in parsed.tags:
        assert tag not in {'svg','math','style','script','iframe','object','embed','source','video','audio'}
        assert not any(name.startswith('on') or name in {'src','href','srcset','poster','background','data','action','formaction','srcdoc'} for name in attrs)
        assert '\\' not in attrs.get('style','')


def test_field_inventory_does_not_silently_truncate():
    with pytest.raises(QSploitError) as error:
        response_fields('<input name="x" value="captured">'*2049)
    assert error.value.code == 'RESOURCE_LIMIT'
    markup = b'<input name="x" value="captured">'*2049
    msg = parse_http(streams(get(),response(markup,b'Content-Type: text/html\r\n')))[0].view.response
    assert 'PREVIEW_UNAVAILABLE' in [warning.code for warning in msg.warnings]
    assert base64.b64decode(msg.body_b64) == markup
