"""Captured HTML becomes an inert document, never a live site replay."""
from html import escape
from html.parser import HTMLParser
import re

import nh3

from .models import QSploitError

PREVIEW_LIMIT = 2 * 1024 * 1024
PREVIEW_CSP = "sandbox; default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
TAGS = set("a p div span section article header footer main h1 h2 h3 h4 h5 h6 br hr pre code blockquote strong em b i u s small sub sup ul ol li dl dt dd table caption thead tbody tfoot tr th td img label input textarea select option button".split())
STYLES = set("color background-color font-family font-size font-style font-weight text-align white-space margin padding border border-color border-width border-style width height max-width".split())
CONTROLS = {"input", "textarea", "select", "button"}


def _attribute(tag: str, name: str, value: str) -> str | None:
    if name == "style" and re.search(r"url|expression|@|\\", value, re.I):
        return None
    if tag == "input" and name == "type" and value.lower() not in {"text", "password", "hidden", "number", "email", "checkbox", "radio"}:
        return "text"
    return value


def sanitize_html(html: str) -> str:
    if len(html.encode("utf-8")) > PREVIEW_LIMIT:
        raise QSploitError("RESOURCE_LIMIT", "HTML preview exceeds the 2 MiB preview limit. Use Raw instead.")
    attributes = {"*": {"title", "lang", "dir", "style"}, "td": {"colspan", "rowspan"}, "th": {"colspan", "rowspan"}, "img": {"alt"}}
    for tag in CONTROLS | {"option"}:
        attributes[tag] = {"name", "value", "type", "checked", "selected", "placeholder"}
    return nh3.clean(html, tags=TAGS, attributes=attributes,
                     clean_content_tags={"script", "style", "iframe", "object", "embed", "svg", "math", "template"},
                     attribute_filter=_attribute, url_schemes=set(), link_rel=None,
                     strip_comments=True, filter_style_properties=STYLES,
                     set_tag_attribute_values={**{t: {"disabled": ""} for t in CONTROLS}, "button": {"disabled": "", "type": "button"}})


def preview_document(text: str, media_type: str | None) -> str:
    content = sanitize_html(text) if media_type == "text/html" else "<pre>" + escape(text) + "</pre>"
    if len(content.encode("utf-8")) > PREVIEW_LIMIT * 2:
        raise QSploitError("RESOURCE_LIMIT", "This response is too large to preview.")
    return '<!doctype html><html><head><meta charset="utf-8"><title>Captured response · inert preview</title><style>body{font:15px/1.6 system-ui,sans-serif;color:#1c2c40;padding:24px;overflow-wrap:anywhere}pre{white-space:pre-wrap}input,textarea,select,button{font:inherit}table{border-collapse:collapse}td,th{padding:6px 12px}img{max-width:100%}</style></head><body>' + content + "</body></html>"


class _Fields(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.fields: list[tuple[str, str]] = []
        self.textarea: tuple[str, list[str]] | None = None
        self.select: str | None = None
        self.option: tuple[str | None, list[str], bool] | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "input" and a.get("name"):
            self.fields.append((a["name"], a.get("value") or ""))
        elif tag == "textarea" and a.get("name"):
            self.textarea = (a["name"], [])
        elif tag == "select":
            self.select = a.get("name")
        elif tag == "option" and self.select:
            self.option = (a.get("value"), [], "selected" in a)

    def handle_data(self, data):
        if self.textarea:
            self.textarea[1].append(data)
        if self.option:
            self.option[1].append(data)

    def handle_endtag(self, tag):
        if tag == "textarea" and self.textarea:
            self.fields.append((self.textarea[0], "".join(self.textarea[1])))
            self.textarea = None
        elif tag == "option" and self.option and self.select:
            if self.option[2]:
                self.fields.append((self.select, self.option[0] if self.option[0] is not None else "".join(self.option[1])))
            self.option = None
        elif tag == "select":
            self.select = None


def response_fields(html: str) -> list[tuple[str, str]]:
    parser = _Fields()
    parser.feed(sanitize_html(html))
    if len(parser.fields) > 2048:
        raise QSploitError("RESOURCE_LIMIT", "Captured HTML contains more than 2,048 form fields; use Raw to inspect all fields.")
    return parser.fields
