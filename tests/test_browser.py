"""Opt-in browser acceptance. Not executed during the autonomous build because
the browser tool denied local-site access. Run only when browser access is
authorized: QSPLOIT_BROWSER_TESTS=1 .venv/bin/python -m pytest tests/test_browser.py.
Install Chromium first: .venv/bin/python -m playwright install chromium
"""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.request import urlopen

import pytest

pytestmark = [pytest.mark.browser, pytest.mark.skipif(os.getenv("QSPLOIT_BROWSER_TESTS") != "1", reason="Browser acceptance requires explicit opt-in; local browser access was denied during build.")]
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def browser_app():
    from playwright.sync_api import sync_playwright
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0))
        port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    process = subprocess.Popen([sys.executable,"scripts/prove_isolation.py","--serve","--demo","--demo-delay-seconds","0","--port",str(port)],cwd=ROOT,env={**os.environ,"QSPLOIT_ISOLATION_PROOF":"1"},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                with urlopen(origin+"/api/config",timeout=1):
                    break
            except OSError:
                time.sleep(.05)
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            yield browser,origin
            browser.close()
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_full_browser_workflow_and_inert_real_html(browser_app):
    browser,origin = browser_app
    from playwright.sync_api import expect
    page = browser.new_page(viewport={"width":1440,"height":1100})
    requests, errors = [], []
    page.on("request",lambda req: requests.append(req.url))
    page.on("pageerror",lambda err: errors.append(str(err)))
    page.goto(origin)
    expect(page.locator("#mode-banner")).to_contain_text("DEMO MODE")
    page.locator("#file").set_input_files(ROOT / "tests/fixtures/tls12-rsa-ems.pcap")
    expect(page.locator("#recover")).to_be_enabled()
    page.locator("#recover").click()
    expect(page.locator("#job-stage")).to_have_text("Captured TLS plaintext verified",timeout=20000)
    expect(page.locator("#checks")).to_contain_text("19 authenticated records")
    expect(page.locator("#exchanges button")).to_have_count(2)
    page.locator('[data-side="request"][data-tab="parameters"]').click()
    expect(page.locator("#request-content")).to_contain_text("Cooper")
    page.locator('[data-side="response"][data-tab="render"]').click()
    frame = page.frame_locator('iframe[title="Captured response preview"]')
    expect(frame.locator("body")).to_contain_text("Cooper")
    expect(frame.locator("script,img[src],a[href],iframe,form")).to_have_count(0)
    expect(frame.locator('input[name="account_id"]')).to_be_disabled()
    assert page.locator("iframe").get_attribute("sandbox") == ""
    inner = next(f for f in page.frames if "/preview" in f.url)
    assert inner.evaluate("typeof window.__capturedScriptExecuted") == "undefined"
    assert page.evaluate("typeof window.__capturedScriptExecuted") == "undefined"
    assert inner.evaluate("() => {try {void parent.document.body; return 'accessible'} catch {return 'blocked'}}") == "blocked"
    assert inner.evaluate("() => {try {localStorage.setItem('probe','1'); return 'accessible'} catch {return 'blocked'}}") == "blocked"
    before = inner.url
    frame.get_by_text("Account settings",exact=True).click()
    assert inner.url == before and page.url == origin + "/"
    preview_url = page.locator("iframe").get_attribute("src")
    direct = browser.new_page()
    direct.on("request",lambda req: requests.append(req.url))
    response = direct.goto(origin+preview_url)
    assert "sandbox" in response.headers["content-security-policy"]
    assert all(url.startswith(origin+"/") for url in requests)
    assert not errors
    direct.close()
    page.locator("#exchanges button").nth(1).click()
    page.locator('[data-side="response"][data-tab="readable"]').click()
    expect(page.locator("#response-content")).to_contain_text("hello world")
    # Exact bytes are checked independently via API tests; UI must show actual
    # selected response and preserve separate recovered parameter values.
    page.screenshot(path=ROOT/"docs/browser-desktop.png",full_page=True)
    page.set_viewport_size({"width":390,"height":844})
    assert page.locator("#recover").is_visible()
    page.screenshot(path=ROOT/"docs/browser-mobile.png",full_page=True)
    page.close()
