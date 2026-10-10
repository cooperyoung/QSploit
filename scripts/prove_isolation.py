"""Independent process proof: runtime cannot read test oracles or key files.

Run from the repository root with .venv/bin/python scripts/prove_isolation.py.
The parent reads expected endpoint bytes; the application child is denied them
by a Python audit hook inherited by its spawned recovery worker. This is test
instrumentation, not a general-purpose security sandbox.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def deny_oracles(event, args):
    if event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
        path = os.fsdecode(args[0])
        if "/tests/" in path or path.startswith("tests/") or path.endswith((".expected.json", ".pem", ".keylog", ".key")):
            raise PermissionError("Test oracles and endpoint key files are denied in the application process")


if os.environ.get("QSPLOIT_ISOLATION_PROOF") == "1":
    sys.addaudithook(deny_oracles)


def child():
    from fastapi.testclient import TestClient
    from qsploit.app import Settings, create_app
    forbidden = ROOT / "tests/fixtures/tls12-rsa-ems.expected.json"
    try:
        forbidden.read_bytes()
    except PermissionError:
        pass
    else:
        raise AssertionError("Audit denial not active")
    with TestClient(create_app(Settings(backend="fixture", demo_delay_seconds=0)), base_url="http://127.0.0.1:8000") as client:
        upload = client.post("/api/captures", headers={"X-QSploit":"1"}, content=(ROOT / "qsploit/demo/tls12-rsa-ems.pcap").read_bytes())
        upload.raise_for_status()
        sid = upload.json()["sessions"][0]["id"]
        job = client.post(f"/api/sessions/{sid}/recover", headers={"X-QSploit":"1"}, json={}).json()
        deadline = time.monotonic() + 20
        while job["state"] in ("queued", "running") and time.monotonic() < deadline:
            time.sleep(.05)
            job = client.get("/api/jobs/" + job["id"]).json()
        assert job["state"] == "succeeded", job
        assert job["demo_factors"] is None
        hashes = {d:hashlib.sha256(client.get(f"/api/sessions/{sid}/application/{d}").content).hexdigest() for d in ("c2s","s2c")}
        print(json.dumps({"hashes": hashes,"client_finished_verified":job["client_finished_verified"],"server_finished_verified":job["server_finished_verified"],"authenticated_records":job["authenticated_records"],"oracle_access":"denied","execution":job["execution"],"method":job["method"]}))


def parent():
    env = {**os.environ, "QSPLOIT_ISOLATION_PROOF":"1"}
    output = subprocess.check_output([sys.executable, str(Path(__file__).resolve()), "--child"], cwd=ROOT, env=env, text=True)
    result = json.loads(output)
    expected = json.loads((ROOT / "tests/fixtures/tls12-rsa-ems.expected.json").read_text())
    # The independent generator uses explicit application-stream fields.
    for d, key in (("c2s","c2s_base64"),("s2c","s2c_base64")):
        assert result["hashes"][d] == hashlib.sha256(base64.b64decode(expected[key])).hexdigest(), "Endpoint oracle mismatch"
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if "--serve" in sys.argv:
        from qsploit.__main__ import main
        sys.argv.remove("--serve")
        main()
    elif "--child" in sys.argv:
        child()
    else:
        parent()
