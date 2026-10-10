# QSploit

**A working preview of future quantum-assisted HTTPS recovery.** Upload a real PCAP, discover its sessions, recover a supported test key, and inspect authenticated HTTP locally.

In **demo mode**, only factor recovery is substituted: the engine matches the actual RSA modulus to bundled test factors after a configurable presentation delay. RSA premaster recovery, TLS 1.2 PRF/EMS, both Finished checks, AES-GCM authentication, and HTTP reconstruction execute for real. Unknown keys never produce invented success.

This effort is supported by Qollab & IonQ.

## Run the demo

The prepared workspace already has a Python 3.12 virtual environment. From this directory:

```sh
./run-demo.sh --port 8765
```

Open **http://127.0.0.1:8765**. Port 8000 is the default, but another existing local process occupied it during development. QSploit binds only to loopback.

1. Click **Open demo capture**, or upload `qsploit/demo/qsploit-demo.pcap`.
2. Select the RSA session and click **Recover session**. No secret or second input is needed.
3. After the default **3-second illustrative delay**, inspect the two HTTP exchanges.
4. Select **Parameters**, then **Render** for the profile response. Inspect the second exchange's decoded gzip JSON in **Readable**.
5. Upload `qsploit/demo/mixed-discovery.pcap` to contrast static RSA, ECDHE_RSA, TLS 1.3, and ordinary TCP. Enable **All TCP** to see the latter.

The persistent demo banner and job provenance state **known test factors / no quantum execution**. The delay is a presentation setting, not a hardware estimate:

```sh
./run-demo.sh --port 8765 --demo-delay-seconds 0
# Or set QSPLOIT_DEMO_DELAY_SECONDS=3
```

## Install on another machine

Python 3.12 is tested; the package supports Python 3.12–3.13. No Node build, database, traffic-decryption CLI, or runtime network download is required.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install uv
.venv/bin/uv sync --frozen
./run-demo.sh --port 8765
```

For tests and separate quantum evidence:

```sh
.venv/bin/uv sync --frozen --all-extras
.venv/bin/python -m pytest -q
.venv/bin/python scripts/prove_isolation.py
```

`uv.lock` pins all resolved versions. `pip install -e .` also installs the ordinary runtime, while `pip install -e '.[dev,quantum,ionq]'` installs extras; those pip commands resolve the declared ranges rather than enforcing the uv lock.

## Two different demonstrations

| Evidence | What actually happens |
|---|---|
| Real RSA-2048 TLS capture | Known test factors → real RSA premaster → real TLS schedules → verified records and HTTP |
| Quantum validation lab | Generic reversible modular arithmetic → executed Aer order-finding circuit → measured phases → verified factors of 15 or 21 |

The second result **does not** crack the captured RSA key. Open the **Quantum validation lab** drawer, or run:

```sh
.venv/bin/python -m qsploit.quantum --modulus 15
.venv/bin/python -m qsploit.quantum --modulus 21
```

The quantum component accepts `RSAProblem(n)` and returns `Recovery(factors, provenance)`. A spawned process receives only that public problem and execution options. Capture bytes, certificates, TLS ciphertext and secrets are not passed to it. Future fault-tolerant algorithms, compilation, resources, and provider adapters may change substantially; the capture/TLS/HTTP path is protected by this narrow contract.

## Qollab and IonQ

The local FastAPI app is complemented by **`qollab/`**, a portable Qiskit project using Qollab's injected `backend` and one job per run. Its circuit and postprocessing files are generated from the same quantum implementation, not a separate hardcoded factor demo. The companion has been tested locally with an injected Aer backend; a hosted Qollab run remains unverified.

[Submission draft](docs/submission.md) · [2–3 minute walkthrough](docs/demo-walkthrough.md) · [Verified platform requirements](docs/platform-research.md) · [Quantum evidence](docs/quantum-evidence.md)

An IonQ adapter is implemented and tested offline for QIS compilation, result normalization, status, failures and cancellation. No cloud simulator or physical QPU job was submitted: no credentials and target were configured. See the quantum evidence document for explicit enablement and bounds. There is no fallback from quantum failure to demo mode.

## Scope and local handling

Decryption supports full TLS 1.2 static RSA using `TLS_RSA_WITH_AES_128_GCM_SHA256`, RSA-2048 test fixtures, EMS and non-EMS, and HTTP/1.1. Discovery also distinguishes selected TLS 1.2 DHE/ECDHE and TLS 1.3 classical/PQ/PSK exchanges. Factoring an RSA authentication certificate cannot decrypt a captured ECDHE session.

Unsupported: PCAPNG, unrecognized link types, IP fragment reassembly, TLS resumption/client authentication/renegotiation, other TLS decryptors, HTTP/2 and live-site replay. Gaps, conflicting overlaps, wrong factors, bad Finished or bad record tags prevent plaintext publication. Checks authenticate the captured TLS protocol; they do not validate website identity through a CA.

Capture and recovered plaintext live in process memory; replace, clear or restart to release them. Python does not guarantee secure erasure. API mutations require the loopback Host, same Origin when present, and a custom header. Previews strip active markup and URLs, disable controls, and use a sandbox plus restrictive CSP even on direct navigation. They never replay requests or fetch linked resources.

## Validation and source map

- [Validation record and remaining blockers](docs/validation.md) records actual checks, including the denied browser check. Browser acceptance is supplied as an opt-in test and has **not** been executed here.
- [Corrected specification](docs/implementation-spec.md), [change summary](docs/spec-changes.md), and [implementation notes](docs/implementation-notes.md).
- `qsploit/{pcap,tls,tls12,http1,preview}.py`: local classical processing.
- `qsploit/quantum/`: recovery, arithmetic, circuits, provider adapters, timing.
- `qsploit/{app,jobs}.py` and `qsploit/static/`: local API, isolated worker, plain HTML/CSS/JS interface.
- `scripts/make_fixtures.py`: development-only real loopback endpoints and tcpdump. Runtime never invokes it. See [fixture provenance](tests/fixtures/README.md).
- `scripts/prove_isolation.py`: deny test-oracle/key-file access in the application and recovery processes, then independently compare the recovered streams' hashes.

MIT licensed. Built with Codex assistance from the supplied design specification; protocol and algorithm sources are attributed in the specification and quantum evidence. Nothing has been published or submitted externally.
