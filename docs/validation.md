# Validation record

Executed locally on **10 October 2026**, macOS arm64, CPython 3.12.10. `uv.lock`
pins the complete dependency resolution. The original working RSA demonstration
is preserved at `8c207d2`; all requested protocol extensions and the mixed tour
are preserved at `8e10660`. Later review-documentation commits do not change the
validated runtime code.

## Final results

```text
1093 passed, 1 skipped, 2 warnings in 155.70s (0:02:35)
```

The complete suite includes capture/TCP reconstruction, TLS 1.2 and TLS 1.3,
recovery workers, HTTP/preview/API behavior, genuine fixture provenance,
independent cryptographic vectors, executed Aer circuits and the local Qollab
companion. [Raw pytest output](evidence/pytest.txt) is retained.

Separately, **four pure Node controller tests passed**. They evaluate the actual
JavaScript with a stub DOM to check out-of-order exchange responses, session
selection during recovery, duplicate/stale polls and empty-capture replacement.
They are not browser rendering or visual tests.

Warnings are the locked Starlette TestClient's httpx deprecation and the IonQ
provider constructor's default-transpilation warning. Actual QSploit compilation
explicitly uses optimization level 1. Neither warning was suppressed. The one
skipped test is opt-in browser acceptance, which remains **unexecuted**.

## Tested protocol coverage

| Protocol and exchange | Independently validated ciphers |
|---|---|
| TLS 1.2 static RSA | AES-128-GCM, AES-256-GCM |
| TLS 1.2 DHE_RSA / ffdhe2048 | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| TLS 1.2 ECDHE_RSA / P-256 | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| TLS 1.2 ECDHE_RSA / X25519 | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| TLS 1.3 / ffdhe2048 | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| TLS 1.3 / P-256 | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| TLS 1.3 / X25519 | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |

These are **20 version/group/cipher combinations**. TLS 1.2 includes EMS and
non-EMS for every combination; extra evidence covers ticket issuance and genuine
TLS 1.3 KeyUpdate. TLS 1.3 capture authentication uses RSA-PSS. The detailed
[support matrix](support-matrix.md) distinguishes verified paths, detection-only
negotiations and unsupported features.

The mixed tour retains original packet bytes and timestamps from **33 genuine
sessions / 1,634 packets**. The complete upload → spawned recovery → HTTP inspector
API test decrypts every session, then checks all sessions again for state
isolation, exact endpoint HTTP, raw streams and inert previews. Both mixed-tour
tests passed; they are also included in the final full suite.

## Independent decryption evidence

The original RSA fixtures use real OpenSSL/Python TLS endpoints. Additional
captures use independent OpenSSL and tlslite-ng endpoints with tcpdump.
Development hooks observe the endpoint's original ephemeral random input;
they do not replace the wire protocol or shared-secret calculation. Independently
observed key-log secrets and exact HTTP streams agree. Endpoint private keys and
key logs are removed after generation. [Fixture provenance](../tests/fixtures/README.md)
and exact test-only oracles accompany every completed extension.

**All 31 packaged standalone fixtures passed the isolated runtime proof.** A
separate application and spawned recovery worker are denied reads of test oracles,
endpoint key/keylog files and fixture-generator source/bytecode. Recovery receives
only the public problem and returns test factors or a typed ephemeral scalar.
The independent parent verifies the decrypted stream hashes against endpoint
observations. [Per-capture results](evidence/isolation.json) record both Finished
checks, 19/20/21 authenticated records, `fixture_lookup`, `execution=none` and
`oracle_access=denied`. The audit hook is test instrumentation, not an OS sandbox.

No runtime plaintext, traffic key or master secret is loaded from those oracles.
Every supported path computes the shared secret and schedule locally. Corrupting
each protected record prevents publication. Valid-tag but incorrect Finished
messages also fail, demonstrating the separate transcript checks. Other negative
cases include unknown recovery material, wrong result types/values, malformed
points and shares, changed signed parameters, gaps and conflicting overlaps.

Published RFC 7748 and RFC 8448 vectors validate X25519 and TLS 1.3 independently.
Static cross-implementation SHA-384 and ChaCha vectors add schedule/nonce/AEAD
coverage. An OpenSSL-crosschecked FFDHE vector begins with a zero byte: TLS 1.3
correctly retains 256 bytes while TLS 1.2 uses 255. Synthetic vectors are labeled;
they are not presented as genuine captured traffic.

## Installation and actual HTTP-server proof

`uv lock --check --offline` and `uv build --offline` passed. Wheel inspection
confirmed UI assets, all PCAPs and the three isolated recovery registries, with
no test oracles or endpoint key files. The tested wheel is in `dist/`; its SHA-256
and source checkpoint are in [release.json](evidence/release.json).

A fresh environment installed **only the 19 hash-checked, locked base dependencies
and the built wheel**. Qiskit, Aer, IonQ, tlslite-ng, pytest and httpx were absent.
From outside the repository, `scripts/prove_installed_runtime.py` launched the
installed app on a temporary loopback port. Real HTTP requests uploaded the
packaged tour and recovered all **33 sessions / 20 combinations** through actual
spawned workers. Both Finished checks, exact directional bytes, raw HTTP exchanges,
decoded gzip JSON, form values and preview content matched independent endpoint
oracles. [Installed-package report](evidence/installed-runtime.json) is retained.
The initial sandbox disallowed binding a localhost port; the authorized rerun
passed. This is a server/API test, not a browser check.

Python compile checks, JavaScript syntax checks, the frozen lock check and
`git diff --check` passed. Runtime requires no Node build, traffic-decryption
CLI or network download. The review launcher uses a persistent local environment
outside cloud-synced Documents; `run-demo.sh` automatically selects it. The
restarted review server at `http://127.0.0.1:8765` was checked with real HTTP: demo
mode, the default three-second delay and the exact final tour bytes are served.

## Reproduce locally

On a fresh checkout, install all extras with `uv sync --frozen --all-extras` and
use `.venv/bin/python`. In this workspace, the reliable validation environment
avoids macOS/iCloud-offloaded dependency files:

```sh
PYTHONPYCACHEPREFIX=/private/tmp/qsploit-validation-pycache \
  /private/tmp/qsploit-clean-runtime/bin/python -m pytest -q
PYTHONPYCACHEPREFIX=/private/tmp/qsploit-validation-pycache \
  /private/tmp/qsploit-clean-runtime/bin/python scripts/prove_isolation.py --all
node --test tests/ui_races.test.cjs
node --check qsploit/static/app.js
.venv/bin/uv lock --check --offline --cache-dir /private/tmp/qsploit-uv-cache
```

The installed-package proof must use an environment containing a non-editable
wheel and base dependencies only, from a working directory outside this checkout.
The proof verifies that the imported module is outside the source checkout and
that the six checked optional packages are absent before launching its temporary
server; it does not independently inspect wheel installation metadata.

## Quantum and external-access status

Aer actually executes the generic order-finding construction for 15 and 21;
the final suite reruns these and one-job injected-Aer Qollab companion tests.
A separately recorded development experiment factored 35 under an increased local
26-qubit budget. See [quantum evidence](quantum-evidence.md) for exact dimensions,
hashes and provenance. None recovered the RSA-2048 capture key. There is no
implemented cryptographic-scale or finite-field/EC quantum DLP solver.

The IonQ adapter passes offline compilation, status, result, failure and
cancellation tests. **Zero IonQ cloud simulator or QPU jobs** were submitted;
credentials and an authorized target were not configured. **Zero hosted Qollab
runs** occurred. Local injected-backend tests are not hosted-platform verification.
Nothing was published or submitted externally.

## Remaining limitations and access blockers

- **Real-browser acceptance is unverified.** The browser tool denied local-site
  access. No alternate browser/headless workaround was used. API sanitation,
  preview headers and JavaScript state logic are tested; visual layout and actual
  browser script/network/storage isolation are not claimed. After access is
  granted, install Chromium and run `QSPLOIT_BROWSER_TESTS=1 .venv/bin/python -m
  pytest tests/test_browser.py -q`. The supplied unexecuted test may need fixes.
- **Hosted Qollab/IonQ verification and recording remain.** Registration,
  account access, required simulator runs, public repository/project links and
  the actual 2–3 minute video require user review/access. Submission materials
  and a walkthrough are prepared, not published.
- **Protocol scope is explicit.** Full handshakes and supported RSA authentication
  are required. PSK/resumption, HRR, early data, client authentication,
  renegotiation, ECDSA/EdDSA authentication, other groups, PQ/hybrid recovery,
  PCAPNG and IP fragment reassembly are unsupported. TCP checksums are not
  verified; AEAD/signature/Finished checks authenticate supported captured TLS.
  No public-CA or website-identity validation is performed.
- **HTTP/2 decoding is not implemented.** Authenticated directional bytes remain
  downloadable with an explicit decoding warning and successful TLS status.
  Recognition tests and an injected API decoder-limitation test pass; a genuine
  HTTP/2 endpoint capture was not added and no HTTP/2 interoperability is claimed.
- Cloud cancellation is best effort; blocked provider calls can leave remote
  jobs running. IDs and recovered data are in memory, with no secure-erasure
  guarantee. Real execution never falls back to fixtures.
- Demo timing is an illustrative configurable delay, not a cryptographic-scale
  resource estimate. Future algorithms, fault-tolerant compilation and provider
  resource management still require quantum engineering behind the typed contract.
