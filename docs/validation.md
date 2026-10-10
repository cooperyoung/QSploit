# Validation record

Executed locally on **10 October 2026**, macOS arm64, Python 3.12.10 / OpenSSL 3.6.2. The exact dependency resolution is in `uv.lock`.

## Final test result

```text
.venv/bin/python -m pytest -q
223 passed, 1 skipped, 2 warnings in 15.57s
```

| Area | Passed | Evidence |
|---|---:|---|
| PCAP/TCP, TLS classification and TLS 1.2 crypto | 75 | Real EMS/non-EMS/ticket captures, independent master-secret and HTTP oracles, both Finished checks, all 19 protected records per fixture; replay, gaps, overlaps, sequence wrap/reuse, malformed framing and 400 deterministic mutations |
| Quantum engine, arithmetic, provider contracts and Qollab companion | 56 | Generic Aer 15/21 measured factorization; small-register exhaustive arithmetic and coherent superpositions; no-fallback and timing checks; offline IonQ QIS/result/status/cancellation tests; injected-Aer one-job companion runs |
| Recovery worker result boundary | 38 | Wrong factors/provenance, malformed/out-of-range distributions, invalid or excessive resource metadata, missing cloud job IDs and digest validation |
| HTTP and safe-preview processing | 30 | Byte-exact messages, chunked/gzip, HEAD/1xx/204/304, pipelines, missing responses, close-delimited framing, protocol upgrades, body/parameter bounds, malformed/obfuscated unsafe HTML |
| Fixture provenance | 8 | Genuine capture containers, hashes and independent endpoint observations |
| Local API | 16 | Spawned recovery, both Finished and full HTTP outputs, no factor/key leakage, unknown key and corruption failures, origin/Host/custom-header checks, active-job conflicts, scoped IDs, replacement/failed-attempt behavior |

The one skipped test is the opt-in real-browser acceptance test. It is skipped deliberately and is **not** counted as passing.

Warnings: the installed Starlette TestClient deprecates its httpx integration; it remains functional in this lock. qiskit-ionq emits a default-transpilation warning during offline provider construction. QSploit's actual circuit transpilation explicitly uses optimization level 1. Neither warning was suppressed or reported as a failed check.

## Independent runtime proof

```sh
.venv/bin/python scripts/prove_isolation.py
```

Passed. A separate application process and spawned recovery worker are denied reads of `tests/`, expected-output files and endpoint key/keylog files through a test-only Python audit hook. The process reads only the packaged PCAP and demo factors for the workflow. The independent parent compares the resulting stream hashes to endpoint evidence:

```text
c2s SHA-256 316a7c7f3b7a7d402296f5a285bb9e0c7d493d79d74710414cbbc4354c56dd03
s2c SHA-256 d9ff22f992c44c8d6ffb25808effbdec789fbe4fcc1338efe585f158e0910bfb
client_finished_verified = true
server_finished_verified = true
authenticated_records = 19
method = fixture_lookup
execution = none
oracle_access = denied
```

This audit hook is instrumentation demonstrating absence of oracle dependence, not a claim to be an operating-system security sandbox. The installed package excludes expected files entirely. Both evidence approaches support that HTTP comes from runtime TLS decryption.

## Installation and packaging

- `uv lock --check --offline --cache-dir .uv-cache` passed.
- `uv build --offline --cache-dir .uv-cache` produced a source distribution and wheel.
- Wheel inspection confirmed UI assets, PCAPs and `factors.json`, with no test-oracle files. The source distribution contains test evidence but excludes `.venv`, `.git`, bytecode and dependency caches.
- A fresh temporary Python environment installed only the wheel and its **ordinary runtime dependencies**. With Qiskit, Aer, IonQ, pytest and httpx absent, it decrypted the packaged PCAP, verified both Finished messages and 19 protected records, recovered exactly matching endpoint hashes, reconstructed two HTTP exchanges, and constructed the FastAPI application.
- The initial offline clean-install attempt could not resolve every native cached dependency. Repeating with authorized registry access succeeded. This was a cache-availability issue; normal installed runtime makes no downloads.
- Python compile checks and `node --check qsploit/static/app.js` passed. Prettier formatted the static source as a one-time development operation; there is no Node runtime/build dependency.
- Uvicorn starts successfully at **http://127.0.0.1:8765**. Port 8000 was already held by another process, which was left untouched. No external bind is enabled.

## Cryptographic negative evidence

Tests corrupt every captured protected record in turn, including alerts, and require authentication failure with no published session plaintext. They also alter Finished verify_data and re-encrypt with a valid test tag: the separate Finished check rejects it. Conversely, splitting Finished across records and using explicit GCM nonces different from sequence numbers succeeds. Real NewSessionTicket issuance is included in the correct server-Finished transcript. Both EMS and non-EMS match independent endpoint master-secret oracles without trying alternate schedules.

## Quantum execution evidence

Aer actually ran the same generic construction for 15 and 21 under the 22-qubit policy. A separate development run factored 35 with an explicitly increased 26-qubit limit. See [quantum-evidence.md](quantum-evidence.md) for circuit dimensions, hashes, shots, versions and timing. These are circuit simulations, not recovery of the RSA-2048 capture key.

No IonQ cloud simulator or physical QPU execution occurred. No API key/target was configured. Provider tests use explicit test doubles and offline compilation, not hidden live calls. No hosted Qollab execution or submission occurred; its companion was locally tested using the documented backend injection contract.

## Remaining checks and limitations

1. **Browser acceptance unverified.** The browser tool denied permission to access the local app at 127.0.0.1:8765. No alternate browser or headless workaround was used. Static parsing/sanitization and API preview headers are tested, but script/network/storage isolation in a real browser and visual layout are not claimed. Once authorized, install Chromium and run:

   ```sh
   .venv/bin/python -m playwright install chromium
   QSPLOIT_BROWSER_TESTS=1 .venv/bin/python -m pytest tests/test_browser.py -q
   ```

   The supplied test observes outgoing requests, preview navigation, script flags and sandbox isolation; it runs the application with oracle/key-file access denied and saves desktop/mobile screenshots. Because it has not been executed, it may itself need adjustment.

2. **Hosted submission validation remains.** Import `qollab/`, run on the required free simulator(s), verify the actual Qollab behavior/performance, and only then publish after review. Deep noisy order-finding can return no factors. A public repository, public 2–3 minute video, registration/eligibility and final submission links are not prepared external state.

3. **Supported protocol scope is narrow.** Full TLS 1.2 static RSA/0x009c decrypts. Other exchanges are classification-only. PCAPNG, IP fragments, TLS resumption/client authentication/renegotiation, HTTP/2 and other content encodings are unsupported or preserved as raw bytes with warnings. TCP checksum validation is not implemented; supported decryption relies on all record tags plus Finished validation.

4. **Cloud cancellation remains best effort.** The parent tracks provider IDs, resets its deadline when a provider job is observed, and signals interruption before forcing a stopped worker. The adapter attempts cancellation and reports confirmation only after actual cancelled status. A blocked provider request or forced process exit can leave a remote job running. IDs and capture state are in memory and are lost at restart.

5. **Future hardware still requires quantum engineering.** No cryptographic-scale runtime/resource estimate, present RSA-2048 quantum attack, fault-tolerant compiler, or one-key migration is claimed. The current demo delay is explicitly illustrative.
