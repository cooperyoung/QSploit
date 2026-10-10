# Implementation reconciliation

Reviewed against the working source on 10 October 2026. The corrected specification now consolidates the original proposal and ordered extensions; this note records concrete implementation choices and boundaries. Test execution belongs in [validation.md](validation.md), with quantum provenance in [quantum-evidence.md](quantum-evidence.md). A written requirement or prepared test is not a passed gate.

| Area | Implemented choice / correction |
|---|---|
| Python and dependencies | CPython **3.12.10** is the tested interpreter. Package metadata permits 3.12–3.13; 3.13 is not independently validated. Seven direct classical dependencies, lazy quantum extras, and `uv.lock` preserve a runnable classical application without Qiskit. |
| Capture decoding | Ordinary functions validate classic-PCAP, link and IP lengths; `dpkt` decodes TCP. Packet counts are retained, timestamps are not. TCP order and causal handshake flights establish reconstruction; timestamps never establish Finished transcript order. |
| Checksums | IP/TCP checksum verification is **not implemented**. No checksum-offload diagnostic is claimed. Supported TLS authenticity is established by the negotiated AEAD, relevant handshake signatures and both Finished checks. This is separate from public CA/certificate trust, which is not validated. |
| Conservative capture handling | Ethernet/VLAN, BSD NULL/LOOP, unfragmented IPv4/IPv6, sequence wrap, retransmissions and matching overlaps are supported. Missing bytes and conflicting overlaps block recovery. Reused generations with overlapping bounded sequence windows are ambiguous. Undecodable packets conservatively block all retained connections; recognized fragments block the relevant IP endpoint pair. Arbitrary historical TCP generation interleaving is not a complete TCP-stack emulation. |
| Resource policy | Parser limits are module constants, not all CLI settings: 32 MiB capture/aggregate retained TCP payload, 16 MiB per direction/span, 200,000 packets, 512 connections, 200,000 records/direction, 4,096 clear handshakes/direction, 1 MiB/handshake and 16,384-bit RSA public parameters. Retained segment limits count retransmitted bytes before deduplication. HTTP caps headers at 64 KiB and bodies at 8 MiB; HTML input at 2 MiB, escaped preview content at 4 MiB, query/form fields and returned HTML fields at 2,048, exchanges at the 4,096 boundary, and job history at 64. Returned HTML field inventory takes the first 2,048 entries. |
| Contract placement | `problem_for` checks classical prerequisites and returns a typed RSA-factorization, finite-field DLP or curve-specific DLP public problem. The API decides launch-mode eligibility and exposes capabilities separately. The spawned worker receives only that public problem and execution options. No capture, certificate, encrypted premaster, peer client share or TLS secret enters its request. Results have distinct RSA factor, FF exponent, P-256 scalar or raw X25519 private-input types. |
| API state | Capture IDs are random. Public session IDs include the capture ID and TCP generation, preventing stale URLs from addressing a replacement capture. `endpoint_a`/`endpoint_b` display observed sockets when client/server roles are unknown. `/api/config`, `/api/demo-capture`, `/api/protocol-tour`, `/api/captures/current` and `/api/sessions/{id}/job` support launch provenance, the bundled PCAP and browser refresh recovery. |
| Timing and defaults | Demo delay defaults to 3 seconds, allows zero, and is explicitly illustrative. App launch defaults are 256 shots, one attempt and 180 seconds; the standalone quantum CLI uses 512 shots, one attempt and 180 seconds. Library dataclass defaults of 1,024 shots/four attempts are explicitly overridden by those entry points. No resource-based factoring time estimate is supplied. |
| Aer | Actual execution uses **matrix-product-state**, one CPU thread, seed 23, no configured maximum bond dimension and Aer’s default `1e-16` numerical truncation threshold. The app allows 22 qubits / 250,000 compiled operations. A separately recorded N=35 experiment raised its local qubit limit; that does not enlarge the UI budget or establish cryptographic-scale feasibility. |
| IonQ lifecycle | The installed adapter is tested offline, including QIS compilation and mocked lifecycle/results. Credentials and an explicit permitted target are required before real submission. Its own polling timeout attempts cancellation; the parent resets its deadline on first observed provider job ID and grants a short cleanup interval. SIGTERM requests best-effort provider cancellation before a hard kill. A blocked provider request, local stop, or app shutdown still does not establish remote cancellation. Job IDs are in memory; restarting clears them. No hosted simulator/QPU run is claimed. |
| Qollab packaging | `qollab/` is a separate supplied-backend quantum companion. Its arithmetic and postprocessing are byte-identical copies of the tested local source, enforced by tests. It accepts no capture or secret material. Local companion execution is not hosted Qollab execution; no arbitrary Python web-app hosting or submission success is assumed. Nothing has been uploaded or published. |
| UI scope | Sessions remain in capture order with a TLS/All TCP filter. Jobs poll every 400 ms. The separate browser quantum experiment offers Aer for 15 or 21; IonQ remains a separately configured CLI/API path. Browser tests are prepared; their actual execution status and access blocker must be read from the validation record. |

## Cryptographic review and evidence boundaries

The original RSA/AES-128 milestone is preserved at `8c207d2`. Subsequent protocol
checkpoints and exact genuine-capture coverage are in [support-matrix.md](support-matrix.md).
All supported paths quarantine application bytes until handshake authentication,
both Finished messages and every captured protected record have passed. A later
failure never invokes demo fallback or publishes partial plaintext.

TLS 1.2 uses suite-specific PRF/EMS hashes and AEAD layouts. Signed DHE/ECDHE
parameters are verified separately from recovery of the ephemeral secret. P-256
shared secrets retain fixed-width leading zeros; X25519 uses RFC 7748 encodings,
clamping and low-order rejection. The TLS 1.2 FF shared secret strips leading
zeros. TLS 1.3 instead uses its own HKDF/transcript schedule, encrypted certificate
and ALPN, handshake/application key epochs, CertificateVerify, both Finished,
padding and post-handshake processing. Fixed-width TLS 1.3 DH is kept distinct.

Independent endpoint key logs and exact HTTP streams validate genuine captures.
Published RFC 7748 and RFC 8448 vectors add implementation-independent evidence.
Tests also construct valid-tag but incorrect Finished messages, proving that AEAD
alone cannot produce success. Every protected record is individually corrupted
in negative coverage, alongside wrong recovery types/values, missing packets and
malformed group elements. API tests use actual spawned recovery workers; the
isolation proof denies oracle, key-log, private-key and generator-code reads.

These are engineering tests, not a formal security audit. Certificate signatures
bind the captured handshake to its supplied public key; no CA/site-identity trust
validation is claimed. Full handshakes are required; unknown PSK, HRR, early data,
client authentication, renegotiation, unsupported groups and PQ/hybrid exchange
remain explicit limitations. HTTP/2 decoding is separate from successful TLS:
verified directional application bytes remain available with a clear warning.

Only the small-number RSA order-finding solver is implemented as executed quantum
computation. Full-scale RSA and FF/EC DLP recovery use clearly labeled controlled
test fixtures. Future fault-tolerant arithmetic, compilation, resources and
provider execution will require engineering inside the quantum component.
