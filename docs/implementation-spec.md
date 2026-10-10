# QSploit — implementation specification

Revised 10 October 2026. This specification replaces the original proposal's
blocking assumptions and redundant component scaffolds. The user's assignment
and ordered protocol-extension request govern scope. The exact completed
combinations and supporting evidence are recorded in [support-matrix.md](support-matrix.md).

## Purpose and demonstration

QSploit previews future quantum-assisted cryptographic recovery through a local
PCAP inspector. Upload a capture, discover separate TCP/TLS sessions, identify the
negotiated public-key problem, request recovery, authenticate/decrypt locally, and
inspect the actual captured HTTP request and response.

Today's primary demonstration substitutes only cryptographic-scale recovery.
A labeled fixture backend matches the entire public problem to known test
material, waits a configurable illustrative delay, and returns a verified
algorithm-specific result. All shared-secret computation, key schedules,
Finished checks, record authentication, HTTP framing and HTML sanitization run
for real. Unknown problems fail honestly. No key file or second upload is needed.

The product does not promise that more qubits alone make recovery instantaneous.
Future fault-tolerant hardware may require different algorithms, compilation,
resource management and execution adapters. The stable boundary protects the
capture, TLS, HTTP and inspector components from those changes.

## Scope and delivery order

1. Preserve the working original TLS 1.2 static-RSA/AES-128-GCM demonstration.
2. Add static RSA/AES-256-GCM.
3. Add TLS 1.2 DHE_RSA with AES-GCM.
4. Add TLS 1.2 ECDHE_RSA, first P-256 then X25519, with AES-GCM.
5. Add TLS 1.3 ECDHE, first AES-128-GCM, then AES-256-GCM.
6. Add ChaCha20-Poly1305 where a matching standard suite exists.
7. Add TLS 1.3 FFDHE.

Complete a genuine capture-to-inspector acceptance gate and preserve a Git
checkpoint before moving to another path. Current finite-field scope is the
validated RFC 7919 ffdhe2048 group; elliptic curves are P-256 and X25519.
RSA certificate authentication is distinct from RSA key transport. ECDSA/EdDSA
certificate verification is outside the current implementation unless the
support matrix explicitly adds it.

TLS 1.3 is a separate protocol engine, not a TLS 1.2 cipher option. Additional
quantum evidence is independent of these classical extensions: measured generic
small-number order finding is useful, but neither that experiment nor a live
IonQ job is a prerequisite for the complete system demonstration.

## Architecture and public recovery boundary

One local FastAPI process serves plain HTML/CSS/JavaScript and stores one capture
in bounded memory. Ordinary Python functions and explicit dataclasses implement:

- `pcap.py`: capture decoding and distinct TCP connection reconstruction.
- `tls.py`: record/handshake parsing and negotiated classification.
- `tls12.py` and `tls13.py`: version-specific secret schedules and authentication.
- `keyexchange.py` / `groups.py`: shared mathematical validation and exchange.
- `http1.py` and `preview.py`: HTTP framing, decoded bodies and inert rendering.
- `quantum/`: algorithm construction, provider compilation/execution, recovery
  lookup, timing and result verification.
- `jobs.py`: a bounded spawned recovery worker and parent-side verification.
- `app.py` / `static/`: local API, job lifecycle and inspector.

The worker receives one typed public problem and execution options. It never
receives the PCAP, traffic records, certificate chain, peer client share,
HTTP bytes, premaster/master/traffic secrets, or a private key.

| Problem | Public input | Recovery result | Mathematical verification |
|---|---|---|---|
| `RSAProblem` | modulus `n` | `RSAFactors(p,q)` | distinct probable primes, `p*q == n` |
| `FFDLogProblem` | `p,g,y,order` | `FFDLogSecret(x)` | validated group/subgroup and `g**x mod p == y` |
| `ECDLogProblem(secp256r1)` | named curve and server point | `ECDLogSecret(x)` | valid scalar and `xG == Q` |
| `ECDLogProblem(x25519)` | named curve and encoded server u-coordinate | `X25519Secret(scalar)` | RFC 7748 public-key computation matches the normalized share |

`Recovery(secret, method, execution, target, measurements)` carries provenance.
Result types cannot be interchanged. Parent verification occurs before any
local TLS operation. Demo recovery can claim only `fixture_lookup` with no
provider target/job/measurement. Real quantum recovery preserves target, job
IDs, distribution type, circuit hash, qubits, compiled operations/depth and
actual shots when counts exist. Simulator probabilities are not fictional shots.

The same interface supports demo recovery and real execution. At present, only
the small-number RSA order-finding solver is implemented; FF/EC discrete-log
recovery is fixture-only. A real backend must never fall back to fixtures.

## Timing and configuration

`demo_delay_seconds` is finite, bounded, zero-capable, and defaults to three.
The timing function takes the typed public problem and options, separately from
recovery lookup and TLS processing. Its default output is an explicitly labeled
illustrative presentation delay, not a hardware runtime prediction.

An optional resource-based estimate requires defensible serial logical depth,
logical operation time and repetitions. Available logical qubits are a feasibility
constraint, not a divisor that makes runtime vanish. State every assumption.
Without a defensible resource estimate, retain the configured illustrative delay.
Live execution reports actual queued/running/completed/error provider status and
uses bounded timeout/cancellation, never the fixture timer.

Launch with `./run-demo.sh --port 8765`. The persistent UI banner identifies known
test recovery and the configured delay. Production-style execution is explicitly
selected on startup. Credentials stay in environment variables; they do not
appear in the browser, logs, source control or capture metadata.

## TCP and capture requirements

Accept classic PCAP, detect endianness/timestamp format, and bound upload size,
packet/session counts and reconstructed streams. Decode supported Ethernet/VLAN,
loopback and raw-IP link types with IPv4/IPv6 TCP. Identify connections by both
endpoints and lifecycle, including reused tuples. Orient directions from the
actual ClientHello, not port 443.

Reassemble by TCP sequence numbers with wrap handling. Identical retransmissions
are deduplicated; conflicting overlap is an explicit failure. Gaps, truncated
records and missing handshakes must not be papered over. TCP reconstruction is an
internal responsibility, not another service or product step. PCAPNG and IP
fragment reassembly remain explicit limitations.

TLS records and handshake messages can cross packet and record boundaries.
Retain exact wire handshake encodings for transcript hashes. Bound lengths and
reject ambiguous duplicate/renegotiated handshakes. Classification uses selected
version, cipher suite, key-share group, PSK selection and handshake structure.
A certificate by itself does not identify the key exchange.

## TLS 1.2 correctness

For static RSA, extract certificate `n,e` and the ClientKeyExchange ciphertext
locally. Derive the private exponent from verified factors, perform RSA recovery,
and validate strict PKCS#1 v1.5 encryption padding and the 48-byte premaster
including client version. Do not accept malformed padding merely because later
plaintext appears plausible.

For DHE, validate group, prime subgroup and both public shares. Verify signed
ServerKeyExchange parameters against the certificate. A recovered server
exponent computes the client share to that exponent. TLS 1.2's DH premaster
omits leading zero octets.

For P-256, validate uncompressed point encodings and scalar range; verify signed
parameters. The premaster is the fixed 32-byte big-endian ECDH x-coordinate,
including leading zeros. For X25519, retain a distinct 32-byte private input,
apply RFC 7748 clamping and little-endian u-coordinate semantics, mask the high
public bit and normalize aliases, and reject low-order/all-zero exchanges.
Do not reuse P-256 integer or point encoding logic for X25519.

Use the negotiated suite's SHA-256 or SHA-384 PRF. Ordinary master-secret seed is
client_random || server_random. EMS hashes the exact full handshake transcript
through ClientKeyExchange before adding Finished. The key-block seed reverses
random order. Session-ticket handshake messages belong in their protocol-defined
transcript positions. Require both Finished values in constant-time comparison.

Each direction resets protected-record sequence to zero at ChangeCipherSpec and
increments for every protected record, including handshake and alerts. AES-GCM
uses the fixed four-byte write IV, eight-byte explicit record nonce, 16-byte tag,
and AAD sequence || type || version || plaintext length. AES-256 requires 32-byte
keys and SHA-384 PRF; AES-128 uses 16-byte keys and SHA-256.

TLS 1.2 ChaCha20-Poly1305 uses SHA-256, two 32-byte keys and two 12-byte IVs.
Its nonce is the fixed IV XOR zero-padded 64-bit sequence number, with no explicit
nonce bytes. The standard DHE_RSA/ECDHE_RSA suites exist; static RSA ChaCha does
not. An AEAD tag failure aborts release of the entire session's plaintext.

## TLS 1.3 correctness

Parse the selected supported version and server key share from ServerHello.
For a non-PSK full handshake, perform HKDF-Extract/Derive-Secret according to
RFC 8446, including the zero-valued absent PSK and the hash of an empty transcript
for derived secrets. SHA-256 belongs to AES-128-GCM and ChaCha; SHA-384 belongs
to AES-256-GCM. HKDF label encoding is `tls13 ` plus label and explicit lengths.

Handshake traffic secrets depend on ClientHello through ServerHello. Application
traffic secrets depend on the transcript through server Finished, not client
Finished. Decrypt the encrypted handshake before obtaining certificate, ALPN,
CertificateVerify and Finished. Validate CertificateVerify's context string,
64 spaces, separator and transcript digest, using an offered supported signature
scheme. Signature digest selection and cipher-suite transcript hash are distinct.

Verify server Finished before processing application epoch data; verify client
Finished against the transcript including server Finished. Handshake and
application epochs have independent per-direction sequence numbers starting at
zero. Outer records use application_data and legacy version 0x0303; AAD is the
exact outer header. Nonce is write IV XOR padded sequence. Strip zero padding
from authenticated TLSInnerPlaintext, recover inner content type, and enforce
ciphertext/inner/plaintext limits. Never expose partially verified plaintext.

Handle compatibility CCS only at valid positions. Parse and bound post-handshake
NewSessionTicket messages without mixing them into the initial transcript.
KeyUpdate is authenticated with the old sending key, derives `traffic upd`, and
resets that direction's sequence. Enforce message/key-change record boundaries,
valid request flags, and a bounded number of updates. Document whether update
coverage is genuine capture or constructed authenticated-record evidence.

For TLS 1.3 FFDHE, use a fixed-width shared secret padded to the group prime's
byte length, unlike TLS 1.2. The recovery contract remains the FF discrete-log
problem. Reject unsupported groups rather than guessing parameters.

HelloRetryRequest is detected and explicitly unsupported until its synthetic
message_hash transcript, retried shares and negotiation checks are implemented
and independently tested. Unknown PSK/resumption, early data, client certificate
authentication and post-handshake authentication remain explicit blockers.
Recognize PQ/hybrid exchange groups: Shor recovery of the classical component
alone is insufficient. Do not label them quantum-decryptable.

## HTTP and rendering

TLS authentication and application decoding are separate milestones. A verified
session may expose directional authenticated bytes even if the application
protocol is unsupported. HTTP/2 receives a specific decoding limitation unless
a full bounded frame/HPACK/stream decoder has independently verified coverage.

For HTTP/1.1, reconstruct actual request/response framing with h11, pairing
messages in order and preserving exact raw bytes. Respect Content-Length,
chunked transfer/trailers, informational responses, connection closure and body
limits. Authenticated TLS close_notify establishes EOF for close-delimited HTTP;
a capture ending without it does not. Bound gzip expansion. Preserve repeated
and blank query/form values. Do not replay requests or infer missing values.

Render the response associated with the selected captured request. Sanitize HTML
with a small allowlist, remove scripts/handlers/URLs/navigation/live resources,
and make controls inert. Use an iframe with empty sandbox plus restrictive CSP,
no forms, network, plugins or same-origin privileges. Text is assigned through
safe DOM APIs. Raw remains the actual captured plaintext; readable and preview
views are clearly transformations. Unsafe HTML cannot gain application rights.

## API, UI and failure behavior

The UI provides drag/drop upload, distinct sessions with endpoints/version/suite/
key exchange/group/eligibility/status, session details, an ordinary recovery
action, job progress/provenance, request list, raw/readable message panes, query/
form parameters, safe response preview, and authenticated stream downloads.

The main demo uses the original RSA capture. A mixed protocol tour merges genuine
captured packets without modifying them, exercising multiple session types in
one upload. The tour must have a source manifest and exact independent per-session
oracles. Loading a demo follows the ordinary upload API.

Bind to loopback. Validate Host/Origin and require a custom mutation header.
Use no-store, nosniff, restrictive application/preview CSP and no secret-bearing
errors. Capture IDs scope session URLs so replacing an upload cannot resolve an
old URL to new traffic. One bounded active worker avoids unbounded compute. A
failed recovery/decryption never publishes plaintext or corrupts other sessions.

Distinguish unsupported protocol, missing public/handshake data, malformed
capture, unknown fixture, invalid recovery result, authenticated-record failure,
Finished/signature failure, unavailable provider, timeout, and unsupported HTTP.
A demo or failed cloud operation must never produce a misleading success badge.

## Fixtures, validation and acceptance

Generate actual TCP/TLS traffic between independent local endpoints. tcpdump,
OpenSSL, tlslite-ng and endpoint instrumentation are development-only dependencies.
Capture unmodified OS packets; retain public fixture factors/scalars separately
from test-only plaintext and key-log oracles. Observe original random recovery
material without replacing the RNG, handshake records or traffic keys. Delete
temporary private keys and logs after generating bounded test evidence.

A protocol path is complete only when all of these hold:

1. Genuine committed capture and SHA-256/source metadata exist; two independent
   endpoints agree on application bytes and relevant key-log secrets.
2. A PCAP-only upload classifies the negotiated path and invokes the matching
   typed recovery request with the configured delay and honest provenance.
3. Verified recovery yields actual local shared-secret/key derivation, both
   Finished checks and authentication of every protected record.
4. Exact request/response bytes and readable HTTP appear through the normal API;
   selected captured HTML renders inertly, with no external fetches.
5. Unknown material, wrong recovery type/value, modified tags/handshake/Finished,
   missing packets and malformed public parameters fail without plaintext.
6. All previous protocol tests pass, and a Git checkpoint records the gate.

Additional checks cover EMS/non-EMS, ticket ordering, retransmissions/conflicts,
sequence wrap/epochs, TLS 1.3 padding/KeyUpdate, X25519 published vectors, bounded
resource failures, unsafe HTML, backend errors and zero/default delay.
Independent RFC 8448 TLS 1.3 vectors validate schedule/Finished/record behavior.
An isolation process denies access to test oracles, private keys, key logs and
fixture-generator code while independently comparing recovered stream hashes.

Run browser interaction when permission permits. A denied browser run is recorded
as unexecuted/skipped; API tests alone do not establish visual correctness.
Build and install a wheel into a clean runtime to prove that packaged PCAPs and
recovery registries suffice, without development tools or expected-output files.

## Quantum and platform evidence

Generic small-number Shor evidence must construct modular arithmetic from the
input, execute a circuit, reconstruct candidate orders from measurements, and
verify nontrivial factors. No hardcoded factors, precomputed orders or special
factor-15 circuit can be represented as a generic solver. Bound qubits, compiled
operations, shots, attempts and wall time. Label any classical lucky-gcd shortcut.
Never claim small-number results cracked the realistic captured RSA modulus.

IonQ integration stays in the quantum component. Preserve compilation and job
lifecycle diagnostics. A mocked/offline test is not a cloud run, simulator run is
not physical hardware, and target discovery is not access confirmation. Report
exactly which environments ran and which need credentials or platform access.

Official Qollab documentation describes a browser/Pyodide Qiskit runtime with an
injected backend, not a FastAPI host. Keep the local application and prepare a
small runnable Qollab quantum companion with shared generic arithmetic. Respect
one IonQ job per Run and platform limits. Requirements, verified sources and
assumptions are in [platform-research.md](platform-research.md).

Prepare MIT source, a descriptive submission page, attribution/disclosure,
2–3 minute walkthrough and honest limitations. Preserve the required text:
“This effort is supported by Qollab & IonQ”. Do not publish, submit, spend on
unconfigured hardware or claim registration/platform eligibility is verified.

## Deliverables

Runnable source and locked dependencies; simple launch command; genuine demo
captures and isolated recovery fixtures; this corrected specification and change
summary; tested source/adapter boundaries; automated validation and accurate
results; support matrix; walkthrough; Qollab companion/submission copy; and an
honest limitations/access-blocker list. Save precise resume notes if interrupted.
