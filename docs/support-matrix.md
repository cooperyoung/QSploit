# Protocol support and extension record

The original end-to-end demonstration is preserved at Git commit `8c207d2`.
It passed 223 tests; one browser acceptance test was skipped because local
browser access was denied. A skipped browser test is not a passing UI check.

Only rows marked **verified** below have completed genuine capture → upload →
recovery → authenticated TLS → HTTP inspector API tests. A known demo scalar or
factor pair substitutes secret recovery only. The application never loads the
test oracle's master secret or expected plaintext.

| Protocol | Key exchange | Cipher | Recovery / decryption status |
|---|---|---|---|
| TLS 1.2 | Static RSA | AES-128-GCM / SHA-256 | **Verified**: EMS, non-EMS, ticket issuance; RSA-2048 factors |
| TLS 1.2 | Static RSA | AES-256-GCM / SHA-384 | **Verified**: EMS and non-EMS; RSA-2048 factors |
| TLS 1.2 | DHE_RSA, ffdhe2048 | AES-128/256-GCM | **Verified**: EMS and non-EMS; finite-field exponent |
| TLS 1.2 | ECDHE_RSA P-256 | AES-128/256-GCM | **Verified**: EMS and non-EMS; EC scalar |
| TLS 1.2 | ECDHE_RSA X25519 | AES-128/256-GCM | **Verified**: EMS and non-EMS; RFC 7748 private input |
| TLS 1.3 | ECDHE P-256, X25519 | AES-128-GCM / SHA-256 | **Verified**: full handshake, encrypted ALPN, ticket; X25519 genuine KeyUpdate |
| TLS 1.3 | ECDHE P-256, X25519 | AES-256-GCM / SHA-384 | **Verified**: independent 48-byte traffic-secret evidence |
| TLS 1.2 / 1.3 | Applicable DHE / ECDHE | ChaCha20-Poly1305 | Detection only; planned after TLS 1.3 AES-GCM |
| TLS 1.3 | FFDHE | Supported AEADs | Detection only; final requested extension |
| TLS 1.3 | PQ / hybrid, unknown PSK | Any | Unsupported: Shor alone is insufficient or the PSK is missing |

HTTP/1.1 reconstruction, chunked framing, bounded gzip decoding, and inert HTML
previews are implemented. Authenticated HTTP/2 bytes are exposed with an explicit
decoding limitation; that is separate from TLS success.

Full handshakes are required. Session resumption, renegotiation, client certificate
authentication, IP fragment reassembly, and PCAPNG remain unsupported unless a
later row explicitly records a completed extension. Discovery coverage does not
imply decryption coverage. Neither RSA certificate authentication nor a TLS cipher
suite alone determines an ephemeral key exchange.

## Extension 1: RSA / AES-256-GCM

`tls12-rsa-aes256.pcap` and `tls12-rsa-aes256-noems.pcap` are genuine loopback
TCP captures from independent TLS endpoints. Their key-log master secrets and
exact endpoint HTTP bytes agree with runtime decryption. Each verifies both
Finished messages and all 19 protected records. SHA-384 is used for the PRF, EMS
and Finished; the key block contains two 32-byte keys and two 4-byte GCM salts.

The upload, spawned recovery, raw-stream download, HTTP exchange and preview API
flow passes for both captures. Negative checks cover wrong factors, wrong hash
schedule, missing packets, all protected-record corruptions, and valid-tag but
incorrect Finished data. Existing AES-128 captures remain byte-for-byte unchanged.

## Extension 2: DHE / AES-GCM

Four independent OpenSSL ↔ tlslite-ng captures cover ffdhe2048 DHE_RSA,
AES-128 and AES-256, with and without EMS. The development endpoint passively
observes its original random exponent; the demo registry stores only that
exponent keyed by the entire public `(p,g,y,order)` problem. A fifth capture has
no retained test exponent and fails recovery honestly. Ordinary runtime needs
no tlslite-ng installation.

The recovery component verifies the exponent against the public share. The local
TLS component validates both subgroup elements, verifies signed ServerKeyExchange
parameters, computes the shared secret, strips leading zero octets as TLS 1.2
requires, then derives and authenticates traffic. All four upload-to-inspector
API flows pass and match independent OpenSSL master secrets and endpoint bytes;
each checks both Finished messages and 19 protected records. Isolation proof
passes while oracle and endpoint-key file access is denied.

Only ffdhe2048 and RSA signature schemes SHA-256/384/512 (PKCS#1 or PSS) are
implemented here. Other finite-field groups and SHA-1 signatures remain explicit
unsupported cases. The RSA order-finding solver is unchanged. No quantum
finite-field discrete-log solver or cloud DLP execution is claimed.

## Extension 3a: ECDHE / P-256

Four genuine ECDHE_RSA captures cover AES-128/256-GCM with and without EMS.
Their OpenSSL and tlslite-ng endpoints independently agree on master secrets and
exact HTTP bytes. The public recovery request contains only `secp256r1` and the
server's point. Scalar verification proves `xG = Q`; the peer point remains local.
Both points must be valid uncompressed P-256 encodings, and the local premaster
retains the full 32-byte x-coordinate, including leading zeros.

The normal upload/recovery/inspector/preview API flow and isolated runtime proof
pass for every capture. Tests reject off-curve/compressed/infinite points, wrong
scalars or result types, changed signed parameters, missing packets, invalid
record tags and valid-tag incorrect Finished messages. The original 38 recovery
boundary tests are readable again after macOS restored the offloaded file; they
pass after the internal `Recovery.secret` field rename. No EC quantum solver is
claimed. X25519 remains a separate next step at this checkpoint.

## Extension 3b: ECDHE / X25519

Four genuine AES-128/256-GCM, EMS/non-EMS captures pass the same complete API
workflow. A fifth unknown-share fixture has no retained recovery material. The
recovery result is a distinct 32-byte RFC 7748 private input, not a P-256 integer.
Public u-coordinates are decoded little-endian, their top bit is masked, and
noncanonical field encodings are normalized. Private clamping is performed by
X25519 itself; low-order/all-zero exchanges are rejected. The recovered public
share is checked before local shared-secret computation.

Tests include RFC 7748 published vectors, every clamping-bit combination,
noncanonical public aliases, little-endian reversal, malformed and low-order
points, wrong recovery types/scalars, every protected-record corruption and
valid-tag incorrect Finished messages. Full regression: **503 passed, 1 browser
test skipped** before the final 32 X25519 classical tests were added; the final
64-case X25519/P-256 classical run also passed after framing hardening.

## Extension 4a: TLS 1.3 / P-256 / AES-128-GCM

A genuine OpenSSL ↔ tlslite-ng capture passes the upload-to-inspector workflow,
with RSA-PSS CertificateVerify, both Finished messages, all 20 encrypted records,
and exact independently observed HTTP bytes. The local engine implements the
TLS 1.3 HKDF schedule, separate handshake/application epochs and directional
sequence numbers, encrypted ALPN, padding, NewSessionTicket, and bounded
KeyUpdate processing. Published RFC 8448 vectors independently validate the
schedule, keys, Finished and record authentication. KeyUpdate is currently
validated by constructed authenticated records, not a captured endpoint update.

The isolated application cannot read expected-output files, endpoint key logs,
private keys or fixture-generator code; its recovered plaintext still matches
the independent oracle. HRR, PSK, early data and client authentication remain
explicit unsupported cases. Certificate authentication currently supports RSA-PSS.

## Extension 4b: TLS 1.3 / X25519 / AES-128-GCM

The genuine baseline and unknown-share captures exercise RFC 7748 through the
same TLS 1.3 engine. A supplemental genuine endpoint capture sends KeyUpdate
between HTTP responses. All 21 protected records authenticate across the new
server epoch, both Finished messages verify, and the second HTTP response matches
its exact independent oracle. OpenSSL's updated traffic secret agrees with the
server endpoint's. The same capture passes the isolated runtime proof. This adds
genuine KeyUpdate evidence beyond the constructed record tests described above.

## Extension 4c: TLS 1.3 / P-256 / AES-256-GCM

The genuine 0x1302 capture uses 48-byte SHA-384 handshake, application and master
secrets. Independent endpoints agree on these values and exact HTTP streams.
The normal worker/API flow and isolation proof authenticate all 20 protected
records, both Finished messages and CertificateVerify. Independent static KATs
(cross-checked with tlslite-ng and cryptography) cover the complete schedule and
RSA-PSS-SHA256 over a SHA-384 transcript. These vectors are explicitly synthetic,
not claimed as published RFC examples or genuine capture evidence.

## Extension 4d: TLS 1.3 / X25519 / AES-256-GCM

A separate genuine 0x1302 X25519 capture passes exact endpoint-secret and HTTP
comparisons through the existing protocol implementation, with no production
code change. The API and isolated runtime verify both Finished messages and all
20 records. Unknown-share, wrong typed/scalar result, malformed parameters,
record corruption and epoch/KeyUpdate tests cover all four TLS 1.3 curve/cipher
combinations. TLS 1.3 AES coverage is complete for P-256 and X25519.
