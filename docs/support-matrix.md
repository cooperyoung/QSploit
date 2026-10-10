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
| TLS 1.2 | DHE_RSA ffdhe2048 | ChaCha20-Poly1305 / SHA-256 | **Verified**: EMS and non-EMS |
| TLS 1.2 | ECDHE_RSA P-256, X25519 | ChaCha20-Poly1305 / SHA-256 | **Verified**: EMS and non-EMS |
| TLS 1.3 | ECDHE P-256, X25519 | ChaCha20-Poly1305 / SHA-256 | **Verified**: full handshake and exact HTTP |
| TLS 1.3 | FFDHE2048 | AES-128-GCM | **Verified**: full handshake, fixed-width shared secret and exact HTTP |
| TLS 1.3 | FFDHE2048 | AES-256-GCM / ChaCha20-Poly1305 | Pending the next sequential gates |
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

## Extension 5a: TLS 1.2 DHE / ChaCha20-Poly1305

Genuine 0xccaa EMS/non-EMS captures reproduce independent master secrets and HTTP
through the actual worker, both Finished checks and all 19 protected records.
The 88-byte key block contains two 32-byte keys and two 12-byte IVs; nonce XOR
uses the full 64-bit sequence, with no explicit nonce bytes in the record.
Independent RFC 8439 primitive and cross-implementation TLS record vectors cover
the changed layout. AES-GCM regression coverage remains intact. There is no
standard static-RSA ChaCha suite; none is invented.

## Extension 5b: TLS 1.2 P-256 / ChaCha20-Poly1305

The 0xcca8 EMS/non-EMS captures reuse the verified P-256 shared-secret path and
ChaCha record layout. Genuine endpoint masters and both HTTP messages match
through the worker/API and isolated runtime; both Finished and all 19 records
verify. Signed-parameter mutation, wrong recovery, valid-tag wrong Finished,
record corruption, fragmentation and unknown-share tests pass.

## Extension 5c: TLS 1.2 X25519 / ChaCha20-Poly1305

Separate EMS/non-EMS and unknown-share captures validate the X25519/0xcca8
combination without production changes. The ordinary worker/API and isolated
runtime recover exact independent HTTP, both Finished messages and all 19
protected records. The complete ChaCha negative suite now covers DHE, P-256
and X25519, while the X25519 encoding/AES regressions remain passing.

## Extension 5d: TLS 1.3 P-256 / ChaCha20-Poly1305

A genuine 0x1303 capture verifies the SHA-256 HKDF schedule with 32-byte ChaCha
keys, encrypted handshake, CertificateVerify, both Finished messages and all 20
protected records. Independent endpoint traffic secrets and exact HTTP agree
through the same API. Algorithm selection is explicit by cipher suite; it does
not confuse AES-256 and ChaCha merely because both use a 32-byte key.

## Extension 5e: TLS 1.3 X25519 / ChaCha20-Poly1305

The last ECDHE cipher combination passes a separate genuine known/unknown-share
capture gate. Its independent SHA-256 traffic secrets and exact HTTP match the
ordinary worker/API result; CertificateVerify, both Finished and all 20 protected
records authenticate. No production change was needed beyond the existing
X25519 and TLS 1.3 ChaCha implementations. All requested ECDHE AEAD combinations
are now covered; finite-field TLS 1.3 is the remaining protocol family.

## Extension 6a: TLS 1.3 FFDHE2048 / AES-128-GCM

A genuine known-share capture passes the normal upload, spawned finite-field
recovery, inspector and isolated-runtime flow. Independent endpoint secrets and
HTTP match; both Finished, CertificateVerify and all 20 protected records verify.
A separate unknown-share capture fails recovery honestly. Wire validation checks
exact 256-byte shares, offered groups, approved parameters and subgroup membership.
An independent OpenSSL-crosschecked leading-zero vector proves TLS 1.3 retains
all 256 shared-secret bytes while TLS 1.2 strips the leading zero. The integrated
FFDHE/API/provenance gate passed 89 tests; the classical regression passed 258.
