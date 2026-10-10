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
| TLS 1.2 | DHE | AES-GCM | Detection only; next extension |
| TLS 1.2 | ECDHE P-256, X25519 | AES-GCM | Detection only; planned after DHE |
| TLS 1.3 | ECDHE P-256, X25519 | AES-GCM | Detection only; planned after TLS 1.2 ECDHE |
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
