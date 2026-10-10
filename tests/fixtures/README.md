# Fixture evidence

These PCAP files contain **genuine OS TCP packets** captured on macOS loopback (`lo0`, BSD NULL link type 0) by tcpdump 4.99.6. OpenSSL 3.6.2 `s_client` connected to a Python 3.12.10 `ssl` server linked to OpenSSL 3.6.2. `manifest.json` records versions, immutable SHA-256 hashes, byte sizes and packet counts. No packet headers or TLS records were manufactured for these captures.

| Capture | Content |
|---|---|
| `tls12-rsa-ems.pcap` | RSA-2048 TLS 1.2, `TLS_RSA_WITH_AES_128_GCM_SHA256`, EMS, two HTTP exchanges, bilateral close_notify |
| `tls12-rsa-noems.pcap` | Same TLS family with EMS explicitly disabled using OpenSSL `-no_ems` |
| `tls12-rsa-ticket.pcap` | Same TLS family with genuine NewSessionTicket issuance before server Finished |
| `tls12-rsa-aes256.pcap` | RSA-2048 TLS 1.2, `TLS_RSA_WITH_AES_256_GCM_SHA384` (`0x009d`), EMS, two HTTP exchanges and bilateral close_notify |
| `tls12-rsa-aes256-noems.pcap` | The AES-256/SHA-384 family with EMS explicitly disabled |
| `mixed-discovery.pcap` | Four connections: supported static RSA, TLS 1.2 ECDHE_RSA, TLS 1.3 X25519, ordinary cleartext TCP |
| `unknown-rsa.pcap` | Supported TLS family under another test key whose factors are deliberately not retained; must fail fixture lookup |
| `tls12-dhe-aes128-ems.pcap`, `tls12-dhe-aes128-noems.pcap` | Genuine DHE_RSA/ffdhe2048 with AES-128-GCM/SHA-256, both schedules |
| `tls12-dhe-aes256-ems.pcap`, `tls12-dhe-aes256-noems.pcap` | Genuine DHE_RSA/ffdhe2048 with AES-256-GCM/SHA-384, both schedules |
| `tls12-dhe-unknown.pcap` | Same DHE group and signing certificate with a fresh server public share; its private exponent is not retained and lookup must fail |
| `tls12-ecdhe-p256-aes128-ems.pcap`, `tls12-ecdhe-p256-aes128-noems.pcap` | Genuine ECDHE_RSA/P-256 with AES-128-GCM/SHA-256, both schedules |
| `tls12-ecdhe-p256-aes256-ems.pcap`, `tls12-ecdhe-p256-aes256-noems.pcap` | Genuine ECDHE_RSA/P-256 with AES-256-GCM/SHA-384, both schedules |
| `tls12-ecdhe-p256-unknown.pcap` | Same P-256 group and signing certificate with a fresh server public point whose private scalar is not retained |
| `tls12-ecdhe-x25519-aes128-ems.pcap`, `tls12-ecdhe-x25519-aes128-noems.pcap` | Genuine ECDHE_RSA/X25519 with AES-128-GCM/SHA-256, both schedules |
| `tls12-ecdhe-x25519-aes256-ems.pcap`, `tls12-ecdhe-x25519-aes256-noems.pcap` | Genuine ECDHE_RSA/X25519 with AES-256-GCM/SHA-384, both schedules |
| `tls12-ecdhe-x25519-unknown.pcap` | Fresh X25519 server share whose private encoding is deliberately not retained |
| `tls13-p256-aes128.pcap` | Genuine TLS 1.3 P-256, AES-128-GCM/SHA-256, RSA-PSS server CertificateVerify, one NewSessionTicket and two HTTP exchanges |
| `tls13-p256-unknown.pcap` | Same TLS 1.3 family with a fresh server public point whose private scalar is not retained |
| `tls13-x25519-aes128.pcap` | Genuine TLS 1.3 X25519, AES-128-GCM/SHA-256, RSA-PSS CertificateVerify, one NewSessionTicket and two HTTP exchanges |
| `tls13-x25519-unknown.pcap` | Same family with a fresh server public share whose private encoding is not retained |
| `tls13-x25519-aes128-keyupdate.pcap` | A genuine server KeyUpdate between HTTP responses; the second response uses the next application traffic secret |
| `tls13-p256-aes256.pcap` | Genuine TLS 1.3 P-256 with AES-256-GCM/SHA-384 (`0x1302`), 48-byte traffic-secret oracles and one NewSessionTicket |
| `tls13-p256-aes256-unknown.pcap` | Same AES-256 TLS 1.3 family with an unknown server public point |
| `tls13-x25519-aes256.pcap` | Genuine TLS 1.3 X25519 with AES-256-GCM/SHA-384 (`0x1302`), 48-byte traffic-secret oracles and one NewSessionTicket |
| `tls13-x25519-aes256-unknown.pcap` | Same AES-256 family with an unknown X25519 server share |
| `tls12-dhe-chacha-ems.pcap`, `tls12-dhe-chacha-noems.pcap` | Genuine DHE_RSA/ffdhe2048 with ChaCha20-Poly1305/SHA-256 (`0xccaa`), both TLS 1.2 schedules |
| `tls12-dhe-chacha-unknown.pcap` | Same ChaCha20 family with a fresh server share whose private exponent is not retained |
| `tls12-ecdhe-p256-chacha-ems.pcap`, `tls12-ecdhe-p256-chacha-noems.pcap` | Genuine ECDHE_RSA/P-256 with ChaCha20-Poly1305/SHA-256 (`0xcca8`), both TLS 1.2 schedules |
| `tls12-ecdhe-p256-chacha-unknown.pcap` | Same P-256 ChaCha20 family with an unknown server point |

The first exchange is `GET /profile?name=Cooper&tag=a&tag=b&empty=` and an HTML account page containing a real hidden `account_id=42` field. The second is `POST /echo` with URL-encoded parameters and a chunked, gzip JSON response. TLS application writes span multiple records. The HTML intentionally includes a script, link, external image and form to exercise inert rendering. None refers to a real user account.

`*.expected.json` files are **test-only oracles**. They contain exact bytes observed independently at both endpoints, plus an independently matching client/server master-secret keylog value. The generator never imports QSploit's capture parser, TLS decryptor or HTTP decoder. Runtime QSploit never reads these files. Temporary private-key files and endpoint keylogs are deleted after generation. The AES-256 captures use a separately generated test RSA key; their modulus/factors are appended alongside the original test key. The runtime recovery inputs are explicit demonstration registries: `qsploit/demo/factors.json` contains public test moduli and their two factors; `qsploit/demo/dlog.json` contains canonical public `(p,g,y,order)` tuples and their known test exponents. Neither registry includes HTTP plaintext, master secrets, certificate private keys or traffic keys.

`negotiation-vectors.json` is different evidence: its hello messages are explicitly **synthetic**, independently encoded per RFC 5246/8446 layouts, and only test public negotiation classification. Dummy key shares and binders are not interoperable cryptographic handshakes. They are never labeled as captured traffic.

To regenerate on macOS (requires OpenSSL 3.5+ and tcpdump capture permission):

```sh
.venv/bin/python scripts/make_fixtures.py
.venv/bin/python scripts/make_negotiation_vectors.py
```

On Linux use `--interface lo`; ensure tcpdump emits a supported capture link type. Use `--openssl /path/to/openssl` if needed. Generation is intentionally nondeterministic because handshakes, TCP sequence numbers and RSA keys are fresh. Re-run the full test suite after regeneration; the script updates hashes and endpoint evidence together. `--ticket-only` adds or refreshes the ticket case without changing the existing test key or main captures.

The runtime does not require tcpdump, OpenSSL command-line tools, keylogs, private-key files, Wireshark or tshark.

To add or refresh only the AES-256/SHA-384 fixtures while preserving every original capture and original test key:

```sh
.venv/bin/python scripts/make_fixtures.py --aes256-only
```

The targeted generator stages both new captures and independent endpoint oracles, verifies the negotiated cipher, then updates the test-factor registry and manifest. It checks every pre-existing capture outside that family still has the same SHA-256 hash. Temporary private keys and keylogs are removed before completion.

## DHE endpoint evidence

The DHE fixtures use an independent OpenSSL 3.6.2 client and tlslite-ng 0.8.2 server. The server's normal random exponent generator is passively observed: the wrapper calls the original `FFDHKeyExchange.get_random_private_key`, records its returned value and returns that same value. It never replaces the RNG, exponent, TLS transcript or packets. The server is explicitly configured with the RFC 7919 ffdhe2048 parameters and each generated public tuple is checked before publication. The RSA certificate only signs the ServerKeyExchange; its private key is deleted and its factors are not entered into the recovery registry.

OpenSSL's independent `CLIENT_RANDOM` keylog is checked against the server's session master secret, and plaintext is recorded and compared at both endpoints. Each test-only expected file retains the master oracle; the development keylog itself is deleted. Unknown-share generation deliberately discards its private exponent even though the named group and signing certificate match the supported captures.

```sh
# Install the optional fixture dependencies, then capture only the DHE family:
.venv/bin/python scripts/make_ephemeral_fixtures.py
```

This preserves all existing RSA-family capture bytes. `dlog.json` uses lowercase hexadecimal `p:g:y:order` keys and `{ "x": "hex" }` values. A different handshake normally has a different public share and therefore no known lookup result. The registry supplies only the missing mathematical recovery result; the application must still verify that `g**x mod p == y`, derive TLS keys, authenticate every protected record and verify both Finished messages.

## P-256 endpoint evidence

The P-256 fixtures use the same independent OpenSSL/tlslite endpoints and the same endpoint-byte and master-secret checks. Generation forces TLS 1.2, the `secp256r1` named group (23), uncompressed 65-byte public points and RSA PKCS#1 SHA-256 ServerKeyExchange signatures. The development observer calls the original `ECDHKeyExchange.get_random_private_key` and returns the original randomly generated `SigningKey`; it records the scalar without changing the key or TLS traffic. Cryptography independently derives the public point from that scalar before the fixture is accepted.

```sh
.venv/bin/python scripts/make_ephemeral_fixtures.py --family p256
```

This targeted command preserves all prior RSA and DHE captures. `qsploit/demo/ec_dlog.json` uses canonical lowercase `secp256r1:<uncompressed-public-point-hex>` keys and `{ "x": "hex" }` values. Only four known test scalars are retained; the fifth unknown-share capture deliberately has no recovery entry. Certificate private keys and temporary OpenSSL keylogs are deleted. Runtime recovery validates the scalar against the actual captured server point, then derives and authenticates the TLS traffic using the captured client point. No application bytes or TLS traffic secrets are in this recovery registry.

## X25519 endpoint evidence

The X25519 fixtures use the same independent TLS 1.2 endpoints, RSA signature and oracle checks. The group is forced to X25519 (29). Its observer copies the original 32 random bytes returned by tlslite's key sampler, then derives a public value using a separate bytearray copy: tlslite's multiplication clamps bytearrays in place, so inspecting the original directly could otherwise change the endpoint's return. The observer verifies the original bytes remain unchanged and returns that original object. Cryptography independently computes the same public value from the recorded bytes.

```sh
.venv/bin/python scripts/make_ephemeral_fixtures.py --family x25519
```

The EC registry adds canonical `x25519:<32-byte-public-u-hex>` keys and `{ "scalar": "32-byte-private-encoding-hex" }` values, preserving every P-256 entry and every earlier capture. These are RFC 7748 private input encodings, not ordinary big-endian integer exponents; the X25519 primitive applies clamping and little-endian interpretation. Only four known fixtures are retained, and the unknown-share capture must fail lookup. The application still derives the actual shared secret with the captured peer share and verifies all protected records and both Finished messages.

## TLS 1.3 endpoint evidence

The initial TLS 1.3 fixtures force P-256 and `TLS_AES_128_GCM_SHA256` (`0x1301`), with RSA-PSS SHA-256 CertificateVerify (`0x0804`). They contain complete fresh handshakes, no selected PSK, no early data, no client authentication and no HelloRetryRequest. The server issues one genuine NewSessionTicket using a temporary random ticket key; the generator never resumes it. The same passive P-256 key observer records only the server's independently random scalar for known-test recovery.

```sh
.venv/bin/python scripts/make_ephemeral_fixtures.py --family p256 --tls13
.venv/bin/python scripts/make_ephemeral_fixtures.py --family x25519 --tls13
```

OpenSSL's test-only keylog supplies both handshake traffic secrets, both application traffic secrets and the exporter secret in `tls13_secrets`. The application traffic secrets are independently checked against tlslite's session values before any files are published. The server's TLS 1.3 master secret is separately recorded as `tls13_master_secret_hex`; it is not mislabeled as a TLS 1.2 `CLIENT_RANDOM` master-secret oracle. Both endpoints also independently record and compare exact application bytes. Temporary endpoint keylogs, certificate private keys and ticket keys are deleted. The runtime registry contains only the known server scalar; none of these traffic secrets or expected HTTP bytes enters the runtime package.

The X25519 TLS 1.3 fixtures use the same schedule and endpoint checks, with the byte-preserving scalar observer described above. Each targeted command changes only its own TLS 1.3 family; prior TLS 1.2 captures and the other TLS 1.3 curve remain unchanged.

The separate KeyUpdate fixture invokes the server endpoint's normal `send_keyupdate_request(0)` after the first response. Its second response therefore uses a fresh application traffic key and resets that epoch's sequence number. OpenSSL's updated `SERVER_TRAFFIC_SECRET_N` oracle matches tlslite's updated session secret. Runtime recovery receives the same initial public problem and must process the authenticated KeyUpdate to read the second response.

```sh
.venv/bin/python scripts/make_ephemeral_fixtures.py --family x25519 --tls13 --key-update
```

This command creates only the supplemental capture and preserves both baseline TLS 1.3 captures.

The P-256 AES-256 fixture explicitly negotiates `TLS_AES_256_GCM_SHA384`, and the generator rejects any endpoint oracle whose secret length is not 48 bytes. Its RSA-PSS CertificateVerify uses SHA-256 (`0x0804`), independently of the cipher suite's SHA-384 transcript and key schedule. It retains the same real NewSessionTicket and HTTP exchange coverage.

```sh
.venv/bin/python scripts/make_ephemeral_fixtures.py --family p256 --tls13 --aes256
.venv/bin/python scripts/make_ephemeral_fixtures.py --family x25519 --tls13 --aes256
```

This targeted command preserves every earlier AES-128 capture and registry entry.

## TLS 1.2 ChaCha20-Poly1305 endpoint evidence

The DHE ChaCha20 fixtures force `TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256` (`0xccaa`) with the same exact ffdhe2048 parameters, RSA signature, passive exponent observer and independent endpoint master-secret/HTTP checks as the AES DHE cases. EMS and non-EMS are generated separately. Runtime decryption must apply the TLS ChaCha20 record nonce construction and authenticate the actual records; no ciphertext is converted from another cipher.

```sh
.venv/bin/python scripts/make_ephemeral_fixtures.py --family dhe --chacha
.venv/bin/python scripts/make_ephemeral_fixtures.py --family p256 --chacha
```

The command stages two known captures and an unknown-share capture, then appends only the two observed test exponents to the DHE registry. Every earlier capture and registry entry is preserved.

The P-256 variant forces `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` (`0xcca8`) and uses the unchanged ECDH scalar observer and EC registry. It independently verifies both TLS 1.2 schedules in exactly the same endpoint harness.
