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
