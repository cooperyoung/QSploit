# Specification review changes

The original attachment was read in full; the Downloads original is preserved.
The corrected working specification is [implementation-spec.md](implementation-spec.md).
Its baseline is preserved in Git before the later requested protocol extensions.

- Made the primary acceptance gate genuine PCAP → automatic demo recovery → real
  authenticated TLS → exact HTTP. Toy Shor and a live IonQ job are separate evidence.
- Replaced manual factor/private-key inputs with exact public-problem lookup,
  server-selected demo mode, a persistent label and explicit provenance.
- Separated a configurable problem-based illustrative delay from recovery and TLS.
  No qubit-count-to-runtime shortcut or silent fallback from real execution.
- Kept one local FastAPI app and explicit data structures; removed proposed
  scaffolding and duplicated interface sketches that no longer matched the code.
- Extended the original modulus-only boundary with precise FF/EC discrete-log
  problem/result types. Public client shares, captures and traffic secrets stay local.
- Specified TCP gaps/conflicts/retransmission handling, negotiated classification,
  strict RSA padding, EMS and transcript ordering, directional sequence counters,
  signed ephemeral parameters, all AEAD tags and both Finished messages.
- Separated TLS 1.3 HKDF, encrypted handshake, CertificateVerify, key epochs,
  padding and KeyUpdate from TLS 1.2. Distinguished X25519 encoding/clamping from
  P-256, and TLS 1.2 minimal-width DH secrets from TLS 1.3 fixed-width secrets.
- Kept PSK, hybrid/PQ and incomplete captures honest; HTTP decoding failure no
  longer implies TLS authentication failure. Captured HTML is inert and isolated.
- Added per-protocol genuine captures, independent endpoint oracles, negative
  tests, isolation proofs, mixed-capture validation and sequential Git checkpoints.
- Verified Qollab's browser runtime and submission requirements separately from
  assumptions; prepared a runnable quantum companion alongside the local app.
- Preserved actual counts versus simulator probabilities and precise Aer/IonQ
  execution provenance. Future hardware may require algorithm/compiler/resource/
  adapter changes; switching an API key is not promised to suffice.

The support matrix records completed implementations and remaining limitations;
the specification describes acceptance requirements, not claims of passing tests.
