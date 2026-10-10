# QSploit — prepared Qollab project page

Status: draft for review. Nothing is published or submitted. Replace the link placeholders only with actual reviewed public URLs.

**Short description:** A working preview of future quantum-assisted HTTPS recovery: real packet captures, explicit recovery provenance, authenticated TLS decryption, and safe local HTTP inspection.

**Suggested theme:** Quantum Unlocked, with Quantum Impact context. This is a future-systems demonstration and educational security tool, not a claim of present quantum advantage.

## What it explores

What happens after sufficiently capable quantum computation returns a cryptographic answer? QSploit connects that future computation to a tangible present-day workflow. A local application reconstructs TCP sessions from real PCAPs, identifies negotiated TLS cryptography, requests a supported recovery, and reconstructs authenticated HTTP requests/responses.

The main capture uses a controlled RSA-2048 TLS 1.2 static-RSA connection. An unmistakably labeled demo backend returns known factors matched to its actual public modulus. This is the **only** substituted step. Runtime code then recovers the RSA premaster, derives the negotiated EMS or ordinary master secret and traffic keys, verifies both Finished messages, authenticates every protected record, and reconstructs HTTP. No stored plaintext or session key is used by the application.

Additional genuine captures extend the same workflow to finite-field DHE and P-256/X25519 ECDHE, including a distinct TLS 1.3 HKDF engine and real key updates. Their demo recovery material is an algorithm-specific ephemeral scalar; it is never a stored traffic key. The support matrix records each verified version/group/cipher combination.

Captured response pages render inertly, with active content and linked resources removed. Query/form values come from recovered messages. The application never replays a request or invents missing server values.

## What runs on Qollab

The companion under `qollab/` executes the same generic reversible Fourier modular arithmetic and order-finding construction used by the local quantum component. It uses Qollab's supplied `backend`, submits exactly one circuit job, processes measured phases with continued fractions/LCM, and verifies nontrivial factors. Choose 15 or 21; default 15 keeps the experiment small.

These are toy mathematical inputs, separate from the captured RSA-2048 key. There are no dense permutation-matrix gates, precomputed orders, or hardcoded factor answers in the quantum solver. The local Aer execution has been validated; hosted Qollab and IonQ runs still need a final account-backed check before this page is published. No physical-QPU result is claimed.

## How to run

**Qollab:** copy the prepared companion files into a Python/Qiskit project so `main.py` is at its root. Choose the free built-in simulator and press Run. Qollab automatically calls the annotated `main`; do not add a second call or create a provider. For IonQ, use a small shot count and one job per Run; a deep noisy circuit may return an honest no-factor result. Record the actual platform check before submitting.

**Local capture app:** follow the repository README, then `./run-demo.sh --port 8765`. Click Open demo capture → Recover session → Parameters / Render / Readable. Only a PCAP is supplied by the user.

## Technical contribution

- Real OS packet captures with independent endpoint plaintext and test-only master-secret oracles.
- TCP gap/overlap/retransmission handling and negotiated TLS classification.
- Genuine TLS 1.2 RSA/DHE/ECDHE and TLS 1.3 decryption, version-specific schedules, both Finished and all protected records verified before publication.
- A typed public-problem recovery boundary: RSA factorization, finite-field DLP and curve-specific DLP, mathematically verified results, and explicit provenance.
- A separate problem-based timing function that labels the configured delay as illustrative.
- Generic small-number Shor execution and an offline-tested IonQ execution adapter.
- Safe HTTP rendering and a local inspector requiring no production capture or secret uploads.

## Why this is future-facing

The application consumes a verified mathematical answer regardless of backend. Future fault-tolerant hardware will likely require changes to circuit algorithms, compilation, resource management and provider execution, but not a rewrite of the TCP/TLS/HTTP pipeline. The DHE/ECDHE paths already consume typed discrete-log results and perform local shared-secret derivation. Only small-number RSA order finding has an implemented executed quantum solver; full-scale factoring and FF/EC DLP recovery remain explicitly substituted by demo fixtures.

Qubit count alone does not establish runtime. The current three-second delay is a presentation choice, not a scientific estimate. The small-number circuit execution is evidence about implementation correctness, not evidence of a practical RSA-2048 attack.

## Evidence and limits

See `docs/validation.md` for exact executed checks and `docs/quantum-evidence.md` for circuit counts, depths, versions and execution provenance. A separate process proves that runtime recovery reproduces independent HTTP hashes while test-oracle and key-file reads are denied.

See `docs/support-matrix.md` for tested combinations. Full handshakes, RSA certificate authentication, ffdhe2048/P-256/X25519 and HTTP/1.1 are the supported scope. Unknown recovery material, missing packets, conflicting overlaps and invalid authentication fail honestly. PSK/resumption, HelloRetryRequest, early data, client authentication, unlisted groups and hybrid/PQ exchanges remain unsupported. Authenticated HTTP/2 bytes remain available with an explicit decoding limitation. Browser execution/visual acceptance was blocked by the development environment's browser permission and remains a final manual/automated check.

## Originality, attribution and license

Built during the hackathon assignment with Codex AI assistance, starting from the user's supplied implementation specification. The workspace initially contained no application code. The specification was critically corrected before implementation. The code is newly implemented against the cited TLS RFCs and Beauregard-style arithmetic construction, using FastAPI, dpkt, cryptography, h11, nh3, Qiskit/Aer and the IonQ provider. Dependencies retain their own licenses; QSploit source and documentation use MIT.

This effort is supported by Qollab & IonQ.

## Links to fill after review

- Public Qollab project: **not yet published**
- Public MIT-licensed repository: **not yet published**
- Public 2–3 minute demonstration video: **not yet recorded/published**

The deadline in the official rules is October 11, 2026, 4:00 p.m. Pacific (19:00 ET). The submitter must confirm registration and node/track eligibility and accept the publication obligations personally. [Official rules](https://qollab.xyz/programs/hackathon/terms)
