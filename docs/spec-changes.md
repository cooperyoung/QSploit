# Specification review changes

- Prioritized the future-system end-to-end demonstration; Shor/Aer/IonQ evidence remains a separate milestone.
- Replaced manual fixture selection with a normal recovery action under explicit server demo configuration, automatic exact-modulus matching, and persistent provenance.
- Added a standalone problem-based timing function and `demo_delay_seconds=3`; no qubit-to-runtime fiction or fallback from real execution.
- Preserved TCP reconstruction, strict RSA validation, EMS transcript boundary, per-direction record counters, AES-GCM tags, both Finished checks, and all-or-nothing plaintext publication.
- Preserved one local FastAPI app, explicit dataclasses, a modulus-only spawned-worker boundary, h11, and inert previews.
- Corrected stale IonQ probability/count assumptions: inspect the installed provider and preserve actual distribution provenance.
- Will document verified platform requirements separately from assumptions. Quantum hardware requires algorithm/compiler/resource/adapter work, not merely an API-key switch.

Original attachment was read in full. The corrected working specification is `docs/implementation-spec.md`; the Downloads original is preserved.
