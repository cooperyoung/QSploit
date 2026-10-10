# Review / resume state

Updated 10 October 2026. The original project and all requested ordered protocol
extensions are implemented and validated. Nothing has been published or submitted.

- Workspace: `/Users/cooperyoung/Documents/ChatGPT/Qsploit`.
- Launch: `./run-demo.sh --port 8765`, then open `http://127.0.0.1:8765`.
- The launcher reads the ignored `.runtime-python` pointer to the persistent
  environment under `~/Library/Application Support/QSploit/venv`. The original
  `.venv` is preserved but some dependencies were offloaded by iCloud.
- Original baseline checkpoint: `8c207d2`. Complete protocol/runtime checkpoint:
  `8e10660`. Later commits finalize documentation and retained evidence.
- Final suite: **1,093 passed, one browser skip, two known dependency warnings**.
  Four pure Node controller tests pass. All 31 standalone isolation proofs and
  the installed-wheel 33-session/20-combination real HTTP workflow pass.
- All requested protocol paths are covered; see `support-matrix.md` for exact
  authentication/group/cipher limits. No known failing executed check remains.

## Demonstrate

Open demo capture → Recover session → wait three illustrative seconds → inspect
Parameters, Render and Readable. Protocol tour loads 33 genuine sessions covering
TLS 1.2 RSA/DHE/ECDHE and TLS 1.3 ffdhe2048/P-256/X25519. Demo mode substitutes
only exact-public-problem recovery; all later cryptography and HTTP run for real.
Use the separate quantum drawer for actual Aer 15/21 evidence. It did not crack
the realistic capture key.

## Outstanding external checks

1. Browser access was explicitly denied. Do not bypass it. After access is
   granted, run the opt-in browser test in `validation.md`, inspect the layout
   and address any real-browser findings.
2. Verify `qollab/` in the user's hosted account/free simulators. The companion
   has only been tested locally with injected Aer. No live IonQ job was run.
3. Record the prepared walkthrough, fill actual public links in `submission.md`,
   confirm registration/eligibility, and publish/submit only when authorized.
   Official deadline recorded: October 11, 2026, 4 p.m. Pacific.
4. Configured credentials, an explicit target and budget are needed for live
   IonQ execution. No full-scale RSA or FF/EC quantum DLP solver is claimed.

## Commands and assets

`validation.md` records exact commands, test output, installed-wheel evidence and
limitations. `dist/` holds the tested runtime wheel and final source archive.
`docs/evidence/` preserves results; `tests/fixtures/` holds independently observed
oracles. Generator scripts are development-only and require loopback capture
privileges; do not regenerate randomized fixtures merely to run the app.

Reliable complete test environment: `/private/tmp/qsploit-clean-runtime`.
Clean wheel-only proof environment: `/private/tmp/qsploit-release-runtime`.
Use external `PYTHONPYCACHEPREFIX` as documented to avoid offloaded bytecode.
Port 8000 belongs to another application and must be left untouched.
