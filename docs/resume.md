# Review / resume checkpoint

Updated 10 October 2026. The local project is implemented, packaged, and tested. No external publish/submission has occurred.

## Working state

- Local source: `/Users/cooperyoung/Documents/ChatGPT/Qsploit`.
- Python: `.venv/bin/python` (3.12.10); all extras installed; dependency lock committed with project.
- Run: `./run-demo.sh --port 8765`. The default port 8000 belongs to an unrelated existing Python process; do not stop it.
- Uvicorn was left running on 127.0.0.1:8765 for review. If unavailable later, use the run command above.
- Core loop: upload `qsploit/demo/qsploit-demo.pcap` → ordinary Recover session → 3-second labeled demo recovery → 19 verified protected records / both Finished → two real HTTP exchanges.
- Final suite: 223 passed, 1 browser test skipped, 2 dependency warnings. Isolation proof and clean runtime-only installed-wheel roundtrip pass. No known failing executed tests.

## Next steps that require access or user review

1. Local browser access was denied by the browser tool. Do not circumvent that denial. After the user grants browser access, run the explicit browser acceptance command in `validation.md`, inspect the layout and fix actual browser findings.
2. Import prepared `qollab/` into the user's account and verify one free-simulator run, including the required IonQ simulator compatibility. No such hosted run has happened. It must not be reported as passed based on local injected-Aer tests.
3. Record the walkthrough in `demo-walkthrough.md` once browser behavior is checked. No actual video has been recorded.
4. Review `submission.md`, fill real repo/project/video links, disclose prior specification and Codex assistance, and publish/submit only with user authorization. Deadline per official rules: October 11, 2026, 4 p.m. Pacific.
5. Live IonQ adapter execution requires an authorized account/key, explicit target and bounded enablement. No credentials were configured. Do not spend cloud credits or invent access.

## Useful verification commands

```sh
.venv/bin/python -m pytest -q
.venv/bin/python scripts/prove_isolation.py
.venv/bin/python -m qsploit.quantum --modulus 15
.venv/bin/python -m qsploit.quantum --modulus 21
.venv/bin/uv build --offline --cache-dir .uv-cache
```

Fixture regeneration is development-only, needs tcpdump/loopback capture privileges and OpenSSL >=3.5, and replaces randomized fixture bytes/factors. Existing fixtures are already genuine and validated; do not regenerate merely to run the demo. See `tests/fixtures/README.md`.
