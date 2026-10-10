# Protocol extension checkpoint

Original working baseline: `8c207d2` (223 passed, one browser test skipped).
RSA AES-256 extension: `26832a6` (EMS/non-EMS, genuine authenticated captures).
DHE extension: `fc533a9` (ffdhe2048, AES-128/256, EMS/non-EMS).

P-256 is preserved at `2200f73`; X25519 also completes TLS 1.2 ECDHE.
The current assignment continues with TLS 1.3 ECDHE,
ChaCha20-Poly1305 and TLS 1.3 FFDHE, completing each path before the next.
See `support-matrix.md` for concrete evidence; do not infer completion from this list.

## Storage issue and reliable validation

macOS/iCloud offloaded some files under Documents, causing reads to stall.
This is independent of TLS implementation failures. The original `.venv` is
preserved but unreliable in its current offloaded state. A locked local Python
environment is installed at:

`/Users/cooperyoung/Library/Application Support/QSploit/venv`

`run-demo.sh` reads the ignored `.runtime-python` pointer to this interpreter;
on a fresh machine with no pointer, it uses the ordinary project `.venv`.
`QSPLOIT_PYTHON` can explicitly override either. Python bytecode is written to a
local temporary cache, avoiding offloaded source bytecode. The complete extra
validation environment also exists at `/private/tmp/qsploit-clean-runtime`.

```sh
./run-demo.sh --port 8765
PYTHONPYCACHEPREFIX=/private/tmp/qsploit-validation-pycache \
  /private/tmp/qsploit-clean-runtime/bin/python -m pytest -q
PYTHONPYCACHEPREFIX=/private/tmp/qsploit-validation-pycache \
  /private/tmp/qsploit-clean-runtime/bin/python scripts/prove_isolation.py --all
```

A scoped Foundation download request restored `tests/test_jobs.py`; it is now
readable and its original boundary tests can run again. Some old Git blobs may
still hydrate slowly. Use `git commit --quiet`: ordinary commit statistics can
stall reading old blobs after the commit has already succeeded; verify
`git log -1` before retrying. Generated `qollab/arithmetic.py` was restored
byte-for-byte from its canonical source.

Local browser access was explicitly denied earlier. Do not bypass that denial.
Browser acceptance remains unexecuted; the same upload/recover/inspect/preview
API workflow is exercised for every completed capture.
