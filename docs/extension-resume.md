# Protocol extension checkpoint

Original working baseline: `8c207d2` (223 passed, one browser test skipped).
RSA AES-256 extension: `26832a6` (EMS/non-EMS, genuine authenticated captures).
DHE extension: `fc533a9` (ffdhe2048, AES-128/256, EMS/non-EMS).

P-256 TLS 1.2 is preserved at `2200f73`; X25519 TLS 1.2 at `8129a5d`.
TLS 1.3 P-256/AES128 is preserved at `2fd7f0e` (607 passed, one browser skip).
TLS 1.3 X25519/AES128 and genuine KeyUpdate are preserved at `34535fd`.
Its full run had 651 passes and one outdated unsupported-status expectation;
the expectation was corrected for newly supported TLS 1.3, and all 16 API tests
then passed. Genuine KeyUpdate isolation verifies 21 protected records.

TLS 1.3 P-256/AES256 is at `cc84ef3` (706 passed, one browser skip).
TLS 1.3 X25519/AES256 is at `cb1fc59` (244 targeted passes, isolation verified).
TLS 1.2 DHE ChaCha is at `3ddc603` (780 passed, one browser skip).
TLS 1.2 P-256 ChaCha and inspector race fixes are at `9a6d44f`
(91 targeted Python passes, four pure Node controller tests, isolation verified).

TLS 1.2 X25519 ChaCha is at `be82599` (117 targeted passes, isolation verified).
Current gate: TLS 1.3 P-256 ChaCha passes 287 integrated tests and isolation;
independent vector confirmation is pending before checkpoint. Next: TLS 1.3
X25519 ChaCha, then TLS 1.3 ffdhe2048 (AES128, AES256, ChaCha).
Complete one path with genuine capture/negative/API proof before next; checkpoint.
No DLP quantum solver is being implemented; only unavailable recovery is simulated.

The root owns app/UI/docs/mixed-tour integration; classical owns TLS engines;
fixtures owns genuine endpoint generators/assets/API per-path tests; quantum
owns independent vectors/review. Mixed tour builder and two passing API/provenance
tests exist; rebuild the tour after all protocol gates. Final work also includes
full-suite/isolation/wheel verification, latest server restart, precise documentation
and local Git checkpoint. Browser access remains denied; do not bypass it.

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
