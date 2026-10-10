# Completed protocol extension checkpoints

The ordered extension assignment is complete within the explicit support matrix.
Each path passed genuine capture, independent plaintext, negative, worker/API and
isolated-runtime checks before the next path began.

| Checkpoint | Completed path |
|---|---|
| `8c207d2` | Original RSA/AES-128 end-to-end demo; 223 passing tests |
| `26832a6` | TLS 1.2 RSA/AES-256 |
| `fc533a9` | TLS 1.2 DHE/AES-GCM |
| `2200f73` | TLS 1.2 P-256/AES-GCM |
| `8129a5d` | TLS 1.2 X25519/AES-GCM |
| `2fd7f0e` | TLS 1.3 P-256/AES-128 |
| `34535fd` | TLS 1.3 X25519/AES-128 and genuine KeyUpdate |
| `cc84ef3` | TLS 1.3 P-256/AES-256 |
| `cb1fc59` | TLS 1.3 X25519/AES-256 |
| `3ddc603` | TLS 1.2 DHE/ChaCha |
| `9a6d44f` | TLS 1.2 P-256/ChaCha and inspector race fixes |
| `be82599` | TLS 1.2 X25519/ChaCha |
| `652b87c` | TLS 1.3 P-256/ChaCha |
| `a29d52e` | TLS 1.3 X25519/ChaCha |
| `d79e7b4` | TLS 1.3 ffdhe2048/AES-128 |
| `9603110` | TLS 1.3 ffdhe2048/AES-256 |
| `8e10660` | TLS 1.3 ffdhe2048/ChaCha and complete mixed tour |

Final validation: 1,093 Python tests passed, one browser test skipped; four Node
controller tests passed; 31 isolated fixture proofs passed; the clean installed
wheel recovered all 33 tour sessions across 20 combinations over real localhost
HTTP. No production fixes remain pending. See [validation.md](validation.md) and
[resume.md](resume.md) for evidence, launch commands and external blockers.

The source is on branch `codex/qsploit-demo`. Some old Git objects were iCloud
offloaded; `git commit --quiet` avoids slow post-commit diff statistics. Confirm
`git log -1` before retrying an apparently stalled commit. Persistent runtime and
temporary validation environments are documented in `resume.md`. Local browser
access was denied; it must not be bypassed or reported as verified.
