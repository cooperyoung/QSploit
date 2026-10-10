# QSploit · quantum companion

Prepared project files for Qollab: `main.py`, `arithmetic.py`, `postprocess.py`. The local full PCAP application stays in the parent repository. This companion demonstrates **measured small-number quantum order finding**, not recovery of the capture's RSA-2048 key.

Create a Qollab Qiskit project and add those three Python files. Choose the platform's built-in simulator first, leave modulus 15 and shots 256, and run. Qollab supplies `backend` and invokes `main` automatically. Do not add a provider, token or manual `main()` invocation. Modulus 21 uses 22 qubits and a deeper circuit. One invocation submits exactly one job; there is no hidden retry or known-factor fallback.

Console output records width/depth/operations, requested and actual shots (or exact probabilities), provider-reported backend/job identity, circuit hash, recovered factors and verification. For an IonQ simulator selected in Qollab, record the actual console result; noisy simulations may produce no factors. Do not claim platform or physical-device execution merely from a successful local test.

These files have been tested locally against a supplied Qiskit Aer backend for 15 and 21. No hosted Qollab or IonQ run has been performed and nothing has been published. Consult `docs/quantum-evidence.md` in the source repository for full evidence and limitations.

The generic arithmetic and measured-phase postprocessor are exact copies of `qsploit/quantum/arithmetic.py` and `postprocess.py`. After changing those source files, run `.venv/bin/python scripts/sync_qollab.py`; tests enforce byte equality.
