# Quantum evidence and boundary

Verified locally on 10 October 2026 with Python 3.12, Qiskit 2.5.2, Qiskit Aer 0.17.2 and qiskit-ionq 1.1.1. See `uv.lock` for the reproducible environment.

## Two separate demonstrations

The main PCAP demonstration uses `method=fixture_lookup`, `execution=none`. Its exact-modulus lookup returns the isolated test RSA factors after the configured illustrative delay. It runs no quantum circuit. All subsequent TLS recovery, key derivation and authentication happen in the real classical pipeline.

The separate quantum experiment executes generic modular-arithmetic order-finding circuits. It derives candidate orders from measured phase-register outcomes through integer continued fractions and bounded LCM combinations, verifies each order with modular exponentiation, then verifies the resulting nontrivial factor pair. It never reads the capture, factor fixture or expected plaintext.

## Actual Aer execution

| Public modulus | Verified factors | Qubits | Compiled operations | Compiled depth | Measured shots |
|---|---|---:|---:|---:|---:|
| 15 | 3 × 5 | 18 | 3,291 | 2,343 | 512 |
| 21 | 3 × 7 | 22 | 26,335 | 18,169 | 512 |
| 35 | 5 × 7 | 26 | 48,764 | 33,285 | 512 |

All three used the same builder and public base 2. The 35 experiment explicitly raised the local qubit limit from 22 to 26; the presentation UI retains the 22-qubit limit. Local wall times observed were approximately 1.5 s, 1.9 s and 7.7 s, including compilation. These are measurements of this computer running Aer, **not estimates for cryptographic recovery or future hardware**.

Aer uses its matrix-product-state simulator with one CPU thread, no maximum bond-dimension cap, and its default numerical truncation threshold `1e-16`. Simulation samples actual circuit output using fixed seed 23 for reproducibility. No factors or orders are encoded into that seed. Circuit construction is polynomial in the bit length; simulation is not thereby polynomial for arbitrary inputs.

QASM hashes of the executable Aer circuits:

```text
N15  41c0065890c856e3aba372bcd67aefd2c88724dc49bd3d706fbc8179da89237a
N21  c1eb2958042514875a318c410145a4be6dfef7b7afe6416227d9e132aace1f05
N35  eb426c68db52fa0d70ed2b9209b51c0ba4e6f6fb69474dabe3198232e34e3c29
```

Reproduce the presentation experiments:

```sh
.venv/bin/python -m qsploit.quantum --modulus 15
.venv/bin/python -m qsploit.quantum --modulus 21
.venv/bin/python -m pytest tests/test_quantum.py -q
```

The targeted quantum suite passed **48 tests** at the initial evidence checkpoint. It verifies exact modulus lookup, zero/configured timing, wrong factors, resource preflight, malformed measurements, failure without fallback, exhaustive small modular-addition inputs and controls, coherent multiplication/inverse/scratch checks through modulus 21, actual Aer factorization, and Qollab companion one-job local execution for both presentation moduli. See the final repository validation record for any later test additions.

The Fourier construction follows the modular-reduction and uncomputation approach in [Beauregard's paper](https://arxiv.org/abs/quant-ph/0205095), with a full coherent phase register. Width is `4*n+2`, not the paper's recycled-control `2*n+3`. There are no dense permutation matrices, enumerated truth tables, precomputed orders, or special factor-15 gates. A realistic RSA-2048 input is rejected before building a circuit: this implementation alone would require 8,194 logical qubits, far beyond its configured limit, before considering gate count, precision or fault tolerance.

## IonQ: implemented, offline-tested, no hosted execution claim

No IonQ API key was configured, so **no IonQ simulator job and no physical IonQ QPU job ran**. Offline tests compile the generic circuit into an IonQ-supported universal QIS subset with metadata mocked. Contract tests exercise provider status, exact probabilities, timeout cancellation and failure handling with explicitly fake jobs. These tests establish adapter behavior, not credentials, target access, remote execution or hardware success.

Current [IonQ Qiskit documentation](https://docs.ionq.com/sdks/qiskit/index) recommends QIS transpilation optimization level 0 or 1 and distinguishes ideal-simulator probabilities from client-sampled counts. The installed [provider APIs](https://qiskit-community.github.io/qiskit-ionq/apidocs/backends.html) were inspected and used directly. The adapter keeps ideal simulator probabilities as probabilities with `actual_shots=None`; QPU output uses counts and recorded shots. It reports actual provider status and never invokes the demo timer.

The installed provider constructor may fetch public backend metadata. A first offline metadata/compilation probe encountered a sandbox DNS failure and submitted no job; final offline tests explicitly mock that lookup. The app gates provider construction behind all of:

- `IONQ_API_KEY` configured by the operator.
- An explicit `QSPLOIT_IONQ_TARGET` selected from the operator's accessible targets.
- `QSPLOIT_IONQ_ALLOW_SUBMIT=1`, authorizing the configured bounded submission.

Use the standalone CLI with `--backend ionq_simulator` or `--backend ionq_qpu` only after target/account access and costs are understood. A default CLI experiment authorizes one attempt, 512 shots, and the requested timeout. Provider cancellation is best effort; a timeout does not prove a remote job stopped. No credential appears in logs or returned error details.

## Qollab companion

`qollab/main.py`, `qollab/arithmetic.py`, and `qollab/postprocess.py` form the prepared Qollab project. The two core files are exact copies of the tested local implementation, regenerated by `scripts/sync_qollab.py`. Main uses Qollab's supplied global backend and submits exactly one circuit per invocation; it does not construct a provider or carry any capture/test factors/TLS secrets. It prints measured provenance and verified small factors or an honest failure.

Both 15 and 21 were tested locally with a supplied Aer backend using the same companion entry point. **The project has not been uploaded, published, submitted, or executed on Qollab.** That requires the user's platform account and explicit external publication step. The provided project follows the verified [runtime contract](https://qollab.xyz/learn/docs/runtime-environment); actual hosted compatibility and performance remain an external validation milestone. Noisy simulated devices may fail at these circuit depths.

## Future integration promise

Only an `RSAProblem(n)` crosses into the engine. Verified factors plus provenance cross back. Future fault-tolerant execution may require different arithmetic, compilation, scheduling, resource models and provider adapters, while preserving capture parsing, local TLS/HTTP processing and the inspector. No endpoint/API-key-only migration is promised. DHE/ECDHE require new typed problem/result variants and actual discrete-log algorithms; they are not implemented placeholders.
