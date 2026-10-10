# Qollab × IonQ: verified requirements and packaging decisions

Checked 10 October 2026 against the live official Qollab pages in the browser and official IonQ documentation. Search initially could not extract Qollab's rendered pages; direct browser inspection succeeded. No account was created, no terms were accepted, and no project was published.

## Submission requirements that affect this project

The official [how-it-works page](https://qollab.xyz/programs/hackathon/how-it-works) and [rules](https://qollab.xyz/programs/hackathon/terms) require a public runnable Qiskit project on Qollab, MIT licensing (including supporting outside repos), a descriptive project page, and a public 2–3 minute video that opens without sign-in. Judges run the project on a free simulator. IonQ hardware versus simulator results do not add or subtract points, but a failed run matters.

Build window: **October 9, 2026, 4:00 p.m. Pacific through October 11, 2026, 4:00 p.m. Pacific** (official 19:00 ET times). Registration had closed on October 8. The user's registration, node, team, age and track eligibility were not inspected or verified. Team size is one to four.

The rubric names novelty/creativity, technical execution, impact potential, and documentation quality. No numeric weights were visible. AI assistance and prior work are allowed with attribution/disclosure; judging focuses on work added during the build window. A project must go beyond an unchanged tutorial. QSploit's contribution is the real authenticated TLS-to-HTTP workflow and explicit recovery boundary, alongside measured generic order finding.

The rules require accessibility practices, project availability for 12 months, and the attribution **“This effort is supported by Qollab & IonQ”**. The prepared files include the attribution and MIT license. Publishing and accepting obligations remain the user's actions after review.

## Runtime facts

[Qollab runtime documentation](https://qollab.xyz/learn/docs/runtime-environment) establishes:

- Code runs in the browser through Pyodide; this is not arbitrary Python web-server hosting.
- A top-level `main.py` creates a Python project. A top-level `index.html` plus `main.js` creates a JS/Qiskit project.
- The selected QPU is injected as the global `backend`. Do not construct `IonQProvider` inside a Qollab project.
- IonQ accepts **one job per Run**. Local simulators allow multiple jobs. QSploit's companion calls `backend.run` exactly once.
- A one-line, top-level `def main(...)` with supported typed scalar parameters is called automatically; do not call it again.
- Qiskit is preinstalled; docs currently name `>=2.5.2,<3.0.0`. Additional packages need a compatible Pyodide build or pure Python wheel.
- Network access is GET/OPTIONS only and constrained by CORS. No durable cross-run storage. Project files are limited to 100, each at most 2 MB.

The [compute-backend page](https://qollab.xyz/learn/docs/compute-backends) lists a 24-qubit built-in browser simulator, 25-qubit AWS Braket local simulator, and free IonQ remote noise-model simulators with 25 or 29 qubit ceilings. Hardware consumes credits; live availability comes from the selection dialog. These are ceilings, not proof a deep circuit will finish or produce a useful noisy result.

## Packaging decision

Keep PCAP/TLS/HTTP in the local FastAPI app. Publishable quantum companion files in `qollab/` use the same arithmetic and measured postprocessing with the platform's backend. This follows the official allowance for a public, MIT-licensed external frontend/backend supporting a runnable Qollab project. It avoids sending captures or recovered secrets to a remote service.

The companion is prepared and tested locally through the documented injection contract. It has **not** been run inside Qollab or submitted to an IonQ remote simulator. Consequently, platform eligibility is not claimed as complete. A logged-in final platform run and publication, plus a public video link and outside repo link, remain required before submission.

## IonQ facts and limits

[IonQ's Qiskit guide](https://docs.ionq.com/sdks/qiskit/index) describes cloud account/API-key access, the provider, backend selection and QIS transpilation. Qiskit 2 requires a compatible provider (tested here: Qiskit 2.5.2 / qiskit-ionq 1.1.1). Guidance recommends QIS optimization level 0 or 1. Listing/constructing a provider is not proof of target permissions; the installed provider may also request backend metadata, so no provider is initialized merely to show a capability badge.

Results preserve counts versus probabilities, target, execution category, circuit hash, gate count/depth, shots when real counts exist, and job IDs. Exact simulator probabilities are not rounded into fictional shots. Live IonQ access is unverified because no credentials or explicit target were configured. No cryptographic-scale hardware runtime or required physical-qubit estimate is asserted.
