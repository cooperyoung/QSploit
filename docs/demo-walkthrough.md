# QSploit — 2 minute 45 second demonstration

Before recording: run `./run-demo.sh --port 8765`; open http://127.0.0.1:8765. Use the 3-second delay. Hide unrelated applications, enlarge the browser to a readable desktop size, and keep the permanent demo banner visible. Check the browser acceptance steps manually because automated visual checks were blocked during development.

## 0:00–0:20 — The problem and promise

“Encrypted traffic can be stored now and attacked later. QSploit previews the software workflow for future cloud quantum computers: discover a session, recover the necessary secret, and inspect authenticated plaintext locally.”

Show the empty workspace and permanent demo label. “Today's hardware does not factor this RSA-2048 key. We replace exactly that missing computation with known test factors.”

## 0:20–0:45 — Real captured traffic

Click **Open demo capture** (or drag `qsploit/demo/qsploit-demo.pcap`). Show TLS 1.2, static RSA, the AES-128-GCM suite, RSA-2048 and EMS in the session details. Explain that TCP reconstruction and negotiated classification came from the uploaded PCAP.

Open public details briefly. “The recovery component receives only the modulus. The PCAP, certificate, ciphertext and TLS secrets stay here.”

## 0:45–1:15 — Recover and verify

Click **Recover session**. “This three-second wait is an illustrative presentation delay, not a quantum runtime estimate. We match the actual modulus to a controlled test key.”

Point to the provenance and four verification indicators: factor pair, client Finished, server Finished, and 19 authenticated records. “After the factors return, everything is real: RSA premaster recovery, the TLS key schedule, both Finished checks and AES-GCM authentication.”

## 1:15–1:50 — Inspect what was actually sent

Select the GET exchange. Show **Parameters**: `name=Cooper`, duplicate tags and an empty value. Show the response's **Render** view and captured `account_id=42` field inventory. “This is the selected captured response. Scripts and external resources are removed; we never replay the request.”

Select POST `/echo`. Show its request form parameters and the response's **Readable** JSON. Explain that the real response was chunked and gzip-compressed across records.

## 1:50–2:15 — Where quantum evidence fits

Open **Quantum validation lab**, select 21, and **Run on Aer**. Show factors `3 × 7` and execution provenance. “The same quantum component executes generic reversible order finding, then verifies factors from measurements. This is a separate small-number experiment; it did not crack our realistic capture.”

For the required Qollab recording segment, use the prepared companion's **Run** on the free local simulator once hosted verification is complete. Do not imply that a local injected-Aer test was a Qollab run.

## 2:15–2:45 — Honest failures and future architecture

Upload `qsploit/demo/mixed-discovery.pcap`. Point out ECDHE_RSA and TLS 1.3 as classified but unsupported for decryption. “RSA in a cipher name may mean authentication, not key transport.”

Close with: “The working classical pipeline is ready to consume verified future recovery results. Fault-tolerant algorithms, compilation and resource management will still evolve inside the quantum component. QSploit makes the consequence visible today without pretending today's quantum computers already do it.”

## Quick checks before publishing

- Run local tests and the actual browser smoke check.
- Run the Qollab companion on the required free simulator(s). One job per Run.
- Upload a 2–3 minute video with public, no-sign-in access.
- Add the real repo/project/video links to the submission draft. Disclose AI and prior-spec assistance.
- Do not describe the demo factors as a quantum simulation or the Aer result as RSA-2048 recovery.
