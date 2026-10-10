const $ = (s) => document.querySelector(s);
const state = {
  config: null,
  capture: null,
  selected: null,
  exchange: null,
  tabs: { request: "raw", response: "raw" },
  job: null,
  busy: false,
  quantumBusy: false,
};
const node = (tag, text, cls) => {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
};
const error = (e) => {
  $("#error").textContent = e.message || String(e);
  $("#error").hidden = false;
};
async function api(path, options = {}) {
  const r = await fetch(path, {
    ...options,
    headers: { "X-QSploit": "1", ...options.headers },
  });
  if (!r.ok) {
    let d;
    try {
      d = await r.json();
    } catch {
      d = {};
    }
    throw new Error(d.error?.message || `Request failed (${r.status}).`);
  }
  return r.status === 204 ? null : r.json();
}
const text = (b64, charset = "utf-8") => {
  const bytes = Uint8Array.from(atob(b64 || ""), (x) => x.charCodeAt(0));
  try {
    return new TextDecoder(charset || "utf-8").decode(bytes);
  } catch {
    return new TextDecoder().decode(bytes);
  }
};
const bytes = (b64) => atob(b64 || "").length;
const formatSize = (n) => (n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`);
const kex = (k) =>
  ({
    rsa_transport: "Static RSA",
    ecdhe: "ECDHE",
    dhe: "DHE",
    hybrid_pq: "Hybrid / PQ",
    pq: "Post-quantum",
    psk: "PSK",
    psk_ecdhe: "PSK + ECDHE",
    psk_dhe: "PSK + DHE",
    unknown: "Unknown",
    other: "Other",
  })[k] || k;
const statusLabel = (s) =>
  ({
    not_started: "Not recovered",
    running: "Recovering…",
    verified: "Verified",
    failed: "Failed",
  })[s] || s;
function showNotice(element, messages) {
  element.replaceChildren(...messages.map((x) => node("p", x.message || x)));
  element.hidden = !messages.length;
}
function busy(on) {
  state.busy = on;
  for (const id of ["#recover", "#clear", "#replace", "#load-demo"])
    $(id).disabled = on;
  $("#file").disabled = on;
  $("#run-quantum").disabled = on || state.quantumBusy || !state.aer;
}
async function upload(file) {
  if (state.busy || state.quantumBusy) return;
  $("#error").hidden = true;
  busy(true);
  $("#load-demo").textContent = "Reading TCP / TLS…";
  try {
    state.capture = await api("/api/captures", {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: file,
    });
    state.filename = file.name || "qsploit-demo.pcap";
    state.selected = null;
    state.job = null;
    $("#dropzone").classList.add("compact");
    renderCapture();
    const first =
      state.capture.sessions.find((s) => s.recovery_modes.length) ||
      state.capture.sessions.find((s) => s.protocol === "tls") ||
      state.capture.sessions[0];
    if (first) await selectSession(first.id);
  } catch (e) {
    error(e);
  } finally {
    busy(false);
    $("#load-demo").textContent = "Open demo capture ↗";
    if (state.selected) renderDetail();
  }
}
$("#file").addEventListener("change", (e) => {
  if (e.target.files[0]) upload(e.target.files[0]);
  e.target.value = "";
});
$("#replace").onclick = () => $("#file").click();
$("#load-demo").onclick = async () => {
  try {
    const r = await fetch("/api/demo-capture");
    if (!r.ok) throw new Error("Bundled capture unavailable.");
    const b = await r.blob();
    await upload(new File([b], "qsploit-demo.pcap"));
  } catch (e) {
    error(e);
  }
};
for (const event of ["dragenter", "dragover"])
  $("#dropzone").addEventListener(event, (e) => {
    e.preventDefault();
    $("#dropzone").classList.add("drag");
  });
for (const event of ["dragleave", "drop"])
  $("#dropzone").addEventListener(event, (e) => {
    e.preventDefault();
    $("#dropzone").classList.remove("drag");
    if (event === "drop" && e.dataTransfer.files[0])
      upload(e.dataTransfer.files[0]);
  });
$("#clear").onclick = async () => {
  try {
    await api(`/api/captures/${state.capture.id}`, { method: "DELETE" });
    state.capture = null;
    state.selected = null;
    state.job = null;
    $("#workspace").hidden = true;
    $("#dropzone").classList.remove("compact");
    $("#error").hidden = true;
  } catch (e) {
    error(e);
  }
};
$("#all-tcp").onchange = renderCapture;
function renderCapture() {
  if (!state.capture) return;
  $("#workspace").hidden = false;
  $("#capture-label").textContent =
    `${state.filename || "Active capture"} · ${formatSize(state.capture.size_bytes)} · ${state.capture.packets_seen} packets`;
  $("#session-count").textContent = state.capture.sessions.length;
  showNotice($("#capture-warnings"), state.capture.warnings);
  const rows = $("#session-rows");
  rows.replaceChildren();
  const sessions = state.capture.sessions.filter(
    (s) => $("#all-tcp").checked || s.protocol === "tls",
  );
  $("#no-sessions").hidden = !!sessions.length;
  for (const s of sessions) {
    const row = node("tr");
    row.tabIndex = 0;
    row.setAttribute(
      "aria-label",
      `Select session ${s.id}, ${s.sni || s.server || "unknown"}`,
    );
    if (s.id === state.selected) row.className = "selected";
    row.onclick = () => selectSession(s.id).catch(error);
    row.onkeydown = (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        selectSession(s.id).catch(error);
      }
    };
    const endpoint = node("td");
    endpoint.append(
      node("span", s.sni || s.server || s.endpoint_b || s.id, "session-name"),
      node(
        "span",
        `${s.client || s.endpoint_a || "?"} ${s.client ? "→" : "↔"} ${s.server || s.endpoint_b || "?"}`,
        "endpoint",
      ),
    );
    row.append(
      endpoint,
      node(
        "td",
        s.tls_version ? `TLS ${s.tls_version}` : s.protocol.toUpperCase(),
      ),
      node("td", s.cipher_suite_name || "—", "suite"),
      node("td", kex(s.key_exchange)),
    );
    const eligible = node("td");
    eligible.append(
      node(
        "span",
        s.recovery_modes.length
          ? "Demo available"
          : s.implementation === "supported"
            ? "No matching backend"
            : "Unsupported",
        `badge ${s.recovery_modes.length ? "demo" : ""}`,
      ),
    );
    const status = node("td");
    status.append(
      node(
        "span",
        statusLabel(s.decrypt_state),
        `badge ${s.decrypt_state === "verified" ? "good" : s.decrypt_state === "failed" ? "bad" : s.decrypt_state === "running" ? "blue" : ""}`,
      ),
    );
    row.append(eligible, status);
    rows.append(row);
  }
}
function selected() {
  return state.capture?.sessions.find((s) => s.id === state.selected);
}
async function selectSession(id) {
  state.selected = id;
  state.exchange = null;
  state.job = null;
  $("#inspector").hidden = true;
  $("#job-panel").hidden = true;
  renderCapture();
  renderDetail();
  const job = await api(`/api/sessions/${id}/job`);
  if (state.selected !== id) return;
  if (job) {
    state.job = job;
    renderJob(job);
    if (["running", "queued"].includes(job.state)) {
      busy(true);
      poll(job.id, false).catch(error);
    }
  }
  if (selected().decrypt_state === "verified") await loadExchanges();
}
function renderDetail() {
  const s = selected();
  if (!s) return;
  $("#session-detail").hidden = false;
  $("#session-title").textContent = s.sni || s.server || `Session ${s.id}`;
  $("#session-description").textContent =
    `${s.client || s.endpoint_a || "Unknown endpoint"} ${s.client ? "→" : "↔"} ${s.server || s.endpoint_b || "Unknown endpoint"}`;
  const values = [
    ["Protocol", s.tls_version ? `TLS ${s.tls_version}` : "Unknown"],
    ["Key exchange", kex(s.key_exchange)],
    ["Public key", s.rsa ? `${s.rsa.bits}-bit RSA` : s.selected_group_name || "—"],
    [
      "Master secret",
      s.ems === true
        ? "Extended (EMS)"
        : s.ems === false
          ? "Standard"
          : "Unknown",
    ],
    ["Application", s.alpn || "Not negotiated"],
    [
      "Quantum assessment",
      s.vulnerability === "shor_applicable"
        ? "Shor applicable · future resources"
        : s.vulnerability === "shor_insufficient"
          ? "Shor alone insufficient"
          : "Unknown",
    ],
  ];
  $("#facts").replaceChildren(
    ...values.map(([k, v]) => {
      const f = node("div", undefined, "fact");
      f.append(node("small", k), node("strong", v));
      return f;
    }),
  );
  const issues = [...s.blockers, ...s.warnings];
  if (!s.recovery_modes.length && !s.blockers.length)
    issues.push({
      message:
        state.config.mode === "disabled"
          ? "Recovery is disabled. Launch with --demo to use the bundled test key."
          : "No executable recovery backend matches this public key. A future cryptographic-scale backend is required.",
    });
  showNotice($("#session-issues"), issues);
  $("#recover").disabled =
    state.busy || state.quantumBusy || !s.recovery_modes.length;
  $("#recover").textContent =
    s.decrypt_state === "verified" ? "Recover again →" : "Recover session →";
  $("#public-details").hidden = !s.rsa;
  if (s.rsa)
    $("#public-key").textContent =
      `Modulus (n)\n${s.rsa.n_hex}\n\nPublic exponent (e)\n${s.rsa.e_hex}`;
  $("#timing-note").textContent =
    state.config.mode === "demo"
      ? `Demo recovery: ${state.config.demo_delay_seconds}s illustrative presentation delay · Known test recovery material, no quantum execution. TLS decryption and verification are real.`
      : "Recovery completion is driven by the configured backend’s actual job status.";
}
const stages = {
  queued: "Queued",
  matching_test_modulus: "Matching the public test modulus",
  illustrative_demo_delay: "Demonstration recovery in progress",
  verifying_factors: "Verifying the recovered factors",
  matching_test_problem: "Matching the public test problem",
  verifying_secret: "Verifying the recovered discrete logarithm",
  verifying_discrete_log: "Verifying the recovered discrete logarithm",
  authenticating_tls: "Deriving keys and authenticating TLS",
  parsing_http: "Reconstructing captured HTTP",
  building_circuit: "Building order-finding circuit",
  compiling: "Compiling circuit",
  waiting_for_provider: "Waiting for execution result",
  processing_measurements: "Verifying measured result",
  complete: "Captured TLS plaintext verified",
  failed: "Recovery did not complete",
};
function renderJob(job) {
  $("#job-panel").hidden = false;
  $("#job-stage").textContent =
    stages[job.stage] || job.stage.replaceAll("_", " ");
  $("#job-icon").className = ["running", "queued"].includes(job.state)
    ? "spinner"
    : "";
  $("#job-icon").textContent =
    job.state === "succeeded" ? "✓" : job.state === "failed" ? "!" : "";
  $("#job-source").textContent =
    job.method === "fixture_lookup"
      ? `${job.recovery_problem === "rsa_factor" ? "Known test factors" : "Known test discrete logarithm"} · no quantum execution`
      : job.method === "quantum_order_finding"
        ? `Quantum order finding · ${job.execution}`
        : state.config.mode === "demo"
          ? "Demonstration backend"
          : job.requested_backend;
  $("#checks").replaceChildren(
    ...[
      [job.recovery_problem === "rsa_factor" ? "Factor pair" : "Discrete logarithm", job.recovery_verified || job.factor_pair_verified],
      ["Client Finished", job.client_finished_verified],
      ["Server Finished", job.server_finished_verified],
      [
        `${job.authenticated_records} authenticated records`,
        job.authenticated_records > 0,
      ],
    ].map(([label, ok]) =>
      node(
        "span",
        `${ok ? "✓" : "○"} ${label}`,
        `check ${ok ? "verified" : ""}`,
      ),
    ),
  );
  showNotice($("#job-error"), [
    ...(job.error ? [job.error] : []),
    ...job.warnings,
  ]);
}
$("#recover").onclick = async () => {
  try {
    $("#error").hidden = true;
    $("#inspector").hidden = true;
    busy(true);
    const job = await api(`/api/sessions/${state.selected}/recover`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    state.job = job;
    renderJob(job);
    await poll(job.id, false);
  } catch (e) {
    error(e);
    busy(false);
    renderDetail();
  }
};
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
async function poll(id, quantum) {
  try {
    while (true) {
      const job = await api(`/api/jobs/${id}`);
      if (quantum) {
        $("#quantum-output").textContent = quantumText(job);
      } else if (state.selected === job.session_id) {
        state.job = job;
        renderJob(job);
      }
      if (!["running", "queued"].includes(job.state)) {
        if (!quantum) {
          state.capture = await api(`/api/captures/${state.capture.id}`);
          renderCapture();
          renderDetail();
          if (job.state === "succeeded" && state.selected === job.session_id)
            await loadExchanges();
        }
        break;
      }
      await delay(400);
    }
  } finally {
    if (quantum) state.quantumBusy = false;
    busy(false);
    if (state.selected) renderDetail();
  }
}
async function loadExchanges() {
  const sid = state.selected;
  const exchanges = await api(`/api/sessions/${sid}/http`);
  if (sid !== state.selected) return;
  $("#inspector").hidden = false;
  $("#exchanges").replaceChildren();
  $("#message-panes").hidden = !exchanges.length;
  showNotice(
    $("#http-empty"),
    exchanges.length
      ? []
      : [
          "TLS authenticated successfully; no supported complete HTTP exchange was decoded. Inspect the authenticated application bytes.",
        ],
  );
  $("#raw-downloads").replaceChildren(
    ...["c2s", "s2c"].map((d) => {
      const a = node(
        "a",
        d === "c2s" ? "Download request stream" : "Download response stream",
      );
      a.href = `/api/sessions/${sid}/application/${d}`;
      a.download = `${d}.bin`;
      return a;
    }),
  );
  for (const item of exchanges) {
    const b = node("button", undefined, "exchange");
    b.dataset.index = item.index;
    b.append(
      node("span", item.method, "method"),
      node("span", item.target, "target"),
      node("span", item.status || "No response", "status"),
    );
    b.onclick = () => loadExchange(item.index).catch(error);
    $("#exchanges").append(b);
  }
  if (exchanges.length) await loadExchange(0);
}
async function loadExchange(index) {
  const sid = state.selected;
  const item = await api(`/api/sessions/${sid}/http/${index}`);
  if (sid !== state.selected) return;
  state.exchange = item;
  for (const b of $("#exchanges").children)
    b.classList.toggle("active", Number(b.dataset.index) === index);
  renderMessages();
}
for (const tab of document.querySelectorAll(".tabs button"))
  tab.onclick = () => {
    state.tabs[tab.dataset.side] = tab.dataset.tab;
    renderMessages();
  };
function table(pairs) {
  const t = node("table");
  const body = node("tbody");
  for (const [k, v] of pairs) {
    const r = node("tr");
    r.append(node("td", k), node("td", v));
    body.append(r);
  }
  t.append(body);
  return t;
}
function section(container, title, pairs) {
  container.append(node("h4", title));
  container.append(
    pairs.length ? table(pairs) : node("p", "None captured.", "empty"),
  );
}
function renderMessages() {
  if (!state.exchange) return;
  const view = state.exchange;
  let warnings = [];
  for (const side of ["request", "response"]) {
    const msg = view[side],
      mode = state.tabs[side],
      container = $(`#${side}-content`);
    container.replaceChildren();
    document
      .querySelectorAll(`.tabs button[data-side="${side}"]`)
      .forEach((b) => b.classList.toggle("active", b.dataset.tab === mode));
    $(`#${side}-size`).textContent = msg
      ? `${formatSize(bytes(msg.raw_b64))} · ${msg.complete ? "Complete" : "Incomplete"}`
      : "Not captured";
    if (!msg) {
      container.append(node("p", "No response captured.", "empty"));
      continue;
    }
    warnings.push(...msg.warnings);
    if (mode === "raw") {
      container.append(node("pre", text(msg.raw_b64, "windows-1252")));
    } else if (mode === "headers") {
      section(container, "HEADERS", msg.headers);
      if (msg.trailers.length) section(container, "TRAILERS", msg.trailers);
    } else if (mode === "parameters") {
      section(container, "QUERY PARAMETERS", view.query_parameters);
      section(container, "FORM PARAMETERS", view.form_parameters);
    } else if (mode === "render") {
      if (
        msg.decoded_body_b64 !== null &&
        msg.media_type &&
        (msg.media_type.startsWith("text/") || msg.media_type.includes("json"))
      ) {
        container.append(
          node(
            "div",
            "Captured response only · Scripts and linked resources omitted",
            "render-note",
          ),
        );
        const frame = node("iframe");
        frame.title = "Captured response preview";
        frame.setAttribute("sandbox", "");
        frame.referrerPolicy = "no-referrer";
        frame.src = `/api/sessions/${state.selected}/http/${view.index}/preview`;
        container.append(frame);
        if (view.response_form_fields.length)
          section(
            container,
            "CAPTURED RESPONSE FIELDS",
            view.response_form_fields,
          );
      } else {
        container.append(
          node(
            "p",
            "This body cannot be rendered safely. Inspect Raw or Readable.",
            "empty",
          ),
        );
      }
    } else {
      const data = msg.decoded_body_b64;
      if (data === null) {
        container.append(
          node(
            "p",
            "Content encoding is not decoded. Raw preserves the captured bytes.",
            "empty",
          ),
        );
        continue;
      }
      let content = text(data, msg.charset);
      if (msg.media_type?.includes("json")) {
        try {
          content = JSON.stringify(JSON.parse(content), null, 2);
        } catch {}
      }
      if (
        msg.media_type &&
        !msg.media_type.startsWith("text/") &&
        !msg.media_type.includes("json") &&
        msg.media_type !== "application/x-www-form-urlencoded"
      ) {
        content =
          `Binary body · ${msg.media_type}\n\n` +
          Array.from(atob(data).slice(0, 4096), (c) =>
            c.charCodeAt(0).toString(16).padStart(2, "0"),
          ).join(" ");
      }
      container.append(node("pre", content));
    }
  }
  showNotice($("#message-notes"), warnings);
}
function quantumText(j) {
  const lines = [
    j.state === "succeeded"
      ? "Executed circuit → verified small-number factorization"
      : stages[j.stage] || j.stage.replaceAll("_", " "),
    `Requested: ${j.requested_backend}`,
    `Execution: ${j.execution}`,
    `Method: ${j.method || "pending"}`,
  ];
  if (j.demo_factors)
    lines.push(`Verified factors: ${j.demo_factors.join(" × ")}`);
  if (j.qubits)
    lines.push(
      `Circuit: ${j.qubits} qubits · ${j.compiled_ops} operations · depth ${j.compiled_depth}`,
      `Measurements: ${j.actual_shots ?? "exact probabilities"} ${j.distribution_kind}`,
      `Circuit SHA-256: ${j.circuit_sha256}`,
    );
  if (j.provider_job_ids.length)
    lines.push(`Provider job: ${j.provider_job_ids.join(", ")}`);
  if (j.error) lines.push(`${j.error.code}: ${j.error.message}`);
  lines.push(
    "This result is unrelated to the realistic RSA key in the capture.",
  );
  return lines.join("\n");
}
$("#run-quantum").onclick = async () => {
  try {
    state.quantumBusy = true;
    busy(true);
    const j = await api("/api/quantum-demo", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        n: Number($("#quantum-n").value),
        backend: "aer",
      }),
    });
    await poll(j.id, true);
  } catch (e) {
    state.quantumBusy = false;
    busy(false);
    error(e);
  }
};
async function init() {
  try {
    state.config = await api("/api/config");
    const banner = $("#mode-banner");
    banner.replaceChildren(
      node(
        "strong",
        state.config.mode === "demo"
          ? "DEMO MODE"
          : state.config.mode === "disabled"
            ? "RECOVERY DISABLED"
            : "QUANTUM EXECUTION",
      ),
      node(
        "span",
        state.config.mode === "demo"
          ? "Known test keys replace secret recovery. TCP, TLS decryption, and authentication are real."
          : state.config.mode === "disabled"
            ? "Launch with --demo to explore the full workflow using the bundled test key."
            : `${state.config.backend} · actual job status · no demonstration fallback`,
      ),
    );
    banner.classList.toggle("live", state.config.mode !== "demo");
    const caps = await api("/api/capabilities");
    state.aer = caps.find((c) => c.backend === "aer")?.installed;
    $("#quantum-capability").textContent = state.aer
      ? "Aer installed · local simulator"
      : "Optional quantum extra is not installed";
    $("#run-quantum").disabled = !state.aer;
    const r = await fetch("/api/captures/current");
    if (r.ok) {
      state.capture = await r.json();
      $("#dropzone").classList.add("compact");
      renderCapture();
      const first =
        state.capture.sessions.find((s) => s.decrypt_state === "running") ||
        state.capture.sessions.find((s) => s.protocol === "tls") ||
        state.capture.sessions[0];
      if (first) await selectSession(first.id);
    }
  } catch (e) {
    error(e);
  }
}
init();
