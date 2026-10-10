"""One local application. Capture/secret state stays in this process."""
from __future__ import annotations
import asyncio
import importlib.util
import math
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .models import (ApplicationStreams, CaptureView, Capability, ExecutionOptions, ExchangeSummary, ExchangeView, Issue, JobView, ParsedTLS, Progress, PublicRSA, QSploitError, RSAProblem, SessionView, StartQuantumDemo, StartRecovery)
from .http1 import Exchange, parse_http, text_body
from .jobs import run_recovery, verify_recovery
from .preview import PREVIEW_CSP, preview_document
from .quantum.engine import has_known_factors
from .pcap import read_connections
from .tls import parse_tls, problem_for, cipher_suite_name, group_name
from .tls12 import decrypt_tls12

ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Settings:
    backend: str = "disabled"
    demo_delay_seconds: float = 3.0
    target: str | None = None
    port: int = 8000
    shots: int = 256
    max_attempts: int = 1
    timeout_seconds: int = 180
    max_upload_bytes: int = 32 * 1024 * 1024

    def __post_init__(self):
        if self.backend not in {"disabled", "fixture", "aer", "ionq_simulator", "ionq_qpu"}:
            raise ValueError("Invalid configured backend")
        if not math.isfinite(self.demo_delay_seconds) or not 0 <= self.demo_delay_seconds <= 3600:
            raise ValueError("demo_delay_seconds must be between 0 and 3600")
        if not 1 <= self.port <= 65535:
            raise ValueError("Invalid port")
        if not 1 <= self.shots <= 100000 or not 1 <= self.max_attempts <= 16 or not 1 <= self.timeout_seconds <= 7200:
            raise ValueError("Shots, attempts or timeout exceed the configured execution limits")

    def execution(self, backend=None):
        return ExecutionOptions(backend=backend or self.backend, target=self.target, shots=self.shots, max_attempts=self.max_attempts, timeout_seconds=max(self.timeout_seconds, math.ceil(self.demo_delay_seconds)+10), demo_delay_seconds=self.demo_delay_seconds)


@dataclass
class State:
    capture_id: str | None = None
    size_bytes: int = 0
    packets_seen: int = 0
    warnings: tuple[str, ...] = ()
    sessions: dict[str, ParsedTLS] = field(default_factory=dict)
    endpoints: dict[str, tuple[str, str]] = field(default_factory=dict)
    decrypt_states: dict[str, str] = field(default_factory=dict)
    streams: dict[str, ApplicationStreams] = field(default_factory=dict)
    exchanges: dict[str, list[Exchange]] = field(default_factory=dict)
    session_jobs: dict[str, str] = field(default_factory=dict)
    jobs: dict[str, JobView] = field(default_factory=dict)
    active_task: asyncio.Task | None = None


MESSAGES = {
    "TCP_GAP": "Missing TCP bytes prevent trustworthy decryption.",
    "TCP_OVERLAP_CONFLICT": "Overlapping TCP packets contain conflicting bytes.",
    "INCOMPLETE_HANDSHAKE": "Required handshake messages are missing.",
    "UNSUPPORTED_TLS_VERSION": "Decryption currently supports TLS 1.2 only.",
    "UNSUPPORTED_CIPHER": "Decryption currently supports TLS_RSA_WITH_AES_128_GCM_SHA256 only.",
    "UNSUPPORTED_KEX": "This negotiated key exchange needs a different recovery algorithm.",
    "RESUMPTION_UNSUPPORTED": "Resumed sessions require secrets from the original handshake.",
    "CLIENT_AUTH_UNSUPPORTED": "Client-certificate authentication is outside this version's scope.",
    "RENEGOTIATION_UNSUPPORTED": "Renegotiated sessions are not supported.",
    "IP_FRAGMENT_UNSUPPORTED": "Fragmented IP traffic is not reassembled.",
}


def issue(code: str) -> Issue:
    return Issue(code=code, message=MESSAGES.get(code, code.replace("_", " ").capitalize()))


def endpoint(value):
    if value is None:
        return None
    return f"[{value.ip}]:{value.port}" if ":" in value.ip else f"{value.ip}:{value.port}"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    state = State()
    lock = asyncio.Lock()

    @asynccontextmanager
    async def lifespan(app):
        yield
        if state.active_task and not state.active_task.done():
            state.active_task.cancel()
            try:
                await state.active_task
            except asyncio.CancelledError:
                pass

    app = FastAPI(title="QSploit", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.store = state
    app.state.settings = settings

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        allowed = {f"127.0.0.1:{settings.port}", f"localhost:{settings.port}"}
        if settings.port == 80:
            allowed |= {"127.0.0.1", "localhost"}
        host = request.headers.get("host", "")
        if host not in allowed:
            return JSONResponse({"error": {"code": "HOST_REJECTED", "message": "Use the configured loopback address."}}, status_code=403)
        content_length = request.headers.get("content-length")
        if content_length and (not content_length.isdecimal() or int(content_length) > settings.max_upload_bytes):
            return JSONResponse({"error": {"code": "RESOURCE_LIMIT", "message": "Request exceeds the upload limit."}}, status_code=413)
        if request.method in {"POST", "DELETE", "PUT", "PATCH"}:
            if request.headers.get("x-qsploit") != "1" or request.headers.get("origin", f"http://{host}") != f"http://{host}":
                return JSONResponse({"error": {"code": "ORIGIN_REJECTED", "message": "Use QSploit's local interface."}}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if "/preview" not in request.url.path:
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        return response

    @app.exception_handler(QSploitError)
    async def domain_error(request, exc):
        status = 404 if exc.code == "NOT_FOUND" else 409 if exc.code in {"JOB_ACTIVE", "NOT_READY"} else 413 if exc.code == "RESOURCE_LIMIT" else 415 if exc.code in {"PCAPNG_UNSUPPORTED", "UNSUPPORTED_LINKTYPE"} else 422 if exc.code.startswith("UNSUPPORTED") or exc.code == "BACKEND_UNAVAILABLE" else 400
        return JSONResponse({"error": {"code": exc.code, "message": exc.message}}, status_code=status)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse({"error": {"code": "INVALID_REQUEST", "message": "Request fields are invalid."}}, status_code=422)

    def ensure_idle():
        if state.active_task and not state.active_task.done():
            raise QSploitError("JOB_ACTIVE", "Wait for the current recovery to finish before replacing or clearing the capture.")

    def session(sid):
        if sid not in state.sessions:
            raise QSploitError("NOT_FOUND", "Session not found.")
        return state.sessions[sid]

    def session_view(s):
        supported = not s.blockers and s.rsa is not None and s.tls_version == 0x303 and s.cipher_suite == 0x9c and s.kex == "rsa_transport"
        modes = []
        if supported and settings.backend == "fixture" and has_known_factors(RSAProblem(s.rsa.n)):
            modes = ["fixture"]
        elif supported and settings.backend != "disabled" and settings.backend != "fixture" and 4*s.rsa.n.bit_length()+2 <= 22:
            modes = [settings.backend]
        vuln = "shor_insufficient" if s.kex in {"hybrid_pq", "pq", "psk", "psk_dhe", "psk_ecdhe"} else "shor_applicable" if s.kex in {"rsa_transport", "dhe", "ecdhe"} else "unknown"
        incomplete = any("GAP" in b or "INCOMPLETE" in b or "TRUNCATED" in b for b in s.blockers)
        ambiguous = any("CONFLICT" in b or "AMBIGUOUS" in b for b in s.blockers)
        observed = state.endpoints.get(s.id, (None, None))
        return SessionView(id=s.id, client=endpoint(s.client), server=endpoint(s.server), protocol=s.protocol, sni=s.sni, tls_version={0x301:"1.0", 0x302:"1.1", 0x303:"1.2", 0x304:"1.3"}.get(s.tls_version), cipher_suite_id=s.cipher_suite, cipher_suite_name=cipher_suite_name(s.cipher_suite), key_exchange=s.kex, authentication=s.authentication, alpn=s.alpn, selected_group_id=s.selected_group, selected_group_name=group_name(s.selected_group), ems=s.ems, psk_selected=s.psk_selected, resumed=s.resumed, rsa=PublicRSA(n_hex=format(s.rsa.n,"x"),e_hex=format(s.rsa.e,"x"),bits=s.rsa.n.bit_length()) if s.rsa else None, vulnerability=vuln, implementation="supported" if supported else "unsupported", capture_state="ambiguous" if ambiguous else "incomplete" if incomplete else "unsupported" if s.blockers else "usable", recovery_modes=modes, decrypt_state=state.decrypt_states.get(s.id,"not_started"), blockers=[issue(b) for b in s.blockers], warnings=[issue(w) for w in s.warnings], endpoint_a=observed[0], endpoint_b=observed[1])

    def capture_view():
        if not state.capture_id:
            raise QSploitError("NOT_FOUND", "Upload a capture to begin.")
        return CaptureView(id=state.capture_id, size_bytes=state.size_bytes, packets_seen=state.packets_seen, sessions=[session_view(s) for s in state.sessions.values()], warnings=[issue(w) for w in state.warnings])

    @app.get("/api/config")
    async def config():
        return {"mode": "demo" if settings.backend == "fixture" else "disabled" if settings.backend == "disabled" else "quantum", "backend":settings.backend, "demo_delay_seconds":settings.demo_delay_seconds, "timing_kind":"illustrative_delay" if settings.backend == "fixture" else "actual_job_status", "timing_assumptions":"Presentation delay only; not an estimate of quantum runtime.", "target":settings.target, "shots":settings.shots,"max_attempts":settings.max_attempts,"max_upload_bytes":settings.max_upload_bytes}

    @app.get("/api/capabilities", response_model=list[Capability])
    async def capabilities():
        return [Capability(backend=b, installed=b == "fixture" or importlib.util.find_spec("qiskit_aer" if b == "aer" else "qiskit_ionq") is not None, configured=b in {"fixture","aer"} or bool(settings.target and os.getenv("IONQ_API_KEY") and os.getenv("QSPLOIT_IONQ_ALLOW_SUBMIT") == "1"), connection_verified=False, target=settings.target if b.startswith("ionq") else None,max_qubits=22,max_compiled_ops=250000,reason="Requires credentials, an explicit target and QSPLOIT_IONQ_ALLOW_SUBMIT=1. Provider access is not verified on page load." if b.startswith("ionq") else None) for b in ("fixture","aer","ionq_simulator","ionq_qpu")]

    @app.get("/api/demo-capture")
    async def demo_capture():
        path = ROOT / "demo" / "tls12-rsa-ems.pcap"
        if not path.is_file():
            raise QSploitError("NOT_FOUND", "Bundled capture is missing.")
        return FileResponse(path, media_type="application/octet-stream", filename=path.name)

    @app.post("/api/captures", response_model=CaptureView, status_code=201)
    async def upload(request: Request):
        async with lock:
            ensure_idle()
            data = bytearray()
            async for chunk in request.stream():
                if len(data)+len(chunk) > settings.max_upload_bytes:
                    raise QSploitError("RESOURCE_LIMIT", "Capture exceeds the 32 MiB upload limit.")
                data.extend(chunk)
            def analyze():
                capture = read_connections(bytes(data))
                return capture, [parse_tls(c) for c in capture.connections]
            capture, parsed = await asyncio.to_thread(analyze)
            state.capture_id = uuid4().hex
            state.size_bytes, state.packets_seen, state.warnings = len(data), capture.packets_seen, capture.warnings
            # A stale browser/session URL must never resolve to another capture.
            scoped = [replace(s, id=f"{state.capture_id}:{s.id}") for s in parsed]
            state.sessions = {s.id:s for s in scoped}
            state.endpoints = {s.id:(endpoint(c.a), endpoint(c.b)) for s,c in zip(scoped,capture.connections)}
            state.decrypt_states.clear(); state.streams.clear(); state.exchanges.clear(); state.jobs.clear(); state.session_jobs.clear()
            return capture_view()

    @app.get("/api/captures/current", response_model=CaptureView)
    async def current():
        return capture_view()

    @app.get("/api/captures/{cid}", response_model=CaptureView)
    async def capture(cid: str):
        if cid != state.capture_id:
            raise QSploitError("NOT_FOUND", "Capture not found.")
        return capture_view()

    @app.delete("/api/captures/{cid}", status_code=204)
    async def clear(cid: str):
        async with lock:
            ensure_idle()
            if cid != state.capture_id:
                raise QSploitError("NOT_FOUND", "Capture not found.")
            state.capture_id = None
            state.sessions.clear(); state.endpoints.clear(); state.streams.clear(); state.exchanges.clear(); state.jobs.clear(); state.decrypt_states.clear(); state.session_jobs.clear()
        return Response(status_code=204)

    def new_job(sid, backend):
        # Keep only a small bounded history in the single-capture memory store.
        while len(state.jobs) >= 64:
            state.jobs.pop(next(iter(state.jobs)))
        return JobView(id=uuid4().hex, session_id=sid, state="queued", stage="queued", requested_backend=backend, method=None, execution="none",target=None,provider_job_ids=[],circuit_sha256=None,qubits=None,compiled_ops=None,compiled_depth=None,distribution_kind=None,actual_shots=None,demo_factors=None,factor_pair_verified=False,client_finished_verified=False,server_finished_verified=False,authenticated_records=0,error=None,warnings=[])

    async def execute(job, problem, options, selected):
        job.state = "running"
        def report(progress: Progress):
            job.stage = progress.stage
            if progress.provider_job_id and progress.provider_job_id not in job.provider_job_ids:
                job.provider_job_ids.append(progress.provider_job_id)
        try:
            result = await run_recovery(problem, options, report)
            verify_recovery(problem, result, options)
            job.factor_pair_verified = True
            job.method, job.execution, job.target = result.method, result.execution, result.target
            if result.measurements:
                m = result.measurements[-1]
                job.circuit_sha256, job.qubits, job.compiled_ops, job.compiled_depth = m.circuit_sha256, m.qubits, m.compiled_ops, m.compiled_depth
                job.distribution_kind, job.actual_shots = m.kind, m.actual_shots
            if selected:
                job.stage = "authenticating_tls"
                streams = await asyncio.to_thread(decrypt_tls12, selected, result.factors)
                job.client_finished_verified, job.server_finished_verified, job.authenticated_records = streams.client_finished_verified, streams.server_finished_verified, streams.authenticated_records
                job.warnings.extend(issue(w) for w in streams.warnings)
                job.stage = "parsing_http"
                try:
                    exchanges = await asyncio.to_thread(parse_http, streams, selected.alpn)
                except QSploitError as exc:
                    exchanges = []
                    job.warnings.append(Issue(code=exc.code,message=exc.message))
                state.streams[selected.id], state.exchanges[selected.id] = streams, exchanges
                state.decrypt_states[selected.id] = "verified"
            else:
                job.demo_factors = (result.factors.p, result.factors.q)
            job.state, job.stage = "succeeded", "complete"
        except QSploitError as exc:
            job.state = "timed_out" if "TIMEOUT" in exc.code else "failed"
            job.stage = "failed"
            job.error = Issue(code=exc.code,message=exc.message)
            if selected:
                state.decrypt_states[selected.id] = "failed"
        except Exception:
            job.state, job.stage = "failed", "failed"
            job.error = Issue(code="PROCESSING_FAILED",message="Processing failed. No plaintext was published and no fallback was attempted.")
            if selected:
                state.decrypt_states[selected.id] = "failed"

    @app.post("/api/sessions/{sid}/recover", response_model=JobView, status_code=202)
    async def start(sid: str, request: StartRecovery):
        async with lock:
            ensure_idle()
            selected = session(sid)
            if settings.backend == "disabled":
                raise QSploitError("BACKEND_UNAVAILABLE", "Restart with --demo for known test-key recovery, or explicitly configure a quantum backend.")
            problem = problem_for(selected)
            options = settings.execution()
            job = new_job(sid, options.backend)
            state.streams.pop(sid,None); state.exchanges.pop(sid,None)
            state.decrypt_states[sid] = "running"
            state.jobs[job.id] = job
            state.session_jobs[sid] = job.id
            state.active_task = asyncio.create_task(execute(job, problem, options, selected))
            return job

    @app.post("/api/quantum-demo", response_model=JobView, status_code=202)
    async def quantum_demo(request: StartQuantumDemo):
        async with lock:
            ensure_idle()
            if request.backend.startswith("ionq") and (not settings.target or not os.getenv("IONQ_API_KEY")):
                raise QSploitError("BACKEND_UNAVAILABLE", "IonQ requires an explicitly configured target and credentials.")
            job = new_job(None, request.backend)
            state.jobs[job.id] = job
            state.active_task = asyncio.create_task(execute(job,RSAProblem(request.n),settings.execution(request.backend),None))
            return job

    @app.get("/api/jobs/{jid}", response_model=JobView)
    async def job(jid: str):
        if jid not in state.jobs:
            raise QSploitError("NOT_FOUND", "Job not found.")
        return state.jobs[jid]

    @app.get("/api/sessions/{sid}/job", response_model=JobView | None)
    async def session_job(sid: str):
        session(sid)
        return state.jobs.get(state.session_jobs.get(sid))

    def exchanges_for(sid):
        session(sid)
        if sid not in state.exchanges:
            raise QSploitError("NOT_READY", "Recover and verify this session first.")
        return state.exchanges[sid]

    def exchange_for(sid, index):
        items = exchanges_for(sid)
        if index < 0 or index >= len(items):
            raise QSploitError("NOT_FOUND", "HTTP exchange not found.")
        return items[index]

    @app.get("/api/sessions/{sid}/http", response_model=list[ExchangeSummary])
    async def http_list(sid: str):
        return [e.summary for e in exchanges_for(sid)]

    @app.get("/api/sessions/{sid}/http/{index}", response_model=ExchangeView)
    async def http_exchange(sid: str, index: int):
        return exchange_for(sid,index).view

    @app.get("/api/sessions/{sid}/http/{index}/preview", response_class=HTMLResponse)
    async def preview(sid: str, index: int):
        message = exchange_for(sid,index).view.response
        if not message or message.decoded_body_b64 is None:
            raise QSploitError("NOT_READY", "No decoded response body is available.")
        if not message.media_type or not (message.media_type.startswith("text/") or "json" in message.media_type):
            raise QSploitError("UNSUPPORTED_MEDIA", "This media type is available in Raw only.")
        return HTMLResponse(preview_document(text_body(message),message.media_type), headers={"Content-Security-Policy":PREVIEW_CSP})

    @app.get("/api/sessions/{sid}/application/{direction}")
    async def application(sid: str, direction: str):
        session(sid)
        if direction not in {"c2s","s2c"}:
            raise QSploitError("INVALID_REQUEST", "Direction must be c2s or s2c.")
        if sid not in state.streams:
            raise QSploitError("NOT_READY", "No verified plaintext available.")
        return Response(getattr(state.streams[sid],direction),media_type="application/octet-stream",headers={"Content-Disposition":f'attachment; filename="{direction}.bin"'})

    @app.get("/")
    async def index():
        return FileResponse(ROOT / "static" / "index.html")

    app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
    return app
