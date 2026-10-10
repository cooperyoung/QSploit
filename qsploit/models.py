from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Literal, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from qiskit import QuantumCircuit

Direction = Literal["c2s", "s2c"]
Backend = Literal["fixture", "aer", "ionq_simulator", "ionq_qpu"]
Execution = Literal["none", "aer", "ionq_simulator", "ionq_qpu"]

@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int

@dataclass(frozen=True)
class TCPConnection:
    id: str                    # capture-scoped generation, not a bare 5-tuple
    a: Endpoint
    b: Endpoint
    a_to_b: bytes = field(repr=False)  # maximal contiguous prefix only
    b_to_a: bytes = field(repr=False)
    a_fin_seen: bool
    b_fin_seen: bool
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]

@dataclass(frozen=True)
class CaptureAnalysis:
    connections: tuple[TCPConnection, ...]
    packets_seen: int
    warnings: tuple[str, ...]

@dataclass(frozen=True)
class Record:
    direction: Direction
    offset: int                 # offset in the directional TCP byte stream
    content_type: int
    version: int               # actual record-header version
    fragment: bytes = field(repr=False)

@dataclass(frozen=True)
class Handshake:
    direction: Direction
    record_offset: int         # first contributing record; diagnostic only
    wire: bytes = field(repr=False)  # type + uint24 length + body, unchanged

@dataclass(frozen=True)
class RSAKeyTransport:
    n: int
    e: int
    encrypted_premaster: bytes = field(repr=False)

@dataclass(frozen=True)
class FFDHEKeyExchange:
    p: int
    g: int
    server_public: int
    client_public: int
    order: int

@dataclass(frozen=True)
class ECDHEKeyExchange:
    group: int
    server_public: bytes
    client_public: bytes

@dataclass(frozen=True)
class ParsedTLS:
    id: str
    protocol: Literal["tls", "tcp", "unknown"]
    client: Endpoint | None
    server: Endpoint | None
    tls_version: int | None
    cipher_suite: int | None
    compression: int | None
    sni: str | None
    alpn: str | None
    authentication: str | None
    kex: str
    selected_group: int | None
    psk_selected: bool
    resumed: bool
    ems: bool | None            # None until negotiation is established
    client_hello_version: int | None
    client_random: bytes | None
    server_random: bytes | None
    rsa: RSAKeyTransport | None
    records: tuple[Record, ...] = field(repr=False)
    clear_handshakes: tuple[Handshake, ...] = field(repr=False)
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]
    dhe: FFDHEKeyExchange | None = None
    ecdhe: ECDHEKeyExchange | None = None

@dataclass(frozen=True)
class RSAProblem:
    n: int
    kind: Literal["rsa_factor"] = "rsa_factor"

@dataclass(frozen=True)
class RSAFactors:
    p: int = field(repr=False)
    q: int = field(repr=False)

@dataclass(frozen=True)
class FFDLogProblem:
    p: int
    g: int
    y: int
    order: int
    kind: Literal["ff_dlog"] = "ff_dlog"

@dataclass(frozen=True)
class FFDLogSecret:
    x: int = field(repr=False)

@dataclass(frozen=True)
class ECDLogProblem:
    curve: Literal["secp256r1", "x25519"]
    public_point: bytes
    kind: Literal["ec_dlog"] = "ec_dlog"

@dataclass(frozen=True)
class ECDLogSecret:
    x: int = field(repr=False)

@dataclass(frozen=True)
class X25519Secret:
    # RFC 7748 little-endian private input; X25519 applies its required clamping.
    scalar: bytes = field(repr=False)

PublicProblem = RSAProblem | FFDLogProblem | ECDLogProblem
RecoveredSecret = RSAFactors | FFDLogSecret | ECDLogSecret | X25519Secret

@dataclass(frozen=True)
class ExecutionOptions:
    backend: Backend
    target: str | None = None   # server configuration, not arbitrary UI URL
    shots: int = 1024
    max_attempts: int = 4
    timeout_seconds: int = 180
    demo_delay_seconds: float = 3.0
    max_qubits: int = 22
    max_compiled_ops: int = 250_000

@dataclass(frozen=True)
class Progress:
    stage: str
    provider_job_id: str | None = None

Report = Callable[[Progress], None]

@dataclass(frozen=True)
class Measurement:
    weights: dict[int, float]   # integer outcome for the phase register only
    kind: Literal["counts", "probabilities"]
    actual_shots: int | None
    execution: Execution
    target: str
    provider_job_id: str | None
    circuit_sha256: str
    qubits: int
    compiled_ops: int
    compiled_depth: int

class CircuitRunner(Protocol):
    def __call__(self, circuit: "QuantumCircuit",
                 options: ExecutionOptions, report: Report) -> Measurement: ...

@dataclass(frozen=True)
class Recovery:
    secret: RecoveredSecret = field(repr=False)
    method: Literal["fixture_lookup", "quantum_order_finding", "classical_precheck"]
    execution: Execution
    target: str | None
    measurements: tuple[Measurement, ...] = field(repr=False)

    @property
    def factors(self) -> RSAFactors:
        """Compatibility for the separate RSA quantum-validation entry point."""
        if not isinstance(self.secret, RSAFactors):
            raise TypeError("This recovery result contains a discrete logarithm, not RSA factors")
        return self.secret

@dataclass(frozen=True)
class ApplicationStreams:
    c2s: bytes = field(repr=False)
    s2c: bytes = field(repr=False)
    client_finished_verified: bool
    server_finished_verified: bool
    authenticated_records: int
    client_close_notify: bool
    server_close_notify: bool
    warnings: tuple[str, ...]


from typing import Literal
from pydantic import BaseModel, ConfigDict

class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

class Issue(WireModel):
    code: str
    message: str

class PublicRSA(WireModel):
    n_hex: str
    e_hex: str
    bits: int

class SessionView(WireModel):
    id: str
    client: str | None           # IPv6 endpoints use [address]:port
    server: str | None
    protocol: Literal["tls", "tcp", "unknown"]
    sni: str | None
    tls_version: str | None      # "1.2", "1.3", or None
    cipher_suite_id: int | None
    cipher_suite_name: str | None
    key_exchange: str            # controlled values defined in section 6
    authentication: str | None
    alpn: str | None
    selected_group_id: int | None
    selected_group_name: str | None
    ems: bool | None
    psk_selected: bool
    resumed: bool
    rsa: PublicRSA | None
    vulnerability: Literal["shor_applicable", "shor_insufficient", "unknown"]
    implementation: Literal["supported", "unsupported", "unknown"]
    capture_state: Literal["usable", "incomplete", "ambiguous", "unsupported"]
    recovery_modes: list[Literal["fixture", "aer", "ionq_simulator", "ionq_qpu"]]
    decrypt_state: Literal["not_started", "running", "verified", "failed"]
    blockers: list[Issue]
    warnings: list[Issue]
    endpoint_a: str | None = None  # observed sockets when TLS roles are unknown
    endpoint_b: str | None = None
    recovery_problem: str | None = None

class CaptureView(WireModel):
    id: str
    size_bytes: int
    packets_seen: int
    sessions: list[SessionView]
    warnings: list[Issue]

class StartRecovery(WireModel):
    pass  # backend is selected by explicit launch configuration

class StartQuantumDemo(WireModel):
    n: Literal[15, 21]
    backend: Literal["aer", "ionq_simulator", "ionq_qpu"]

class JobView(WireModel):
    id: str
    session_id: str | None
    state: Literal["queued", "running", "succeeded", "failed", "timed_out"]
    stage: str
    requested_backend: str
    method: str | None
    execution: Literal["none", "aer", "ionq_simulator", "ionq_qpu"]
    target: str | None
    provider_job_ids: list[str]
    circuit_sha256: str | None
    qubits: int | None
    compiled_ops: int | None
    compiled_depth: int | None
    distribution_kind: Literal["counts", "probabilities"] | None
    actual_shots: int | None
    demo_factors: tuple[int, int] | None
    factor_pair_verified: bool
    client_finished_verified: bool
    server_finished_verified: bool
    authenticated_records: int
    error: Issue | None
    warnings: list[Issue]
    recovery_problem: str | None = None
    recovery_verified: bool = False

class ExchangeSummary(WireModel):
    index: int
    method: str
    target: str
    status: int | None
    response_media_type: str | None
    complete: bool

class HTTPMessage(WireModel):
    raw_b64: str
    headers: list[tuple[str, str]]
    trailers: list[tuple[str, str]]
    body_b64: str               # dechunked entity bytes, still content-encoded
    decoded_body_b64: str | None
    media_type: str | None
    charset: str | None
    complete: bool
    warnings: list[Issue]

class ExchangeView(WireModel):
    index: int
    request: HTTPMessage
    response: HTTPMessage | None
    informational_statuses: list[int]
    query_parameters: list[tuple[str, str]]
    form_parameters: list[tuple[str, str]]
    response_form_fields: list[tuple[str, str]]

class Capability(WireModel):
    backend: str
    installed: bool
    configured: bool
    connection_verified: bool
    target: str | None
    max_qubits: int
    max_compiled_ops: int
    reason: str | None

class ErrorResponse(WireModel):
    error: Issue


class QSploitError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message[:500]
        super().__init__(self.message)
