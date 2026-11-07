"""
docker-exec: minimal Docker container management service for Open WebUI tools.
Only manages containers explicitly trusted (see "Trusting a container" below).

Env vars:
  DOCKER_EXEC_API_KEY      required (shared secret, sent as X-API-Key)
  ALLOW_NO_AUTH=1          disable auth (NOT recommended, dev only)
  PROTECTED_CONTAINERS     comma-separated names that can't be stopped/restarted/removed
                           (default: "docker-exec")
  DOCKER_EXEC_ALLOWLIST    comma-separated container names trusted even without a
                           valid HMAC signature (migration escape hatch - it does
                           NOT stop name spoofing, see below)
  DOCKER_EXEC_SIGNING_KEY  optional key used to verify `managed.signature` labels.
                           Falls back to DOCKER_EXEC_API_KEY.
  MAX_OUTPUT_BYTES         cap for exec/log output (default 65536)
  EXEC_MAX_CONCURRENCY     parallel execs allowed (default 16)
  EXEC_READ_BUDGET_FACTOR  how many times MAX_OUTPUT_BYTES to read from a stream
                           before abandoning it (default 4)
  EXEC_TIMEOUT_WRAPPER     "0" disables the `timeout` wrapper

Trusting a container
--------------------
The `managed=true` label alone is NOT authorization: labels live in the
container's own Config, so anyone who can `docker run` on this host could
otherwise mint a "managed" container and get RCE as root on the host via
/docker/exec/{name}.

A container is trusted only if it carries a valid signature:

    managed=true
    managed.signature=hmac_sha256(key, container_id)

Mint it from the host once the container exists (the ID is only known then):

    CID=$(docker inspect -f '{{.Id}}' mycontainer)
    SIG=$(printf '%s' "$CID" | openssl dgst -sha256 -hmac "$DOCKER_EXEC_SIGNING_KEY" -r | cut -d' ' -f1)
    docker update --label-add managed=true --label-add managed.signature=$SIG mycontainer

Migration: containers that are already managed but unsigned can be listed in
DOCKER_EXEC_ALLOWLIST to accept them *by name*. That keeps them working but does
not fix the spoofing hole for those names, so treat it as temporary.

NOTE on ordering: the allowlist is checked BEFORE the signature, so listing a
container that already carries a valid signature silently downgrades it from
HMAC trust to name trust. See README, "Consequences of signing".
"""

import hashlib
import hmac
import logging
import os
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from docker import DockerClient
from docker.errors import APIError, NotFound
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("docker-exec")

app = FastAPI(title="docker-exec", version="1.2.2")

TRUSTED_LABEL = "managed"
SIGNATURE_LABEL = "managed.signature"
DEFAULT_LOG_LINES = 200
DEFAULT_EXEC_TIMEOUT = 30
MAX_EXEC_TIMEOUT = 600
EXEC_GRACE_SECONDS = 5
MAX_OUTPUT_BYTES = int(os.environ.get("MAX_OUTPUT_BYTES", "65536"))
EXEC_MAX_CONCURRENCY = int(os.environ.get("EXEC_MAX_CONCURRENCY", "16"))
USE_TIMEOUT_WRAPPER = os.environ.get("EXEC_TIMEOUT_WRAPPER", "1") == "1"
# Hard ceiling on how much a single exec may read from its stream. Memory is
# already bounded by MAX_OUTPUT_BYTES; this bounds the *work* a runaway command
# can make the server do (socket reads, decrypt/decode, CPU) before we detach.
EXEC_READ_BUDGET_FACTOR = int(os.environ.get("EXEC_READ_BUDGET_FACTOR", "4"))
PROTECTED = {
    n.strip()
    for n in os.environ.get("PROTECTED_CONTAINERS", "docker-exec").split(",")
    if n.strip()
}
ALLOWLIST = {
    n.strip() for n in os.environ.get("DOCKER_EXEC_ALLOWLIST", "").split(",") if n.strip()
}

# ─── Auth ──────────────────────────────────────────────────────────────────────

API_KEY = os.environ.get("DOCKER_EXEC_API_KEY", "")
if not API_KEY and os.environ.get("ALLOW_NO_AUTH") != "1":
    raise RuntimeError(
        "DOCKER_EXEC_API_KEY is not set (set ALLOW_NO_AUTH=1 to run without auth)."
    )

SIGNING_KEY = os.environ.get("DOCKER_EXEC_SIGNING_KEY") or API_KEY


def require_auth(x_api_key: Optional[str] = Header(default=None)) -> None:
    if os.environ.get("ALLOW_NO_AUTH") == "1" and not API_KEY:
        return
    if not x_api_key or not hmac.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


# All routes except /health live on this router.
api = APIRouter(dependencies=[Depends(require_auth)])

# ─── Docker client / pools ─────────────────────────────────────────────────────

_client: Optional[DockerClient] = None
_client_lock = threading.Lock()


def get_client() -> DockerClient:
    """One shared client for the whole process.

    NOTE: the client timeout only bounds the *initial* HTTP request. Docker's
    exec API hijacks the connection and `_read_from_socket` disables the socket
    timeout afterwards, so long-running execs are NOT limited by this value
    (verified: a 70s exec succeeds with the default 60s client timeout).
    """
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = DockerClient.from_env()
    return _client


_STATS_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="stats")

# ─── Helpers ───────────────────────────────────────────────────────────────────


def _api_error_to_http(e: APIError) -> HTTPException:
    """Map a Docker APIError onto its real status code instead of a bare 500.

    Callers must test NotFound *before* APIError: ImageNotFound subclasses
    NotFound, and both subclass APIError, so the reverse order would turn every
    404 into a 500.
    """
    status = getattr(e, "status_code", None) or 502
    if not 400 <= status <= 599:
        status = 502
    detail = getattr(e, "explanation", None) or str(e)
    return HTTPException(status_code=status, detail=detail)


def _sign(container_id: str) -> str:
    return hmac.new(
        SIGNING_KEY.encode(), container_id.encode(), hashlib.sha256
    ).hexdigest()


def is_trusted(container) -> bool:
    """Trust is signed, not self-asserted by the label."""
    labels = container.attrs.get("Config", {}).get("Labels", {}) or {}
    if labels.get(TRUSTED_LABEL) != "true":
        return False
    if container.name in ALLOWLIST:
        return True
    claimed = labels.get(SIGNATURE_LABEL) or ""
    return bool(claimed) and hmac.compare_digest(claimed, _sign(container.id))


def _require_trusted(container) -> None:
    if not is_trusted(container):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Container '{container.name}' is not trusted. It needs label "
                f"{TRUSTED_LABEL}=true plus a valid {SIGNATURE_LABEL} "
                "(or must be listed in DOCKER_EXEC_ALLOWLIST)."
            ),
        )


def _require_not_protected(container) -> None:
    # Name-based on purpose: this is an identity-ish guard, and trusting a
    # label here would let a re-created container re-mint it.
    if container.name in PROTECTED:
        raise HTTPException(
            status_code=403,
            detail=f"Container '{container.name}' is protected and cannot be stopped, restarted or removed.",
        )


def _get_container(name: str):
    try:
        return get_client().containers.get(name)
    except NotFound:
        raise HTTPException(status_code=404, detail=f"Container '{name}' not found.")
    except APIError as e:
        raise _api_error_to_http(e) from e


def _trusted_container(name: str):
    c = _get_container(name)
    _require_trusted(c)
    return c


def _truncate(data: Optional[bytes], truncated: Optional[bool] = None) -> Dict[str, Any]:
    """Decode bytes, capping size. Returns {"text", "truncated", "bytes_total"}.

    The cap is applied to *bytes* before decoding, which keeps `bytes_total` and
    the cap in the same unit. A multi-byte UTF-8 character straddling the cut is
    emitted as U+FFFD by errors="replace" rather than raising.

    `truncated` exists because the exec path already knows the answer: it records
    overflow *while streaming*, on buffers that are capped as they are filled. If
    truncation were re-derived here from the finished buffer it would compare an
    already-capped buffer against the cap and be `False` every time -- which is
    exactly the bug this parameter fixes.
    """
    if not data:
        return {"text": "", "truncated": bool(truncated), "bytes_total": 0}
    total = len(data)
    capped = total > MAX_OUTPUT_BYTES
    if capped:
        data = data[:MAX_OUTPUT_BYTES]
    return {
        "text": data.decode("utf-8", errors="replace"),
        "truncated": capped if truncated is None else bool(truncated),
        "bytes_total": total,
    }


def _calc_stats(c, s: Dict[str, Any]) -> Dict[str, Any]:
    """Turn raw Docker API stats into the numbers `docker stats` shows."""
    cpu = s.get("cpu_stats", {}) or {}
    pre = s.get("precpu_stats", {}) or {}
    cpu_delta = (cpu.get("cpu_usage", {}).get("total_usage", 0)
                 - pre.get("cpu_usage", {}).get("total_usage", 0))
    sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
    ncpu = (cpu.get("online_cpus")
            or len(cpu.get("cpu_usage", {}).get("percpu_usage") or [])
            or 1)
    cpu_pct = (cpu_delta / sys_delta) * ncpu * 100.0 if sys_delta > 0 and cpu_delta > 0 else 0.0

    mem = s.get("memory_stats", {}) or {}
    mstats = mem.get("stats", {}) or {}
    # same as `docker stats`: subtract page cache (cgroup v2: inactive_file, v1: cache)
    cache = mstats.get("inactive_file", mstats.get("cache", 0))
    mem_usage = max(mem.get("usage", 0) - cache, 0)
    mem_limit = mem.get("limit", 0)

    io = (s.get("blkio_stats", {}) or {}).get("io_service_bytes_recursive") or []

    def blk(op: str) -> int:
        return sum(e.get("value", 0) for e in io if str(e.get("op", "")).lower() == op)

    nets = s.get("networks", {}) or {}

    return {
        "name": c.name,
        "cpu_percent": round(cpu_pct, 2),
        "mem_usage_bytes": mem_usage,
        "mem_limit_bytes": mem_limit,
        "mem_percent": round(mem_usage / mem_limit * 100, 2) if mem_limit else 0.0,
        "block_read_bytes": blk("read"),
        "block_write_bytes": blk("write"),
        "net_rx_bytes": sum(n.get("rx_bytes", 0) for n in nets.values()),
        "net_tx_bytes": sum(n.get("tx_bytes", 0) for n in nets.values()),
    }


def _stats_for(c) -> Dict[str, Any]:
    try:
        return _calc_stats(c, c.stats(stream=False))
    except Exception as e:  # one broken container shouldn't kill the whole response
        return {"name": c.name, "error": str(e)}


def _image_name(c) -> str:
    """Image name without an extra API round-trip.

    `c.image.tags` issues an images.get() per container and raises
    ImageNotFound (a NotFound subclass) when the image was removed or
    retagged, which used to abort the whole /docker/ps listing.
    """
    cfg_image = (c.attrs.get("Config", {}) or {}).get("Image")
    if cfg_image:
        return cfg_image
    image_id = c.attrs.get("Image", "") or ""
    return image_id.split(":", 1)[1][:12] if ":" in image_id else image_id[:12]


def _summarise(c) -> Dict[str, Any]:
    return {
        "name": c.name,
        "image": _image_name(c),
        "status": c.status,
        "created": c.attrs.get("Created", ""),
        "ports": c.attrs.get("NetworkSettings", {}).get("Ports", {}),
    }


# ─── Read-only endpoints ───────────────────────────────────────────────────────


@api.get("/docker/ps")
def docker_ps(include_stopped: bool = Query(False, alias="all")):
    """List managed containers.

    Running containers only by default; `?all=true` also lists stopped ones, so
    a container stopped via /docker/stop stays discoverable (previously it
    vanished from every listing while still deletable and log-readable).
    """
    try:
        containers = get_client().containers.list(
            all=include_stopped, filters={"label": TRUSTED_LABEL}
        )
    except APIError as e:
        raise _api_error_to_http(e) from e
    return [_summarise(c) for c in containers if is_trusted(c)]


@api.get("/docker/stats")
def docker_stats(name: Optional[str] = None):
    """Resource usage for one or all running managed containers (collected in parallel)."""
    if name:
        containers = [_trusted_container(name)]
    else:
        try:
            containers = get_client().containers.list(
                filters={"label": TRUSTED_LABEL, "status": "running"}
            )
        except APIError as e:
            raise _api_error_to_http(e) from e
        containers = [c for c in containers if is_trusted(c)]
    return list(_STATS_POOL.map(_stats_for, containers))


@api.get("/docker/logs/{name}")
def docker_logs(name: str, lines: int = Query(DEFAULT_LOG_LINES, ge=1, le=5000)):
    """Tail recent logs for a managed container."""
    c = _trusted_container(name)
    try:
        raw = c.logs(tail=lines, stdout=True, stderr=True)
    except APIError as e:
        raise _api_error_to_http(e) from e
    total = len(raw)
    # keep the *end* of the logs if too big
    truncated = total > MAX_OUTPUT_BYTES
    if truncated:
        raw = raw[-MAX_OUTPUT_BYTES:]
    return {
        "name": name,
        "logs": raw.decode("utf-8", errors="replace"),
        "truncated": truncated,
        "bytes_total": total,
    }


# ─── Command execution ─────────────────────────────────────────────────────────


class ExecRequest(BaseModel):
    """Arguments for `docker exec`.

    `cmd` is an argv list (e.g. ["curl", "-s", "https://example.com"]).
    It is passed straight to the exec API, NOT through a shell.
    """
    cmd: List[str]
    workdir: Optional[str] = None
    user: Optional[str] = None
    timeout: int = Field(default=DEFAULT_EXEC_TIMEOUT, ge=1, le=MAX_EXEC_TIMEOUT)


_EXEC_SLOTS = threading.BoundedSemaphore(EXEC_MAX_CONCURRENCY)
_TIMEOUT_PROBE_LOCK = threading.Lock()
# container id -> is the `timeout` binary usable? Probed once, then cached.
#
# Bounded on purpose: the key is the container ID, which changes on every
# recreation, so an unbounded dict retains a dead entry for every container ever
# probed -- a slow leak in a long-lived process. 256 is far more containers than
# this service will ever manage concurrently.
_TIMEOUT_CAPABLE_MAX = 256
_TIMEOUT_CAPABLE: "OrderedDict[str, bool]" = OrderedDict()


def _timeout_capability_get(container_id: str) -> Optional[bool]:
    with _TIMEOUT_PROBE_LOCK:
        if container_id in _TIMEOUT_CAPABLE:
            _TIMEOUT_CAPABLE.move_to_end(container_id)
            return _TIMEOUT_CAPABLE[container_id]
        return None


def _timeout_capability_put(container_id: str, ok: bool) -> None:
    with _TIMEOUT_PROBE_LOCK:
        _TIMEOUT_CAPABLE[container_id] = ok
        _TIMEOUT_CAPABLE.move_to_end(container_id)
        while len(_TIMEOUT_CAPABLE) > _TIMEOUT_CAPABLE_MAX:
            evicted_id, evicted = _TIMEOUT_CAPABLE.popitem(last=False)
            logger.debug("evicted timeout-probe cache entry for %s (%s)", evicted_id, evicted)


def _has_timeout_binary(container) -> bool:
    """Does this container have a usable `timeout` binary?

    Probed with `timeout --help`, which exits 0 on both GNU coreutils and
    BusyBox. (`--version` is GNU-only: BusyBox answers "unrecognized option"
    and exits non-zero, so it is useless as a capability probe.)

    IMPORTANT: `get_client().api` is the low-level APIClient. It has
    exec_create / exec_start / exec_inspect but NOT exec_run - exec_run only
    exists on the Container model (container.exec_run). Calling it on the API
    object raises AttributeError, so the probe must go through the container.

    A failed probe is logged rather than silently swallowed: the previous
    version hid an AttributeError here and reported "no timeout binary" for
    every container, which quietly turned timeout enforcement off.
    """
    if not USE_TIMEOUT_WRAPPER:
        return False
    cached = _timeout_capability_get(container.id)
    if cached is not None:
        return cached
    try:
        res = container.exec_run(["timeout", "--help"])
        code = res.exit_code
        ok = code is not None and code == 0
    except Exception as e:
        logger.warning(
            "timeout probe failed for %s, assuming no wrapper: %s", container.name, e
        )
        ok = False
    _timeout_capability_put(container.id, ok)
    if not ok:
        logger.warning(
            "container %s has no usable `timeout` binary: commands will be "
            "returned at the deadline but not killed",
            container.name,
        )
    return ok


class ExecOutcome:
    __slots__ = (
        "stdout", "stderr", "timed_out", "exit_code",
        "bytes_total_out", "bytes_total_err", "wrapped",
        "stdout_truncated", "stderr_truncated", "stream_stopped_early",
    )

    def __init__(self) -> None:
        self.stdout = b""
        self.stderr = b""
        self.timed_out = False
        self.exit_code: Optional[int] = None
        self.bytes_total_out = 0
        self.bytes_total_err = 0
        self.wrapped = False
        # Recorded while streaming, because the finished buffers are already
        # capped and cannot reveal that they were capped.
        self.stdout_truncated = False
        self.stderr_truncated = False
        self.stream_stopped_early = False


def _run_exec(container, argv: List[str], workdir, user, timeout: int) -> ExecOutcome:
    """Run one command with bounded buffering and a wall-clock deadline.

    Replaces exec_run(demux=True), which concatenated every frame into a single
    bytes object *before* any truncation: `yes` allocated 34 GB in 2 seconds
    (measured) and this service ran with no memory limit at all.

    The `timeout -s KILL` wrapper is kept, because the Docker API has no
    exec-kill endpoint (exec_inspect exposes no PID), so it is the only way to
    actually terminate a hung command without killing the container. What is
    removed is the old *guessing*: previously any exit code 126/127 whose
    output merely contained "timeout" - or any unmatched APIError - caused the
    command to be re-executed unwrapped, so commands with side effects ran
    twice. Capability is now probed deterministically and cached per container.

    Two independent limits now stop the read loop:

    * the wall-clock deadline (timeout + grace), and
    * a read budget of MAX_OUTPUT_BYTES * EXEC_READ_BUDGET_FACTOR.

    The budget matters because the buffers being full does NOT stop the old
    loop: it kept reading and discarding every frame until the deadline, so a
    `yes`-style command could hold a socket, a worker and CPU for the full
    timeout even though nothing more could be stored. Abandoning the stream
    early is safe here: the `timeout` wrapper is what kills the process, and it
    is unaffected by us detaching.
    """
    api = get_client().api
    out = ExecOutcome()

    wrapped = _has_timeout_binary(container)
    out.wrapped = wrapped
    final_argv = (
        ["timeout", "-s", "KILL", str(timeout)] + argv if wrapped else list(argv)
    )

    exec_id = api.exec_create(
        container.id, final_argv, stdout=True, stderr=True,
        workdir=workdir, user=user,
    )["Id"]

    stream = api.exec_start(exec_id, stream=True, demux=True)
    deadline = time.monotonic() + timeout + EXEC_GRACE_SECONDS
    read_budget = MAX_OUTPUT_BYTES * max(EXEC_READ_BUDGET_FACTOR, 1)
    read_total = 0
    exceeded = False

    try:
        for chunk_out, chunk_err in stream:
            if chunk_out:
                out.bytes_total_out += len(chunk_out)
                room = MAX_OUTPUT_BYTES - len(out.stdout)
                if room > 0:
                    out.stdout += chunk_out[:room]
                read_total += len(chunk_out)
            if chunk_err:
                out.bytes_total_err += len(chunk_err)
                room = MAX_OUTPUT_BYTES - len(out.stderr)
                if room > 0:
                    out.stderr += chunk_err[:room]
                read_total += len(chunk_err)
            if time.monotonic() > deadline:
                # A bounded read loop would otherwise never end (e.g. `yes`).
                exceeded = True
                break
            if read_total >= read_budget:
                # Both buffers are certainly full by now in the runaway case;
                # stop paying for data we cannot return.
                out.stream_stopped_early = True
                break
    finally:
        try:
            stream.close()  # detaches the socket; does not kill the process
        except Exception:
            pass

    # Derived from the counters (everything read), not from the buffers (capped).
    out.stdout_truncated = out.bytes_total_out > MAX_OUTPUT_BYTES
    out.stderr_truncated = out.bytes_total_err > MAX_OUTPUT_BYTES

    try:
        out.exit_code = api.exec_inspect(exec_id).get("ExitCode")
    except Exception:
        out.exit_code = None

    # The wrapper is authoritative when present: `timeout -s KILL` reports 137
    # (or 124 with TERM) once it has killed the child, so this is not a guess.
    if wrapped:
        out.timed_out = out.exit_code in (124, 137)
    else:
        out.timed_out = exceeded

    return out


@api.post("/docker/exec/{name}")
def docker_exec(name: str, body: ExecRequest):
    """Run a single command inside a managed container and return its output.

    Returns: {"name", "exit_code", "stdout", "stderr", "timed_out",
              "stdout_truncated", "stderr_truncated", "bytes_total_out",
              "bytes_total_err", "duration_s", "timeout_enforced",
              "stream_stopped_early"}
    """
    c = _trusted_container(name)

    if not body.cmd:
        raise HTTPException(status_code=400, detail="`cmd` must be a non-empty list of arguments.")
    if not all(isinstance(a, str) for a in body.cmd):
        raise HTTPException(status_code=400, detail="`cmd` must contain only strings.")

    if not _EXEC_SLOTS.acquire(blocking=False):
        raise HTTPException(
            status_code=429,
            detail="Too many commands are still running. Try again later.",
        )

    start = time.monotonic()
    try:
        outcome = _run_exec(c, body.cmd, body.workdir, body.user, body.timeout)
    except NotFound:
        raise HTTPException(status_code=404, detail=f"Container '{name}' not found.")
    except APIError as e:
        raise _api_error_to_http(e) from e
    except Exception as e:  # noqa: BLE001 - never leak a bare traceback as a 500
        raise HTTPException(status_code=502, detail=f"exec failed: {e}") from e
    finally:
        _EXEC_SLOTS.release()

    duration = round(time.monotonic() - start, 2)
    # Pass the flags recorded during streaming: the buffers below are already
    # capped, so re-deriving truncation from them would always answer "no".
    o = _truncate(outcome.stdout, outcome.stdout_truncated)
    e = _truncate(outcome.stderr, outcome.stderr_truncated)
    return {
        "name": name,
        "exit_code": outcome.exit_code,
        "stdout": o["text"],
        "stderr": e["text"],
        "stdout_truncated": o["truncated"],
        "stderr_truncated": e["truncated"],
        "bytes_total_out": outcome.bytes_total_out,
        "bytes_total_err": outcome.bytes_total_err,
        "timed_out": outcome.timed_out,
        "timeout_enforced": outcome.wrapped,
        "stream_stopped_early": outcome.stream_stopped_early,
        "duration_s": duration,
    }


# ─── Destructive endpoints ─────────────────────────────────────────────────────


@api.post("/docker/start/{name}")
def docker_start(name: str):
    """Start a stopped managed container. ASK USER BEFORE CALLING."""
    c = _trusted_container(name)
    try:
        c.start()
    except APIError as e:
        raise _api_error_to_http(e) from e
    return {"name": name, "action": "started"}


@api.post("/docker/restart/{name}")
def docker_restart(name: str):
    """Restart a managed container. ASK USER BEFORE CALLING."""
    c = _trusted_container(name)
    _require_not_protected(c)
    try:
        c.restart(timeout=10)
    except APIError as e:
        raise _api_error_to_http(e) from e
    return {"name": name, "action": "restarted"}


@api.post("/docker/stop/{name}")
def docker_stop(name: str):
    """Stop a managed container. Use /docker/start to bring it back. ASK USER BEFORE CALLING."""
    c = _trusted_container(name)
    _require_not_protected(c)
    try:
        c.stop(timeout=10)
    except APIError as e:
        raise _api_error_to_http(e) from e
    return {
        "name": name,
        "action": "stopped",
        "hint": "It stays down until POST /docker/start/{name}.",
    }


@api.delete("/docker/rm/{name}")
def docker_rm(name: str, force: bool = False):
    """Remove a managed container. ASK USER BEFORE CALLING."""
    c = _trusted_container(name)
    _require_not_protected(c)
    try:
        c.remove(force=force)
    except APIError as e:
        raise _api_error_to_http(e) from e
    return {"name": name, "action": "removed"}


app.include_router(api)

# ─── Health (unauthenticated, for container healthchecks) ──────────────────────


@app.get("/health")
def health():
    """Unauthenticated on purpose: the container healthcheck cannot send a key.

    Because it is the one endpoint without auth, it must not reflect daemon
    state back to the caller. The reason is logged, not returned -- the old
    version put `str(e)` (a raw docker-py/OS error, including socket paths and
    daemon messages) in the 503 body for anyone on the network to read.
    """
    try:
        get_client().ping()
        return {"status": "ok", "docker": "connected"}
    except Exception as e:
        logger.warning("health check failed: %s", e)
        raise HTTPException(
            status_code=503, detail="Docker socket is not reachable."
        ) from e
