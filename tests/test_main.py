"""Tests for the parts of docker-exec that have actually broken before.

These are deliberately narrow. The service's history includes two incidents that
a handful of unit tests would have caught:

  * the `timeout` probe calling a method that does not exist on APIClient,
    silently turning timeout enforcement off fleet-wide (1.2.1), and
  * truncation flags that could never be true because they were derived from an
    already-capped buffer.

So the trust model, the probe cache, the truncation/read-budget path and the
unauthenticated /health response are covered here. Nothing in this file talks to
a real Docker daemon.
"""

import pytest
from fastapi.testclient import TestClient

import main


# ─── Fakes ─────────────────────────────────────────────────────────────────────


class FakeContainer:
    def __init__(self, name="c1", cid="a" * 64, labels=None):
        self.name = name
        self.id = cid
        self.attrs = {"Config": {"Labels": labels or {}}}


class FakeStream:
    """Mimics docker-py's CancellableStream closely enough for _run_exec."""

    def __init__(self, frames):
        self._frames = frames
        self.closed = False

    def __iter__(self):
        return iter(self._frames)

    def close(self):
        self.closed = True


class FakeApi:
    def __init__(self, frames, exit_code=0):
        self.stream = FakeStream(frames)
        self._exit_code = exit_code

    def exec_create(self, *args, **kwargs):
        return {"Id": "exec-1"}

    def exec_start(self, *args, **kwargs):
        return self.stream

    def exec_inspect(self, exec_id):
        return {"ExitCode": self._exit_code}


class FakeClient:
    def __init__(self, frames, exit_code=0):
        self.api = FakeApi(frames, exit_code)


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    """Every test starts with no allowlist and an empty probe cache."""
    monkeypatch.setattr(main, "ALLOWLIST", set())
    monkeypatch.setattr(main, "PROTECTED", {"docker-exec"})
    main._TIMEOUT_CAPABLE.clear()
    yield
    main._TIMEOUT_CAPABLE.clear()


# ─── Trust model ───────────────────────────────────────────────────────────────


def test_untrusted_without_label():
    assert main.is_trusted(FakeContainer(labels={})) is False


def test_untrusted_when_managed_but_unsigned():
    """The whole point of 1.2.0: `managed=true` alone must grant nothing."""
    assert main.is_trusted(FakeContainer(labels={"managed": "true"})) is False


def test_managed_label_must_be_exactly_true():
    for value in ("1", "yes", "TRUE", ""):
        c = FakeContainer(labels={"managed": value})
        assert main.is_trusted(c) is False, value


def test_trusted_with_valid_signature(monkeypatch):
    monkeypatch.setattr(main, "ALLOWLIST", set())
    c = FakeContainer(cid="b" * 64, labels={"managed": "true"})
    c.attrs["Config"]["Labels"]["managed.signature"] = main._sign(c.id)
    assert main.is_trusted(c) is True


def test_untrusted_with_forged_signature(monkeypatch):
    monkeypatch.setattr(main, "ALLOWLIST", set())
    c = FakeContainer(cid="b" * 64, labels={"managed": "true",
                                            "managed.signature": "0" * 64})
    assert main.is_trusted(c) is False


def test_signature_bound_to_container_id(monkeypatch):
    """A signature minted for one container must not validate for another.

    This is the property that stops someone re-creating a container and
    reusing the previous container's label.
    """
    monkeypatch.setattr(main, "ALLOWLIST", set())
    sig = main._sign("c" * 64)
    c = FakeContainer(cid="d" * 64, labels={"managed": "true",
                                            "managed.signature": sig})
    assert main.is_trusted(c) is False


def test_allowlisted_name_is_trusted_by_name(monkeypatch):
    monkeypatch.setattr(main, "ALLOWLIST", {"allowed"})
    c = FakeContainer(name="allowed", labels={"managed": "true"})
    assert main.is_trusted(c) is True


def test_allowlist_still_requires_the_managed_label(monkeypatch):
    monkeypatch.setattr(main, "ALLOWLIST", {"allowed"})
    assert main.is_trusted(FakeContainer(name="allowed", labels={})) is False


def test_allowlist_shadows_a_valid_signature(monkeypatch):
    """Documents the documented ordering: name match wins over HMAC.

    This is intentional behaviour (see README, "Consequences of signing"), but
    it means allowlisting a signed container silently downgrades it -- so it
    gets a test rather than being folklore.
    """
    c = FakeContainer(cid="e" * 64, name="listed", labels={"managed": "true"})
    c.attrs["Config"]["Labels"]["managed.signature"] = main._sign(c.id)
    monkeypatch.setattr(main, "ALLOWLIST", {"listed"})
    assert main.is_trusted(c) is True


def test_protected_is_name_based():
    c = FakeContainer(name="docker-exec", labels={"managed": "true"})
    with pytest.raises(main.HTTPException) as exc:
        main._require_not_protected(c)
    assert exc.value.status_code == 403


def test_sign_is_deterministic_and_key_dependent(monkeypatch):
    assert main._sign("x") == main._sign("x")
    first = main._sign("x")
    monkeypatch.setattr(main, "SIGNING_KEY", "a-different-key")
    assert main._sign("x") != first


# ─── Truncation ────────────────────────────────────────────────────────────────


def test_truncate_reports_overflow_when_derived(monkeypatch):
    monkeypatch.setattr(main, "MAX_OUTPUT_BYTES", 4)
    out = main._truncate(b"abcdefgh")
    assert out["truncated"] is True
    assert out["bytes_total"] == 8
    assert len(out["text"]) == 4


def test_truncate_explicit_flag_wins(monkeypatch):
    """This is the 1.2.2 fix: the streaming path already knows it overflowed.

    With only the capped buffer in hand the derived answer would be False,
    which is exactly the bug.
    """
    monkeypatch.setattr(main, "MAX_OUTPUT_BYTES", 100)
    out = main._truncate(b"short", truncated=True)
    assert out["truncated"] is True


def test_truncate_handles_utf8_boundary(monkeypatch):
    """Cutting mid-character must not raise; it must yield U+FFFD."""
    monkeypatch.setattr(main, "MAX_OUTPUT_BYTES", 3)
    out = main._truncate("éé".encode("utf-8"))  # 4 bytes, cut at 3
    assert out["truncated"] is True
    assert "\ufffd" in out["text"]


def test_truncate_empty():
    out = main._truncate(b"")
    assert out == {"text": "", "truncated": False, "bytes_total": 0}


# ─── Probe cache bound ─────────────────────────────────────────────────────────


def test_timeout_cache_is_bounded():
    for i in range(main._TIMEOUT_CAPABLE_MAX + 50):
        main._timeout_capability_put(f"id-{i}", True)
    assert len(main._TIMEOUT_CAPABLE) == main._TIMEOUT_CAPABLE_MAX


def test_timeout_cache_evicts_least_recently_used():
    """The entry that was never touched is the one evicted.

    Ordering is easy to get backwards, so this is spelled out: after three
    inserts the order is [oldest, second, first]; touching "first" and "second"
    moves them to the tail, leaving "oldest" at the head. Filling the cache then
    evicts from the head, so "oldest" must be the casualty while both touched
    entries survive.
    """
    main._timeout_capability_put("oldest", True)
    main._timeout_capability_put("second", True)
    main._timeout_capability_put("first", True)
    main._timeout_capability_get("first")
    main._timeout_capability_get("second")

    # Three entries exist; adding MAX-2 more would reach MAX+1, so exactly one
    # eviction happens.
    for i in range(main._TIMEOUT_CAPABLE_MAX - 2):
        main._timeout_capability_put(f"k-{i}", True)

    assert len(main._TIMEOUT_CAPABLE) == main._TIMEOUT_CAPABLE_MAX
    assert "oldest" not in main._TIMEOUT_CAPABLE, "LRU entry should have been evicted"
    assert "first" in main._TIMEOUT_CAPABLE
    assert "second" in main._TIMEOUT_CAPABLE


def test_timeout_cache_hit_and_miss():
    assert main._timeout_capability_get("nope") is None
    main._timeout_capability_put("yes", False)
    assert main._timeout_capability_get("yes") is False


def test_timeout_cache_does_not_confuse_false_with_miss():
    """A cached False must not be re-probed; `is None` is the miss check."""
    main._timeout_capability_put("c", False)
    assert main._timeout_capability_get("c") is False


# ─── Exec stream: read budget and truncation flags ────────────────────────────


def _run(monkeypatch, frames, cap=10, factor=2, exit_code=0, wrapped=True,
         timeout=30, duration=None):
    """Run _run_exec against fakes.

    `duration` freezes time.monotonic() at start=0 and advances it only inside
    exec_start, so `duration_s` is deterministic. Without it the measured
    runtime is ~0, which is correct for these instant frames but makes the
    timeout cases impossible to exercise.
    """
    monkeypatch.setattr(main, "MAX_OUTPUT_BYTES", cap)
    monkeypatch.setattr(main, "EXEC_READ_BUDGET_FACTOR", factor)
    monkeypatch.setattr(main, "_has_timeout_binary", lambda c: wrapped)
    client = FakeClient(frames, exit_code)
    monkeypatch.setattr(main, "get_client", lambda: client)
    if duration is not None:
        clock = {"t": 0.0}
        real = main.time.monotonic
        monkeypatch.setattr(main.time, "monotonic", lambda: clock["t"])
        inner = client.api.exec_start

        def advancing_exec_start(*a, **k):
            clock["t"] += duration
            return inner(*a, **k)

        client.api.exec_start = advancing_exec_start
    container = FakeContainer()
    out = main._run_exec(container, ["cmd"], None, None, timeout)
    return out, client.api.stream


def test_read_loop_stops_at_budget(monkeypatch):
    """A runaway command must not be read to the deadline.

    Budget here is 10*2 = 20 bytes, so two 10-byte frames are read and the
    third is never consumed.
    """
    frames = [(b"a" * 10, None)] * 5
    out, stream = _run(monkeypatch, frames)

    assert out.stream_stopped_early is True
    assert out.bytes_total_out == 20
    assert len(out.stdout) == 10
    assert stream.closed is True, "the stream must be detached on breakout"


def test_truncation_flags_set_when_output_exceeds_cap(monkeypatch):
    frames = [(b"a" * 10, None)] * 5
    out, _ = _run(monkeypatch, frames)
    assert out.stdout_truncated is True
    assert out.stderr_truncated is False


def test_small_output_is_not_flagged_or_cut_short(monkeypatch):
    frames = [(b"hi", b"there")]
    out, stream = _run(monkeypatch, frames, cap=100, factor=4)

    assert out.stream_stopped_early is False
    assert out.stdout == b"hi"
    assert out.stderr == b"there"
    assert out.stdout_truncated is False
    assert out.stderr_truncated is False
    assert stream.closed is True


def test_separate_stdout_and_stderr_counters(monkeypatch):
    frames = [(b"x" * 5, b"y" * 5), (b"x" * 5, b"y" * 5)]
    out, _ = _run(monkeypatch, frames, cap=4, factor=4)
    assert out.bytes_total_out == 10
    assert out.bytes_total_err == 10
    assert len(out.stdout) == 4
    assert len(out.stderr) == 4
    assert out.stdout_truncated is True
    assert out.stderr_truncated is True


def test_timed_out_requires_duration_not_just_exit_code(monkeypatch):
    """The 1.3.0 fix. Exit code alone was the bug.

    Measured on 1.2.2 against the live service: ["sh","-c","exit 137"]
    returned `timed_out: true` with duration_s 0.02 and a 30s timeout, and the
    calling tool then told the user "the command hit the 30s timeout".

    A real timeout has necessarily run for about the whole timeout, because the
    wrapper kills the child AT the deadline.
    """
    # Ran the whole timeout then reported 137 -> a genuine timeout.
    for code in (137, 124):
        out, _ = _run(monkeypatch, [(b"", None)], exit_code=code,
                      timeout=30, duration=30.0)
        assert out.timed_out is True, code

    # Exited 137 immediately -> NOT a timeout, whatever the exit code says.
    for code in (137, 124):
        out, _ = _run(monkeypatch, [(b"", None)], exit_code=code,
                      timeout=30, duration=0.02)
        assert out.timed_out is False, code

    # Ordinary exits are never timeouts, however long they ran.
    for code in (0, 1, 127, 130):
        out, _ = _run(monkeypatch, [(b"", None)], exit_code=code,
                      timeout=30, duration=30.0)
        assert out.timed_out is False, code


def test_duration_is_the_runtime_not_the_whole_request(monkeypatch):
    """duration_s must measure exec_start onward, not container lookup etc.

    If it included exec_create and the probe, a fast exit-137 could look long
    enough to be a timeout, reinstating the bug this change removes.
    """
    out, _ = _run(monkeypatch, [(b"", None)], exit_code=137,
                  timeout=30, duration=0.02)
    assert out.duration_s == pytest.approx(0.02, abs=1e-6)


def test_unwrapped_container_is_not_reported_as_enforced(monkeypatch):
    """No wrapper binary -> the caller must be told enforcement was unavailable."""
    out, _ = _run(monkeypatch, [(b"ok", None)], wrapped=False)
    assert out.wrapped is False   # this is what maps to `timeout_enforced`
    assert out.timed_out is False


def test_unwrapped_timed_out_falls_back_to_the_read_loop(monkeypatch):
    """Without a wrapper there is no exit code to read, so `exceeded` decides.

    This path is unchanged by the 1.3.0 fix and must stay working: it is what
    a container with no `timeout` binary relies on.
    """
    monkeypatch.setattr(main, "EXEC_GRACE_SECONDS", 0)
    out, _ = _run(monkeypatch, [(b"x", None)] * 3, wrapped=False,
                  timeout=1, duration=2.0)
    assert out.timed_out is True


# ─── Timeout rule as a pure function ─────────────────────────────────────────


@pytest.mark.parametrize("code,dur,expected", [
    # A real timeout: reserved code AND ran to the deadline.
    (137, 30.0, True),
    (124, 30.0, True),
    # Ran to the deadline but exited normally -> the wrapper did not kill it.
    (0, 30.0, False),
    (1, 30.0, False),
    # Reserved code reached immediately -> self-inflicted, not our deadline.
    (137, 0.02, False),
    (124, 0.02, False),
    # Non-reserved codes are never timeouts, whatever the duration.
    (127, 30.0, False),
    (130, 30.0, False),
    (None, 30.0, False),
])
def test_is_timeout_truth_table(code, dur, expected):
    assert main._is_timeout(code, dur, 30) is expected


def test_is_timeout_tolerance_boundary():
    """The tolerance absorbs handshake jitter but must not swallow a fast exit.

    With timeout=30 the boundary is 29.5s. Just below it is not a timeout; just
    above is.
    """
    tol = main._TIMEOUT_DURATION_TOLERANCE_S
    assert main._is_timeout(137, 30 - tol + 0.001, 30) is True
    assert main._is_timeout(137, 30 - tol - 0.001, 30) is False


def test_tolerance_cannot_reinstate_the_bug_at_timeout_1():
    """Guards the constant against being raised past the minimum timeout.

    timeout=1 is permitted (ge=1). If the tolerance were >= 1s, an immediate
    exit 137 would satisfy `duration >= timeout - tolerance` and the original
    false positive would return for short timeouts.
    """
    assert main._TIMEOUT_DURATION_TOLERANCE_S < 1, (
        "tolerance must stay below the smallest permitted timeout (1s)"
    )
    assert main._is_timeout(137, 0.0, 1) is False


def test_exec_response_maps_truncation_from_outcome(monkeypatch):
    """/docker/exec must report truncation the stream observed, not re-derive it.

    This is the end-to-end version of the always-False truncation bug: the
    buffers are capped, so only the flags on the outcome can be trusted.
    """
    frames = [(b"a" * 10, None)] * 5
    monkeypatch.setattr(main, "MAX_OUTPUT_BYTES", 10)
    monkeypatch.setattr(main, "EXEC_READ_BUDGET_FACTOR", 2)
    monkeypatch.setattr(main, "_has_timeout_binary", lambda c: True)
    client = FakeClient(frames)
    monkeypatch.setattr(main, "get_client", lambda: client)
    monkeypatch.setattr(main, "_trusted_container", lambda n: FakeContainer(name=n))

    body = main.ExecRequest(cmd=["cmd"])
    result = main.docker_exec("c1", body)

    assert result["stdout_truncated"] is True
    assert result["stderr_truncated"] is False
    assert result["bytes_total_out"] == 20
    assert len(result["stdout"]) == 10
    assert result["stream_stopped_early"] is True
    assert result["timeout_enforced"] is True
    assert result["timed_out"] is False
    assert result["hint"] is None, "a fast success must not carry a hint"
    # The semaphore must be released even on this path.
    assert main._EXEC_SLOTS._value == main.EXEC_MAX_CONCURRENCY


# ─── Diagnostics: the 127 hint ───────────────────────────────────────────────


def _exec_body(cmd, timeout=30):
    return main.ExecRequest(cmd=cmd, timeout=timeout)


def _call_exec(monkeypatch, cmd, exit_code=127, wrapped=True, timeout=30):
    monkeypatch.setattr(main, "_has_timeout_binary", lambda c: wrapped)
    client = FakeClient([(b"", None)], exit_code)
    monkeypatch.setattr(main, "get_client", lambda: client)
    monkeypatch.setattr(main, "_trusted_container", lambda n: FakeContainer(name=n))
    return main.docker_exec("c1", _exec_body(cmd, timeout))


def test_hint_explains_single_element_with_spaces(monkeypatch):
    """The exact production payload must be self-explaining.

    cmd: ["echo probe-ok"] -> exit 127, and stderr says
    "timeout: failed to run command 'echo probe-ok'", which reads as though the
    service joined the arguments. The hint must contradict that reading.
    """
    result = _call_exec(monkeypatch, ["echo probe-ok"])
    assert result["hint"] is not None
    assert "no shell" in result["hint"]
    assert "sh" in result["hint"], "must offer the sh -c escape hatch"


def test_hint_absent_for_a_genuinely_missing_binary(monkeypatch):
    """A single-word name that simply is not installed is not a shape problem."""
    result = _call_exec(monkeypatch, ["definitely-not-installed-xyz"])
    assert result["hint"] is None


def test_hint_absent_for_multi_element_argv(monkeypatch):
    """Correctly-shaped argv must never be second-guessed."""
    result = _call_exec(monkeypatch, ["sh", "-c", "echo a b"])
    assert result["hint"] is None


def test_hint_absent_for_non_127_exits(monkeypatch):
    for code in (0, 1, 126, 137):
        result = _call_exec(monkeypatch, ["echo probe-ok"], exit_code=code)
        assert result["hint"] is None, code


def test_hint_absent_when_no_wrapper_is_present(monkeypatch):
    """Without the wrapper there is no `timeout:` prefix to misread."""
    result = _call_exec(monkeypatch, ["echo probe-ok"], wrapped=False)
    assert result["hint"] is None


# ─── Observability: every exec logs its outcome ─────────────────────────────


def test_every_exec_logs_one_line_without_command_text(monkeypatch, caplog):
    """Failure rate must be measurable from logs alone.

    Before 1.3.0 every exec logged `200 OK` whatever the exit code, so the only
    way to count failures was to read the calling application's database. The
    line must also NOT contain the command or the output: this service must not
    become a second copy of arbitrary, possibly secret-bearing data.
    """
    secret = "hunter2-do-not-log-me"
    with caplog.at_level("INFO", logger="docker-exec"):
        _call_exec(monkeypatch, ["printf", secret], exit_code=0)
    lines = [r.message for r in caplog.records if r.message.startswith("exec ")]
    assert len(lines) == 1, lines
    assert "exit_code=0" in lines[0]
    assert secret not in lines[0]
    assert "printf" not in lines[0]


def test_failed_exec_logs_at_warning(monkeypatch, caplog):
    with caplog.at_level("INFO", logger="docker-exec"):
        _call_exec(monkeypatch, ["sh", "-c", "false"], exit_code=1)
    exec_records = [r for r in caplog.records if r.message.startswith("exec ")]
    assert exec_records, "the exec line must be emitted"
    assert exec_records[0].levelname == "WARNING"
    assert "exit_code=1" in exec_records[0].message


# ─── Auth and /health ─────────────────────────────────────────────────────────


def test_protected_route_requires_api_key():
    client = TestClient(main.app)
    assert client.get("/docker/ps").status_code == 401
    assert client.get("/docker/ps", headers={"X-API-Key": "wrong"}).status_code == 401


def test_health_does_not_leak_the_daemon_error(monkeypatch):
    """The 503 body must be generic -- /health needs no auth.

    The old version returned str(e), which is a raw docker-py/OS error and can
    include socket paths and daemon messages.
    """
    secret_detail = "Cannot connect to /var/run/docker.sock: permission denied"

    def boom():
        raise RuntimeError(secret_detail)

    monkeypatch.setattr(main, "get_client", boom)
    response = TestClient(main.app).get("/health")

    assert response.status_code == 503
    assert "docker.sock" not in response.text
    assert "permission denied" not in response.text
    assert secret_detail not in response.text
    assert response.json()["detail"] == "Docker socket is not reachable."


def test_health_reports_ok_when_daemon_answers(monkeypatch):
    class PingingClient:
        def ping(self):
            return True

    monkeypatch.setattr(main, "get_client", lambda: PingingClient())
    response = TestClient(main.app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "docker": "connected"}
