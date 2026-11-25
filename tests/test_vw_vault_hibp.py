"""The hibp check against a fake HTTP layer: retries, 429, partial failure. No network."""

import hashlib
import json
import threading
import time

import httpx
from vw_vault import checks

from test_vw_vault import login, make, state  # noqa: F401  (state is a fixture)


def sha(pw: str) -> str:
    return hashlib.sha1(pw.encode()).hexdigest().upper()


PW_A, PW_B = "first-password-AAA", "second-password-BBB"
A, B = sha(PW_A), sha(PW_B)
ITEMS = [login("a", "A", "a.example", pw=PW_A), login("b", "B", "b.example", pw=PW_B)]


def body(full: str, count: int) -> str:
    """A range answer carrying the suffix of `full` plus padding rows with a zero count."""
    return f"{full[5:]}:{count}\r\n{'0' * 35}:0\r\n"


class Fake:
    """Answers by prefix from a script: each prefix maps to a list of outcomes, used in order
    (the last one repeats). An outcome is an int status, an Exception, or (status, headers)."""

    def __init__(self, script: dict):
        self.script, self.calls, self.lock = script, {}, threading.Lock()
        self.client = httpx.Client(transport=httpx.MockTransport(self.handle))

    def handle(self, request: httpx.Request) -> httpx.Response:
        prefix = request.url.path.rsplit("/", 1)[-1]
        with self.lock:
            n = self.calls[prefix] = self.calls.get(prefix, 0) + 1
            steps = self.script[prefix]
            step = steps[min(n, len(steps)) - 1]
        if isinstance(step, Exception):
            raise step
        if isinstance(step, tuple):
            return httpx.Response(step[0], headers=step[1])
        if isinstance(step, int):
            return httpx.Response(step)
        return httpx.Response(200, text=step)


def run(script, sleeps=None):
    fake = Fake(script)
    waited = [] if sleeps is None else sleeps
    res = checks.hibp(ITEMS, client=fake.client, sleep=waited.append)
    return fake, res, waited


def test_hits_and_padding_rows_ignored():
    _, res, waited = run({A[:5]: [body(A, 7)], B[:5]: [body(B, 0)]})
    assert res.hits == {"a": 7}
    assert res.unchecked == {} and res.ranges == 2 and waited == []


def test_sends_user_agent_and_padding_header():
    seen = []
    client = httpx.Client(transport=httpx.MockTransport(lambda r: seen.append(r.headers) or httpx.Response(200, text="")))
    checks.hibp(ITEMS[:1], client=client, sleep=lambda s: None)
    assert seen[0]["user-agent"] == checks.USER_AGENT and seen[0]["add-padding"] == "true"


def test_timeout_is_retried_with_growing_backoff():
    timeout = httpx.ReadTimeout("slow")
    fake, res, waited = run({A[:5]: [timeout, timeout, body(A, 3)], B[:5]: [body(B, 0)]})
    assert res.hits == {"a": 3} and res.unchecked == {}
    assert fake.calls[A[:5]] == 3
    assert len(waited) == 2
    assert checks.HIBP_BACKOFF <= waited[0] <= checks.HIBP_BACKOFF * 1.5
    assert 2 * checks.HIBP_BACKOFF <= waited[1] <= 3 * checks.HIBP_BACKOFF


def test_connection_error_and_5xx_are_retried():
    _, res, _ = run({A[:5]: [httpx.ConnectError("reset"), 503, body(A, 1)], B[:5]: [body(B, 0)]})
    assert res.hits == {"a": 1} and res.unchecked == {}


def test_429_honours_retry_after():
    _, res, waited = run({A[:5]: [(429, {"Retry-After": "7"}), body(A, 2)], B[:5]: [body(B, 0)]})
    assert res.hits == {"a": 2}
    assert waited == [7.0]


def test_429_retry_after_is_capped_and_a_date_falls_back_to_backoff():
    _, _, waited = run({A[:5]: [(429, {"Retry-After": "86400"}), (429, {"Retry-After": "Wed, 11 Nov 2026 10:00:00 GMT"}),
                                body(A, 2)], B[:5]: [body(B, 0)]})
    assert waited[0] == checks.HIBP_RETRY_AFTER_MAX
    assert 2 * checks.HIBP_BACKOFF <= waited[1] <= 3 * checks.HIBP_BACKOFF


def test_client_error_is_not_retried():
    fake, res, waited = run({A[:5]: [404], B[:5]: [body(B, 5)]})
    assert fake.calls[A[:5]] == 1 and waited == []
    assert set(res.unchecked) == {A[:5]} and res.unchecked_ids == {"a"}
    assert res.hits == {"b": 5}


def test_a_range_out_of_attempts_is_unchecked_and_the_rest_still_counts():
    timeout = httpx.ReadTimeout("slow")
    fake, res, waited = run({A[:5]: [timeout], B[:5]: [body(B, 9)]})
    assert fake.calls[A[:5]] == checks.HIBP_ATTEMPTS
    assert len(waited) == checks.HIBP_ATTEMPTS - 1
    assert res.hits == {"b": 9}
    assert res.unchecked == {A[:5]: {"a"}} and res.ranges == 2


def test_persistent_429_is_unchecked_too():
    _, res, _ = run({A[:5]: [(429, {"Retry-After": "1"})], B[:5]: [body(B, 0)]})
    assert res.unchecked_ids == {"a"}


def test_garbled_body_is_unchecked():
    _, res, _ = run({A[:5]: [f"{A[5:]}:many\r\n"], B[:5]: [body(B, 0)]})
    assert res.unchecked_ids == {"a"}


def test_progress_counts_failed_ranges_as_done():
    seen = []
    fake = Fake({A[:5]: [httpx.ReadTimeout("x")], B[:5]: [body(B, 0)]})
    checks.hibp(ITEMS, lambda d, t: seen.append((d, t)), client=fake.client, sleep=lambda s: None)
    assert seen[-1] == (2, 2)


# --- the engine ---------------------------------------------------------------------------


def wait(eng):
    for _ in range(200):
        if not eng.busy():
            return eng.job_status()
        time.sleep(0.01)
    raise AssertionError("job did not finish")


def test_engine_reports_not_checked_and_keeps_the_hits(state, monkeypatch):
    eng, _ = make(ITEMS, state)
    monkeypatch.setattr(checks, "hibp", lambda items, progress=None: checks.HibpResult(
        hits={"b": 4}, unchecked={A[:5]: {"a"}}, ranges=2))
    eng.check("hibp")
    job = wait(eng)
    assert job["state"] == "done", job
    out = job["result"]
    assert (out["items"], out["ranges"], out["not_checked"], out["not_checked_ranges"]) == (1, 2, 1, 1)
    saved = json.loads((state / "check-hibp.json").read_text())["result"]
    assert [r["id"] for r in saved["pwned"]] == ["b"] and [r["id"] for r in saved["not_checked"]] == ["a"]
    assert PW_A not in json.dumps(saved) and PW_B not in json.dumps(saved)


def test_engine_fails_when_nothing_could_be_checked(state, monkeypatch):
    eng, _ = make(ITEMS, state)
    monkeypatch.setattr(checks, "hibp", lambda items, progress=None: checks.HibpResult(
        unchecked={A[:5]: {"a"}, B[:5]: {"b"}}, ranges=2))
    eng.check("hibp")
    job = wait(eng)
    assert job["state"] == "failed" and "every range lookup failed" in job["error"]
