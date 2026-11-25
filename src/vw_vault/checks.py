"""Checks run inside the daemon. Each returns per-item verdicts, never a value.

- leak_scan: are vault values present in local files (agent transcripts, shell history)?
- hibp: is a password in Have I Been Pwned (k-anonymity: only 5 hex of SHA-1 leave)?
- urls: does the site of a login still resolve and answer, where does it redirect?
- tokens: is an API token of a known service alive (GitHub, Telegram, Anthropic, ...)?
- twofa: does the site offer 2FA (2fa.directory) while the item has no TOTP?

No password is ever sent to a website: there is deliberately no login check.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import socket
import subprocess
import time
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .inventory import host_of, looks_secret, secret_values, token_kind

GREP = "/usr/bin/grep"  # GNU grep: -F with many patterns is Aho-Corasick fast
LEAK_MIN_LEN = 10
DEFAULT_LEAK_PATHS = ["~/.claude/projects", "~/.claude/history.jsonl", "~/.bash_history",
                      "~/.zsh_history", "~/.gemini", "~/.codex"]
HTTP_TIMEOUT = 10
USER_AGENT = "vw-vault-check/1 (+https://github.com/ai2sky/blind-vault-mcp)"
Progress = Callable[[int, int], None]


def _noop(done: int, total: int) -> None:
    pass


# --- leaks in local files -------------------------------------------------------


def _patterns(items: list[dict]) -> dict[str, set[str]]:
    """Search pattern -> item ids. Multi-line values are represented by their longest line."""
    out: dict[str, set[str]] = defaultdict(set)
    for item in items:
        if item.get("deletedDate"):
            continue
        for where, value in secret_values(item):
            if where == "notes":
                # a whole note: search only its secret-looking lines
                for ln in (x.strip() for x in value.splitlines()):
                    if looks_secret("notes:line", ln) and len(ln) >= LEAK_MIN_LEN:
                        out[ln].add(item["id"])
                continue
            if not looks_secret(where, value):
                continue
            line = max(value.splitlines() or [""], key=len).strip()
            if len(line) < LEAK_MIN_LEN or line.isdigit():
                continue
            out[line].add(item["id"])
            escaped = json.dumps(line, ensure_ascii=False)[1:-1]
            if escaped != line:
                out[escaped].add(item["id"])  # how it looks inside a JSON transcript
    return out


def leak_scan(items: list[dict], paths: list[str] | None = None, exclude: list[str] | None = None) -> dict:
    """Which items have a value inside the given files. Returns ids and file paths only."""
    patterns = _patterns(items)
    targets = [str(Path(p).expanduser()) for p in (paths or DEFAULT_LEAK_PATHS)]
    targets = [p for p in targets if os.path.exists(p)]
    if not patterns or not targets:
        return {"items": {}, "scanned": targets}
    read_fd, write_fd = os.pipe()
    cmd = [GREP, "-r", "-a", "-o", "-F", "-H", "--null", "-f", f"/dev/fd/{read_fd}"]
    for ex in exclude or []:
        cmd.append(f"--exclude-dir={ex}")
    proc = subprocess.Popen(cmd + targets, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            pass_fds=(read_fd,))
    os.close(read_fd)
    with os.fdopen(write_fd, "w") as w:
        w.write("\n".join(patterns) + "\n")
    found: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    assert proc.stdout is not None
    for raw in proc.stdout:
        path, _, match = raw.partition(b"\0")
        value = match.rstrip(b"\n").decode(errors="replace")
        for item_id in patterns.get(value, ()):
            found[item_id][path.decode(errors="replace")] += 1
    proc.wait()
    return {"items": {i: dict(files) for i, files in found.items()}, "scanned": targets}


# --- Have I Been Pwned ----------------------------------------------------------


HIBP_URL = "https://api.pwnedpasswords.com/range/"
HIBP_TIMEOUT = httpx.Timeout(30.0, connect=10.0)  # a range answers in well under a second; this only bounds a stall
HIBP_ATTEMPTS = 4  # per range: the first try and three retries
HIBP_BACKOFF = 1.0  # seconds before the first retry, doubled each time (plus up to 50% jitter)
HIBP_RETRY_AFTER_MAX = 60.0  # never sleep longer than this on a 429, whatever the server asks
HIBP_RETRY_STATUS = {429, 500, 502, 503, 504}


@dataclass
class HibpResult:
    """What the hibp check learned. `unchecked` are ranges that failed all their attempts."""
    hits: dict[str, int] = field(default_factory=dict)  # item id -> times seen in breaches
    unchecked: dict[str, set[str]] = field(default_factory=dict)  # range prefix -> item ids in it
    ranges: int = 0

    @property
    def unchecked_ids(self) -> set[str]:
        return set().union(*self.unchecked.values()) if self.unchecked else set()


def _retry_delay(attempt: int, resp: httpx.Response | None) -> float:
    """How long to wait before retry number `attempt` (0-based): Retry-After on a 429, else backoff."""
    if resp is not None:
        try:
            asked = float(resp.headers.get("Retry-After", ""))
        except ValueError:  # absent, or an HTTP date: fall back to the backoff
            asked = -1.0
        if asked >= 0:
            return min(asked, HIBP_RETRY_AFTER_MAX)
    base = HIBP_BACKOFF * 2 ** attempt
    return base * (1 + random.random() / 2)


def _hibp_range(client: httpx.Client, prefix: str, sleep: Callable[[float], None]) -> dict[str, int]:
    """Suffixes (with the prefix) seen in breaches. Retries a timeout, a dropped connection, a 429
    and a 5xx with backoff; any other error status fails at once. Raises httpx.HTTPError when out of attempts."""
    for attempt in range(HIBP_ATTEMPTS):
        resp = None
        try:
            resp = client.get(HIBP_URL + prefix, headers={"Add-Padding": "true", "User-Agent": USER_AGENT})
            if resp.status_code not in HIBP_RETRY_STATUS:
                resp.raise_for_status()
                out = {}
                for line in resp.text.splitlines():
                    suffix, _, n = line.partition(":")
                    if n.strip() != "0":
                        out[prefix + suffix.strip()] = int(n)
                return out
            if attempt == HIBP_ATTEMPTS - 1:
                resp.raise_for_status()
        except (httpx.TimeoutException, httpx.TransportError):
            if attempt == HIBP_ATTEMPTS - 1:
                raise
        sleep(_retry_delay(attempt, resp))
    raise AssertionError("unreachable")  # pragma: no cover


def hibp(items: list[dict], progress: Progress = _noop, *, client: httpx.Client | None = None,
         sleep: Callable[[float], None] = time.sleep) -> HibpResult:
    """Which passwords are in breaches. A range that keeps failing is reported in `unchecked`
    instead of voiding the run; the caller decides what a mostly-failed run means."""
    by_hash: dict[str, set[str]] = defaultdict(set)
    for item in items:
        pw = (item.get("login") or {}).get("password")
        if pw and not item.get("deletedDate"):
            by_hash[hashlib.sha1(pw.encode()).hexdigest().upper()].add(item["id"])
    by_prefix: dict[str, set[str]] = defaultdict(set)
    for full, ids in by_hash.items():
        by_prefix[full[:5]] |= ids
    prefixes = sorted(by_prefix)
    result = HibpResult(ranges=len(prefixes))
    own = client is None
    client = client or httpx.Client(timeout=HIBP_TIMEOUT, limits=httpx.Limits(max_connections=8))

    def fetch(prefix: str):
        try:
            return prefix, _hibp_range(client, prefix, sleep)
        except (httpx.HTTPError, ValueError):  # ValueError: a garbled body
            return prefix, None

    done = 0
    try:
        with ThreadPoolExecutor(8) as pool:
            for prefix, found in pool.map(fetch, prefixes):
                if found is None:
                    result.unchecked[prefix] = by_prefix[prefix]
                for full, n in (found or {}).items():
                    for item_id in by_hash.get(full, ()):
                        result.hits[item_id] = n
                done += 1
                progress(done, len(prefixes))
    finally:
        if own:
            client.close()
    return result


# --- sites ------------------------------------------------------------------------


def _probe(host: str, uri: str) -> dict:
    try:
        socket.getaddrinfo(host, 443)
    except (socket.gaierror, UnicodeError):
        return {"state": "dns-failed"}
    except OSError:
        return {"state": "dns-error"}
    target = uri if uri.startswith(("http://", "https://")) else f"https://{host}/"
    try:
        resp = httpx.get(target, timeout=HTTP_TIMEOUT, follow_redirects=True, verify=False,
                         headers={"User-Agent": USER_AGENT})
    except httpx.HTTPError as exc:
        return {"state": "unreachable", "error": type(exc).__name__}
    final = host_of(str(resp.url))
    return {"state": "ok" if resp.status_code < 400 else "http-error", "status": resp.status_code,
            "final_host": final, "moved": bool(final and final != host and not final.endswith("." + host))}


def urls(items: list[dict], progress: Progress = _noop) -> dict[str, dict]:
    """Host -> verdict, for every host of a live login. Sends no credentials."""
    first_uri: dict[str, str] = {}
    for item in items:
        if item.get("deletedDate") or item.get("type") != 1:
            continue
        for u in (item.get("login") or {}).get("uris") or []:
            if (h := host_of(u.get("uri"))) and h not in first_uri:
                uri = u["uri"].split("?", 1)[0].split("#", 1)[0]
                first_uri[h] = uri if "@" not in uri else f"https://{h}/"
    hosts = sorted(first_uri)
    out: dict[str, dict] = {}
    with ThreadPoolExecutor(32) as pool:
        for i, (host, verdict) in enumerate(zip(hosts, pool.map(lambda h: _probe(h, first_uri[h]), hosts)), 1):
            out[host] = verdict
            progress(i, len(hosts))
    return out


# --- API tokens ---------------------------------------------------------------------


def _check_token(kind: str, value: str, hosts: list[str]) -> dict:
    """Ask the issuing service whether a token works. Response bodies are not kept."""
    h = {"User-Agent": USER_AGENT}
    if kind.startswith("github"):
        r = httpx.get("https://api.github.com/user", timeout=HTTP_TIMEOUT,
                      headers={**h, "Authorization": f"token {value}"})
        info = {}
        if r.status_code == 200:
            info = {"account": r.json().get("login"), "scopes": r.headers.get("x-oauth-scopes"),
                    "expires": r.headers.get("github-authentication-token-expiration")}
        return {"alive": r.status_code == 200, "status": r.status_code, **info}
    if kind == "telegram-bot":
        r = httpx.get(f"https://api.telegram.org/bot{value}/getMe", timeout=HTTP_TIMEOUT, headers=h)
        ok = r.status_code == 200 and r.json().get("ok")
        return {"alive": bool(ok), "status": r.status_code,
                **({"account": "@" + r.json()["result"].get("username", "")} if ok else {})}
    if kind == "anthropic-api":
        r = httpx.get("https://api.anthropic.com/v1/models", timeout=HTTP_TIMEOUT,
                      headers={**h, "x-api-key": value, "anthropic-version": "2023-06-01"})
        return {"alive": r.status_code == 200, "status": r.status_code}
    if kind in ("openai", "openai-like"):
        r = httpx.get("https://api.openai.com/v1/models", timeout=HTTP_TIMEOUT,
                      headers={**h, "Authorization": f"Bearer {value}"})
        return {"alive": r.status_code == 200, "status": r.status_code}
    if kind == "openrouter":
        r = httpx.get("https://openrouter.ai/api/v1/key", timeout=HTTP_TIMEOUT,
                      headers={**h, "Authorization": f"Bearer {value}"})
        return {"alive": r.status_code == 200, "status": r.status_code}
    if kind == "gitlab-pat":
        base = next((x for x in hosts if "gitlab" in x), "gitlab.com")
        r = httpx.get(f"https://{base}/api/v4/personal_access_tokens/self", timeout=HTTP_TIMEOUT,
                      headers={**h, "PRIVATE-TOKEN": value})
        info = {"expires": r.json().get("expires_at"), "scopes": r.json().get("scopes")} if r.status_code == 200 else {}
        return {"alive": r.status_code == 200, "status": r.status_code, **info}
    if kind == "cloudflare":
        r = httpx.get("https://api.cloudflare.com/client/v4/user/tokens/verify", timeout=HTTP_TIMEOUT,
                      headers={**h, "Authorization": f"Bearer {value}"})
        ok = r.status_code == 200 and r.json().get("success")
        return {"alive": bool(ok), "status": r.status_code,
                **({"expires": r.json()["result"].get("expires_on")} if ok else {})}
    return {"alive": None, "status": None, "note": "no check for this kind"}


def tokens(items: list[dict], progress: Progress = _noop) -> list[dict]:
    """One verdict per (item, field) holding a recognised token."""
    jobs = []
    for item in items:
        if item.get("deletedDate"):
            continue
        hosts = [h for u in (item.get("login") or {}).get("uris") or [] if (h := host_of(u.get("uri")))]
        text = " ".join([item.get("name") or "", *hosts]).lower()
        for where, value in secret_values(item):
            if where.startswith("notes:") or where == "passwordHistory" or not isinstance(value, str):
                continue
            kind = token_kind(value.strip())
            if not kind and "cloudflare" in text and len(value.strip()) == 40:
                kind = "cloudflare"
            if kind and kind not in ("jwt", "pem", "aws-access-key", "anthropic-oauth"):
                jobs.append((item["id"], where, kind, value.strip(), hosts))

    def run(job):
        item_id, where, kind, value, hosts = job
        try:
            verdict = _check_token(kind, value, hosts)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            verdict = {"alive": None, "error": type(exc).__name__}
        return {"id": item_id, "where": where, "kind": kind, **verdict}

    out = []
    with ThreadPoolExecutor(4) as pool:
        for i, result in enumerate(pool.map(run, jobs), 1):
            out.append(result)
            progress(i, len(jobs))
    return out


# --- second factor ------------------------------------------------------------------


TFA_URL = "https://api.2fa.directory/v3/tfa.json"


def twofa(items: list[dict], directory: list | None = None) -> list[dict]:
    """Logins whose site offers 2FA while the item holds no TOTP secret."""
    if directory is None:
        resp = httpx.get(TFA_URL, timeout=30, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        directory = resp.json()
    sites: dict[str, list[str]] = {}
    for entry in directory:
        if isinstance(entry, list) and len(entry) == 2 and isinstance(entry[1], dict):
            info = entry[1]
            methods = info.get("tfa") or []
            for domain in [info.get("domain"), *(info.get("additional-domains") or [])]:
                if domain and methods:
                    sites[domain.lower()] = methods
    out = []
    for item in items:
        login = item.get("login") or {}
        if item.get("deletedDate") or item.get("type") != 1 or login.get("totp"):
            continue
        for host in {h for u in login.get("uris") or [] if (h := host_of(u.get("uri")))}:
            labels = host.split(".")
            match = next((".".join(labels[i:]) for i in range(len(labels) - 1)
                          if ".".join(labels[i:]) in sites), None)
            if match:
                out.append({"id": item["id"], "site": match, "methods": sites[match],
                            "has_passkey": bool(login.get("fido2Credentials"))})
                break
    return out
