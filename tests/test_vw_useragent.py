"""Every HTTP call to Vaultwarden carries a named User-Agent, never the library default.

Cloudflare in front of the vault answers Error 1010 to `Python-urllib/3.x`. No network here:
the transport is replaced and the request headers are read.
"""

import dataclasses
import io
import urllib.error
from types import SimpleNamespace

import httpx
import pytest

from vw_server import client as client_mod, service_account as sa
from vw_server.client import VwClient
from vw_server.useragent import USER_AGENT

from test_vw_client import ccfg, cfg  # noqa: F401  (fixtures)


class FakeResponse(io.BytesIO):
    headers = SimpleNamespace(get_all=lambda name: [])

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def capture_urllib(monkeypatch, body=b"{}"):
    seen = []

    def opener(req, timeout=None):
        seen.append(req)
        return FakeResponse(body)

    monkeypatch.setattr(sa.urllib.request, "urlopen", opener)
    monkeypatch.setattr(sa._no_redirect, "open", opener)
    return seen


def test_the_agent_names_the_tool_and_a_version():
    assert USER_AGENT.startswith("blind-vault-mcp/") and len(USER_AGENT) > len("blind-vault-mcp/")
    assert "urllib" not in USER_AGENT.lower()


def test_http_sends_the_agent(monkeypatch):
    seen = capture_urllib(monkeypatch)
    sa.http(SimpleNamespace(url="https://vault.example"), "GET", "/admin/users")
    assert seen[0].get_header("User-agent") == USER_AGENT
    assert seen[0].get_header("Accept") == "application/json"


def test_http_sends_the_agent_with_a_form_and_a_json_body(monkeypatch):
    seen = capture_urllib(monkeypatch)
    cfg_ = SimpleNamespace(url="https://vault.example")
    sa.http(cfg_, "POST", "/identity/accounts/register", json_body={"email": "x@example.com"})
    sa.http(cfg_, "POST", "/identity/connect/token", form={"grant_type": "client_credentials"})
    assert [r.get_header("User-agent") for r in seen] == [USER_AGENT, USER_AGENT]


def test_http_sends_the_agent_on_the_admin_login_without_following_redirects(monkeypatch):
    seen = capture_urllib(monkeypatch, b"")
    sa.http(SimpleNamespace(url="https://vault.example"), "POST", "/admin", form={"token": "t"}, raw=True)
    assert seen[0].get_header("User-agent") == USER_AGENT


def test_http_keeps_other_headers_next_to_the_agent(monkeypatch):
    seen = capture_urllib(monkeypatch)
    sa.http(SimpleNamespace(url="https://vault.example"), "GET", "/admin/users", headers={"Cookie": "VW_ADMIN=x"})
    assert seen[0].get_header("Cookie") == "VW_ADMIN=x" and seen[0].get_header("User-agent") == USER_AGENT


def test_http_error_still_reports_the_status(monkeypatch):
    def opener(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(b"error code: 1010"))

    monkeypatch.setattr(sa.urllib.request, "urlopen", opener)
    with pytest.raises(sa.ServiceAccountError, match="HTTP 403"):
        sa.http(SimpleNamespace(url="https://vault.example"), "GET", "/admin")


def test_vwclient_api_sends_the_agent_on_both_calls(ccfg, monkeypatch):  # noqa: F811
    cfg_ = dataclasses.replace(ccfg, server_url="https://vault.example", client_id="user.1", client_secret="k3y")
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/connect/token"):
            return httpx.Response(200, json={"access_token": "tok"})
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(handler)
    real = httpx.Client

    def fake_post(url, **kw):
        with real(transport=transport) as c:
            return c.post(url, **kw)

    def fake_request(method, url, **kw):
        with real(transport=transport) as c:
            return c.request(method, url, **kw)

    monkeypatch.setattr(client_mod.httpx, "post", fake_post)
    monkeypatch.setattr(client_mod.httpx, "request", fake_request)
    VwClient(cfg_)._api("POST", "/api/organizations/org1/users/invite", {"emails": []})
    assert len(seen) == 2
    assert [r.headers["user-agent"] for r in seen] == [USER_AGENT, USER_AGENT]
    assert seen[1].headers["authorization"] == "Bearer tok"
