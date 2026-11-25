import httpx

from vw_server import audit


def test_notify_reads_its_url_from_the_vw_env_file(monkeypatch, tmp_path):
    """The telegram and ops servers are spawned without VW_NOTIFY_URL: the file supplies it."""
    token = tmp_path / "token"
    token.write_text("t0ken\n")
    env_file = tmp_path / "env"
    env_file.write_text(f"VW_NOTIFY_URL=https://pd.example/api/notify\nVW_NOTIFY_TOKEN_FILE={token}\n")
    monkeypatch.setenv("VW_ENV_FILE", str(env_file))
    monkeypatch.delenv("VW_NOTIFY_URL", raising=False)
    monkeypatch.delenv("VW_NOTIFY_TOKEN_FILE", raising=False)
    seen = {}

    def post(url, json, headers, timeout):
        seen.update(url=url, json=json, headers=headers)
        return httpx.Response(200, request=httpx.Request("POST", url))
    monkeypatch.setattr(audit.httpx, "post", post)
    audit.notify("hello")
    assert seen["url"] == "https://pd.example/api/notify"
    assert seen["headers"] == {"Authorization": "Bearer t0ken"}


def test_the_process_environment_wins_over_the_file(monkeypatch, tmp_path):
    env_file = tmp_path / "env"
    env_file.write_text("VW_NOTIFY_URL=https://file.example/n\n")
    monkeypatch.setenv("VW_ENV_FILE", str(env_file))
    monkeypatch.setenv("VW_NOTIFY_URL", "https://env.example/n")
    monkeypatch.setenv("VW_NOTIFY_TOKEN_FILE", str(tmp_path / "t"))
    (tmp_path / "t").write_text("x")
    seen = {}
    monkeypatch.setattr(audit.httpx, "post", lambda url, **kw: seen.setdefault("url", url) and httpx.Response(
        200, request=httpx.Request("POST", url)))
    audit.notify("hello")
    assert seen["url"] == "https://env.example/n"
