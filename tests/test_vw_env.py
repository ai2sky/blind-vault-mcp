import dataclasses
import sys

import pytest

from test_vw_client import cfg, seed  # noqa: F401  (fixture)
from vw_server import env as vw_env
from vw_server.client import VwClient, VwError, load_config

SECRET = "s3cr3t-VALUE-9f2"

ITEMS = [{"id": "1", "name": "API_TOKEN", "login": {"password": SECRET}, "collectionIds": ["c2"]},
         {"id": "2", "name": "NOTE_VAR", "notes": "line1\nline2", "collectionIds": ["c2"]},
         {"id": "3", "name": "bad name", "notes": "x", "collectionIds": ["c2"]},
         {"id": "4", "name": "OTHER", "notes": "x", "collectionIds": ["c1"]}]


def test_values_from_collection(cfg, monkeypatch):
    seed(cfg, ITEMS)
    environ = {"VW_URL": cfg.server_url, "VW_CLIENT_ID": cfg.client_id,
               "VW_CLIENT_SECRET_FILE": str(cfg.client_secret_file),
               "VW_MASTER_PASSWORD_FILE": str(cfg.master_password_file),
               "VW_ORGANIZATION_ID": "org", "VW_COLLECTION": "shared"}
    # Point the client at the fake bw; the rest of the config comes from load_config.
    monkeypatch.setattr(vw_env, "VwClient",
                        lambda c: VwClient(dataclasses.replace(c, bw=cfg.bw)))
    assert vw_env.collection_values(environ=environ) == {
        "API_TOKEN": SECRET, "NOTE_VAR": "line1\nline2"}


def test_github_env_masks_before_writing(tmp_path, capsys):
    target = tmp_path / "github_env"
    vw_env.write_github_env({"A": SECRET, "B": "l1\nl2"}, target, sys.stdout)
    out = capsys.readouterr().out.splitlines()
    assert out == [f"::add-mask::{SECRET}", "::add-mask::l1", "::add-mask::l2"]
    text = target.read_text()
    assert f"{SECRET}\n" in text and "A<<vw_" in text and "B<<vw_" in text


def test_exports_are_quoted(capsys):
    vw_env.write_exports({"A": "it's a $x"}, sys.stdout)
    assert capsys.readouterr().out == "export A='it'\"'\"'s a $x'\n"


def test_systemd_format_for_an_environment_file(tmp_path, monkeypatch, capsys):
    values = {"API_TOKEN": SECRET, "QUOTED": "it's", "MULTI": "a\nb", "PATH": "/evil"}
    monkeypatch.setattr(vw_env, "collection_values", lambda *a, **k: dict(values))
    monkeypatch.setenv("GITHUB_ENV", str(tmp_path / "github_env"))  # --format wins over GitHub Actions
    assert vw_env.main(["--format", "systemd"]) == 0
    captured = capsys.readouterr()
    assert captured.out == f"API_TOKEN='{SECRET}'\n"
    assert "QUOTED skipped" in captured.err and "MULTI skipped" in captured.err
    assert "it's" not in captured.err and "/evil" not in captured.out + captured.err
    assert not (tmp_path / "github_env").exists()


def test_main_skips_dangerous_names(tmp_path, monkeypatch, capsys):
    values = {"PATH": "/evil", "LD_PRELOAD": "/evil.so", "github_token": "x", "RUNNER_TEMP": "x",
              "NODE_OPTIONS": "--require /evil", "PYTHONPATH": "/evil", "API_TOKEN": SECRET}
    target = tmp_path / "github_env"
    monkeypatch.setattr(vw_env, "collection_values", lambda *a, **k: dict(values))
    monkeypatch.setenv("GITHUB_ENV", str(target))
    monkeypatch.delenv("VW_ENV_FILE", raising=False)
    assert vw_env.main([]) == 0
    captured = capsys.readouterr()
    text = target.read_text()
    assert "API_TOKEN<<vw_" in text and SECRET in text
    for name in ("PATH", "LD_PRELOAD", "github_token", "RUNNER_TEMP", "NODE_OPTIONS", "PYTHONPATH"):
        assert f"{name}<<" not in text
        assert f"skipping {name}:" in captured.err
    assert "/evil" not in text + captured.out + captured.err

    monkeypatch.delenv("GITHUB_ENV")
    assert vw_env.main([]) == 0
    captured = capsys.readouterr()
    assert captured.out == f"export API_TOKEN={SECRET}\n"
    assert "/evil" not in captured.out + captured.err
    assert "PATH" in captured.err


def test_env_file_must_be_private(tmp_path):
    f = tmp_path / "vw.env"
    f.write_text("# c\nVW_URL='https://vw.example'\nexport VW_CLIENT_ID=user.1\n")
    f.chmod(0o644)
    with pytest.raises(VwError):
        vw_env.read_env_file(f)
    f.chmod(0o600)
    assert vw_env.read_env_file(f) == {"VW_URL": "https://vw.example", "VW_CLIENT_ID": "user.1"}


def test_main_reports_error(monkeypatch, capsys):
    for var in ("GITHUB_ENV", "VW_ENV_FILE", "VW_URL"):
        monkeypatch.delenv(var, raising=False)
    assert vw_env.main([]) == 1
    assert "VW_URL" in capsys.readouterr().err
