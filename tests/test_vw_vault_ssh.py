from vw_vault.rotation import run_module
from vw_vault.ssh import HOST, SshPasswordRotator

OLD, NEW = "old-pass-0001-xyz", "new-pass-0002-xyz"


class FakeHost:
    """A substitute SSH host: one account, a password, a switch for each failure."""

    def __init__(self, password=OLD, refuse_change=False, ignore_change=False, new_login_broken=False):
        self.password = password
        self.refuse_change, self.ignore_change = refuse_change, ignore_change
        self.new_login_broken = new_login_broken
        self.calls = []

    def run(self, host, user, password, command, stdin=""):
        self.calls.append(command)
        if password != self.password or (self.new_login_broken and password == NEW):
            return None
        if command == "true":
            return 0
        if self.refuse_change:
            return 1
        if not self.ignore_change:
            self.password = stdin.strip().split(":", 1)[1]
        return 0


def item():
    return {"id": "i1", "type": 1, "name": "pi", "login": {"username": "pi", "password": OLD}}


def rotator(host, written, fail_write=False):
    def write(it, value):
        if fail_write and value == NEW:
            raise RuntimeError(f"bw said {value}")
        written.append(value)

    return SshPasswordRotator({"pi"}, "pi.lan", write, transport=host, generate=lambda: NEW)


def test_success_changes_checks_and_writes():
    host, written = FakeHost(), []
    res = run_module(rotator(host, written), item())
    assert res["ok"] and res["consumers"] == [HOST, "vault item"]
    assert host.password == NEW and written == [NEW]


def test_refused_change_rolls_back_nothing_changed():
    host, written = FakeHost(refuse_change=True), []
    res = run_module(rotator(host, written), item())
    assert not res["ok"] and res["stage"] == "distribute" and res["rolled_back"]
    assert host.password == OLD and written == []


def test_old_password_still_works_fails_verify_and_rolls_back():
    host, written = FakeHost(ignore_change=True), []
    res = run_module(rotator(host, written), item())
    assert not res["ok"] and res["stage"] == "verify" and res["rolled_back"]
    assert host.password == OLD and written == [NEW, OLD]


def test_new_login_fails_vault_restored_host_reset_reported():
    host, written = FakeHost(new_login_broken=True), []
    res = run_module(rotator(host, written), item())
    assert not res["ok"] and res["stage"] == "verify"
    # the new password cannot log in, so the host cannot be reset: reported, vault restored
    assert res["rolled_back"] is False and written == [NEW, OLD]


def test_vault_write_failure_puts_old_password_back_without_leaking_value():
    host, written = FakeHost(), []
    res = run_module(rotator(host, written, fail_write=True), item())
    assert not res["ok"] and res["rolled_back"] and host.password == OLD
    assert NEW not in str(res) and OLD not in str(res)


def test_wrong_current_password_stops_before_any_change():
    host, written = FakeHost(password="something-else"), []
    res = run_module(rotator(host, written), item())
    assert not res["ok"] and res["stage"] == "issue" and host.password == "something-else"
    assert host.calls == ["true"]


def test_matches_only_live_logins_on_the_list():
    rot = rotator(FakeHost(), [])
    assert rot.matches(item())
    assert not rot.matches({**item(), "name": "other"})
    assert not rot.matches({**item(), "deletedDate": "2026-01-01"})


def test_transport_ignores_ssh_config_and_takes_a_port(monkeypatch):
    """The owner's ~/.ssh/config never applies (it once stalled the password check), and
    `host:port` reaches ssh as -p; the password stays out of argv."""
    from vw_vault import ssh as ssh_mod
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"], seen["env"] = argv, kw.get("env") or {}
        return type("P", (), {"returncode": 0})()

    monkeypatch.setattr(ssh_mod.subprocess, "run", fake_run)
    assert ssh_mod.SshTransport().run("192.0.2.20:11022", "admin", "s3cret-pw", "true") == 0
    argv = seen["argv"]
    assert argv[argv.index("-F") + 1] == "/dev/null"
    assert argv[argv.index("-p") + 1] == "11022" and "admin@192.0.2.20" in argv
    assert "s3cret-pw" not in " ".join(argv) and seen["env"]["SSHPASS"] == "s3cret-pw"
    ssh_mod.SshTransport().run("pve.example.internal", "root", "x", "true")
    assert "-p" not in seen["argv"] and "root@pve.example.internal" in seen["argv"]


def test_target_parses_host_port_and_ipv6():
    from vw_vault.ssh import target
    assert target("192.0.2.20:11022") == ("192.0.2.20", ["-p", "11022"])
    assert target("pve.example.internal") == ("pve.example.internal", [])
    assert target("[fe80::1]:2222") == ("fe80::1", ["-p", "2222"])
    assert target("fe80::1") == ("fe80::1", [])
