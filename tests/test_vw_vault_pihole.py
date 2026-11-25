import httpx

from vw_vault.pihole import PiHoleRotator

OLD, NEW = "old-pass-0001-xyz", "new-pass-0002-xyz"


class FakePiHole:
    """Stands in for the host (admin ssh) and the Pi-hole API."""

    def __init__(self, refuse_change=False):
        self.password, self.refuse_change, self.stdin = OLD, refuse_change, []

    def run(self, host, user, password, command, stdin=""):
        self.stdin.append(stdin)
        if self.refuse_change:
            return 1
        self.password = stdin.split("\n")[0]
        return 0

    def handler(self, request):
        if request.method == "DELETE":
            return httpx.Response(204)
        if httpx.Response(200, content=request.read()).json()["password"] != self.password:
            return httpx.Response(401, json={"session": {"valid": False}})
        return httpx.Response(200, json={"session": {"valid": True, "sid": "s"}})


def make(host, written):
    http = httpx.Client(transport=httpx.MockTransport(host.handler))
    return PiHoleRotator({"pihole"}, "pi.lan", lambda it, v: written.append(v), transport=host, http=http,
                         generate=lambda: NEW)


def item():
    return {"id": "i1", "type": 1, "name": "pihole", "login": {"password": OLD}}


def test_rotation_new_works_old_refused_value_written():
    host, written = FakePiHole(), []
    rot = make(host, written)
    assert rot.matches(item())
    assert rot._can_login("admin", OLD) and not rot._can_login("admin", NEW)
    new = rot.issue(item())
    rot.distribute(item(), new)
    assert host.stdin[-1] == f"{NEW}\n{NEW}\n"
    assert rot.verify(item(), new)
    assert rot._can_login("admin", NEW) and not rot._can_login("admin", OLD)
    assert written == [NEW]


def test_failed_change_keeps_old():
    host, written = FakePiHole(refuse_change=True), []
    rot = make(host, written)
    try:
        rot.distribute(item(), rot.issue(item()))
    except Exception:
        pass
    assert written == [] and rot._can_login("admin", OLD)
