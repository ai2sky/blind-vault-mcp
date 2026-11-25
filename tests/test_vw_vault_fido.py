import json

import pytest

from vw_vault import fidokey


class Resp:
    def __init__(self, raw_id, first):
        self.raw_id = raw_id
        self.client_extension_results = {"prf": {"results": {"first": first}}}


class FakeClient:
    """Stands in for Fido2Client: PRF output = a keyed hash of credential and salt."""

    def __init__(self, cred=b"C" * 32):
        self.cred = cred

    def make_credential(self, options):
        return type("M", (), {"raw_id": self.cred})()

    def _out(self, salt):
        import hashlib
        return hashlib.sha256(self.cred + salt).digest()

    def get_assertion(self, options):
        ext = options.extensions["prf"]
        if "eval" in ext:
            salt = ext["eval"]["first"]
        else:
            salt = ext["evalByCredential"][fidokey._b64(self.cred)]["first"]
        resp = Resp(self.cred, self._out(salt))
        return type("S", (), {"get_response": lambda s, i: resp})()


def test_enroll_then_unlock(tmp_path, monkeypatch):
    client = FakeClient()
    monkeypatch.setattr(fidokey, "_devices", lambda: ["dev"])
    monkeypatch.setattr(fidokey, "_client", lambda d: (client, "YubiKey 5C"))
    path = tmp_path / "fido.json"
    assert fidokey.enroll(path, "master-Pa55") == "YubiKey 5C"
    assert "master-Pa55" not in path.read_text() and oct(path.stat().st_mode & 0o777) == "0o600"
    assert fidokey.unlock_password(path) == "master-Pa55"
    other = FakeClient(b"D" * 32)
    monkeypatch.setattr(fidokey, "_client", lambda d: (other, "NFC key"))
    fidokey.enroll(path, "master-Pa55")
    assert len(json.loads(path.read_text())) == 2
    assert fidokey.unlock_password(path) == "master-Pa55"


def test_no_key(tmp_path, monkeypatch):
    monkeypatch.setattr(fidokey, "_devices", lambda: [])
    with pytest.raises(fidokey.FidoError):
        fidokey.enroll(tmp_path / "f.json", "x")
