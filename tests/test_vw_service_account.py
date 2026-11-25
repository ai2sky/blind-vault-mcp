import base64
import hashlib
import json
import stat
import sys

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from vw_server import service_account as sa
from vw_server.service_account import Config, ServiceAccountError, VaultFile

PASSWORD = "m4st3r-PASSWORD-7c1"

# Fake ansible-vault: "encrypts" by prefixing, so a test can read what was written without
# a vault password. view/encrypt/encrypt_string are the three calls the command makes.
FAKE = f"""#!{sys.executable}
import sys
a = sys.argv[1:]
if a[0] == "view":
    sys.stdout.write(open(a[1]).read()[4:])
elif a[0] == "encrypt":
    open(a[a.index("--output") + 1], "w").write("ENC:" + open(a[1]).read())
elif a[0] == "encrypt_string":
    sys.stdout.write("probe: !vault |\\n  ENC\\n")
"""


@pytest.fixture
def cfg(tmp_path):
    fake = tmp_path / "ansible-vault"
    fake.write_text(FAKE)
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    return Config(vault_file=tmp_path / "vault.yml", repo=tmp_path, org_domain="example.test",
                  url="https://vault.example", bw_url="https://vault.example",
                  ansible_vault=str(fake))


def plain(cfg) -> str:
    return cfg.vault_file.read_text()[4:]


# --- the vault file -----------------------------------------------------------


def test_set_creates_a_missing_file(cfg):
    VaultFile(cfg).set({"vault_demo_bw_email": "svc-demo@example.test"})
    assert plain(cfg) == '\nvault_demo_bw_email: "svc-demo@example.test"\n'


def test_set_replaces_one_variable_and_keeps_the_rest(cfg):
    cfg.vault_file.write_text("ENC:vault_other: 'keep me'\nvault_demo_bw_clientid: 'user.old'\n")
    VaultFile(cfg).set({"vault_demo_bw_clientid": "user.new"})
    text = plain(cfg)
    assert "vault_other: 'keep me'" in text
    assert 'vault_demo_bw_clientid: "user.new"' in text
    assert "user.old" not in text


def test_set_quotes_a_value_that_would_break_yaml(cfg):
    VaultFile(cfg).set({"vault_demo_bw_password": "a: b #c\n"})
    assert VaultFile.get(plain(cfg), "vault_demo_bw_password") == "a: b #c\n"


def test_get_reads_a_value_back(cfg):
    cfg.vault_file.write_text("ENC:vault_demo_bw_password: 'p4ss'\n")
    assert VaultFile.get(VaultFile(cfg).read(), "vault_demo_bw_password") == "p4ss"
    assert VaultFile.get(VaultFile(cfg).read(), "vault_missing") is None


def test_read_of_a_missing_file_is_empty_not_an_error(cfg):
    assert VaultFile(cfg).read() == ""


def test_view_failure_is_reported_without_the_contents(cfg, tmp_path):
    broken = tmp_path / "broken"
    broken.write_text(f"#!{sys.executable}\nimport sys\nsys.stderr.write('no password')\n"
                      "sys.exit(1)\n")
    broken.chmod(broken.stat().st_mode | stat.S_IEXEC)
    cfg.vault_file.write_text("ENC:x: 1\n")
    with pytest.raises(ServiceAccountError, match="ansible-vault view"):
        VaultFile(Config(**{**cfg.__dict__, "ansible_vault": str(broken)})).read()


def test_check_writable_refuses_before_anything_is_created(cfg, tmp_path):
    broken = tmp_path / "broken"
    broken.write_text(f"#!{sys.executable}\nimport sys\n"
                      "sys.stderr.write('ERROR! The given address is empty\\n')\nsys.exit(1)\n")
    broken.chmod(broken.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(ServiceAccountError, match="no account was created"):
        VaultFile(Config(**{**cfg.__dict__, "ansible_vault": str(broken)})).check_writable()


# --- Bitwarden crypto ---------------------------------------------------------


def test_master_password_hash_matches_the_bitwarden_scheme():
    email, pw = "svc-demo@example.test", PASSWORD
    mkey = hashlib.pbkdf2_hmac("sha256", pw.encode(), email.encode(), sa.KDF_ITERATIONS, 32)
    assert sa.master_key(pw, "SVC-Demo@Example.Test") == mkey
    expected = base64.b64encode(hashlib.pbkdf2_hmac("sha256", mkey, pw.encode(), 1, 32)).decode()
    assert sa.master_password_hash(mkey, pw) == expected


def test_enc_string_is_a_type_2_encstring_that_decrypts_back():
    enc_key, mac_key = sa.stretch(sa.master_key(PASSWORD, "svc-demo@example.test"))
    text = sa.enc_string(b"the user key", enc_key, mac_key)
    kind, rest = text.split(".", 1)
    iv, ct, mac = (base64.b64decode(part) for part in rest.split("|"))
    assert kind == "2" and len(iv) == 16 and len(mac) == 32
    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    assert unpadder.update(padded) + unpadder.finalize() == b"the user key"


def test_registration_payload_carries_no_plaintext_password():
    payload = sa.registration_payload("svc-demo@example.test", PASSWORD)
    assert payload["kdfIterations"] == sa.KDF_ITERATIONS
    assert payload["key"].startswith("2.")
    assert payload["keys"]["encryptedPrivateKey"].startswith("2.")
    assert PASSWORD not in json.dumps(payload)


# --- configuration ------------------------------------------------------------


def test_repo_is_the_nearest_directory_with_an_ansible_cfg(tmp_path):
    (tmp_path / "deploy/inventory/ori/group_vars/all").mkdir(parents=True)
    (tmp_path / "deploy/ansible.cfg").write_text("[defaults]\n")
    vault = tmp_path / "deploy/inventory/ori/group_vars/all/vault.yml"
    assert sa.find_repo(vault) == (tmp_path / "deploy").resolve()


def test_without_an_ansible_cfg_the_repo_must_be_given(tmp_path):
    with pytest.raises(ServiceAccountError, match="no ansible.cfg"):
        sa.find_repo(tmp_path / "vault.yml")


def test_load_config_takes_the_urls_apart(tmp_path):
    env = {"VW_URL": "http://vault.lan:8080/", "VW_BW_URL": "https://vault.example/",
           "VW_ORG_DOMAIN": "example.test"}
    cfg = sa.load_config(str(tmp_path / "vault.yml"), str(tmp_path), env)
    assert cfg.url == "http://vault.lan:8080"
    assert cfg.bw_url == "https://vault.example"


def test_load_config_needs_the_mail_domain(tmp_path):
    with pytest.raises(ServiceAccountError, match="VW_ORG_DOMAIN"):
        sa.load_config(str(tmp_path / "vault.yml"), str(tmp_path), {"VW_URL": "https://v"})


def test_the_collection_is_the_service_name_with_dashes():
    assert sa.collection_of("my_app") == "my-app"
    assert sa.prefix("my_app") == "vault_my_app_bw"


@pytest.mark.parametrize("name", ["My-App", "1myapp", "my app", "my-app", ""])
def test_a_bad_service_name_is_refused(name):
    assert not sa.NAME_RE.match(name)


def test_create_refuses_a_service_that_is_already_there(cfg):
    cfg.vault_file.write_text("ENC:vault_demo_bw_password: 'p4ss'\n")
    with pytest.raises(ServiceAccountError, match="rotate"):
        sa.cmd_create(cfg, "demo")


def test_create_refuses_without_an_admin_token(cfg, monkeypatch):
    monkeypatch.delenv("VW_ADMIN_TOKEN", raising=False)
    with pytest.raises(ServiceAccountError, match="admin token") as exc:
        sa.cmd_create(cfg, "demo")
    assert "--invited" in str(exc.value)


def test_create_invited_needs_no_admin_token_and_skips_the_admin_interface(cfg, monkeypatch):
    monkeypatch.delenv("VW_ADMIN_TOKEN", raising=False)
    monkeypatch.setattr(sa, "admin_invite", lambda *a: pytest.fail("the invitation was sent"))
    registered = []
    monkeypatch.setattr(sa, "http", lambda _cfg, _m, path, **kw: registered.append(path) or {})
    monkeypatch.setattr(sa, "api_key", lambda *a: ("user.1", "k3y"))

    sa.cmd_create(cfg, "demo", invited=True)

    assert registered == ["/identity/accounts/register"]
    text = plain(cfg)
    assert VaultFile.get(text, "vault_demo_bw_email") == "svc-demo@example.test"
    assert VaultFile.get(text, "vault_demo_bw_clientsecret") == "k3y"


def test_register_falls_back_to_the_two_step_flow_on_404(cfg, monkeypatch):
    calls = []

    def fake_http(_cfg, _m, path, json_body=None, **kw):
        calls.append((path, json_body))
        if path == "/identity/accounts/register":
            raise ServiceAccountError("POST /identity/accounts/register: HTTP 404 <html>")
        if path.endswith("send-verification-email"):
            return "t0ken"
        return {}

    monkeypatch.setattr(sa, "http", fake_http)
    password = "Plain-Master-Password-7f3e"  # long enough that random base64 cannot contain it
    sa.register(cfg, "svc-demo@example.test", password)

    assert [c[0] for c in calls] == [
        "/identity/accounts/register",
        "/identity/accounts/register/send-verification-email",
        "/identity/accounts/register/finish",
    ]
    finish = calls[-1][1]
    assert finish["emailVerificationToken"] == "t0ken"
    assert finish["email"] == "svc-demo@example.test"
    assert password not in str(finish)


def test_register_without_a_token_in_the_body_explains_why(cfg, monkeypatch):
    def fake_http(_cfg, _m, path, **kw):
        if path == "/identity/accounts/register":
            raise ServiceAccountError("POST /identity/accounts/register: HTTP 404")
        return {}

    monkeypatch.setattr(sa, "http", fake_http)
    with pytest.raises(ServiceAccountError, match="SMTP"):
        sa.register(cfg, "svc-demo@example.test", "pw")


def test_register_passes_other_errors_through(cfg, monkeypatch):
    def fake_http(_cfg, _m, path, **kw):
        raise ServiceAccountError("POST /identity/accounts/register: HTTP 400 taken")

    monkeypatch.setattr(sa, "http", fake_http)
    with pytest.raises(ServiceAccountError, match="400"):
        sa.register(cfg, "svc-demo@example.test", "pw")


def test_the_invited_flag_belongs_to_create_only(capsys):
    assert sa.build_parser().parse_args(["create", "demo", "--invited"]).invited is True
    assert sa.build_parser().parse_args(["create", "demo"]).invited is False
    with pytest.raises(SystemExit):
        sa.build_parser().parse_args(["rotate", "demo", "--invited"])
