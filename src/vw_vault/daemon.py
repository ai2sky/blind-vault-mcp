"""vw-vault: the owner unlocks the personal vault once, agents work through the daemon.

  vw-vault unlock   (owner, own terminal) API key + master password (or a registered
                    FIDO2 security key: PIN + touch), then the daemon
                    holds the session in memory and serves a 0600 Unix socket
  vw-vault unlock --enroll   unlock with the password, then register security keys for it
  vw-vault forget-keys       drop the registered keys (the password is asked again)
  vw-vault status   is it running, idle time, current job
  vw-vault lock     stop the daemon and lock bw
  vw-vault check logins [--dry-run]   (owner, own terminal) opt-in login checks, see docs/vault.md
  vw-vault call CMD [JSON]   send one request (what the MCP server does)

The master password is read with getpass and never stored. The API key may sit in
the keyring (service vw-vault, entries client_id, client_secret). Settings come from
the environment or ~/.config/vw/env: VW_URL, VW_VAULT_BACKUP_CMD, VW_VAULT_IDLE (s).
"""

from __future__ import annotations

import dataclasses
import getpass
import hashlib
import json
import logging
import os
import signal
import socket
import socketserver
import struct
import sys
import threading
import time
from pathlib import Path

from vw_server.client import VwClient, VwConfig, VwError

from . import cf_tunnel, fidokey, logins, selfgen
from .engine import STATE_DIR, Engine
from .lanproxy import LanProxy
from .backup import BackupRotator
from .cloudflare import MASTER_NAME as CF_MASTER_NAME
from .cloudflare import CloudflareRotator
from .github_app import GitHubAppRotator, load_github_consumers
from .gitlab import GitLabRotator
from .pihole import PiHoleRotator
from .proxmox import ProxmoxKeyRotator, ProxmoxPasswordRotator
from .mikrotik import MikroTikRotator
from .openrouter import MASTER_NAME, OpenRouterRotator, load_consumers

KEYRING_SERVICE = "vw-vault"
DEFAULT_IDLE = 2 * 3600
ENV_FILE = Path("~/.config/vw/env").expanduser()


def socket_path() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/tmp/vw-vault-{os.getuid()}"
    return Path(os.environ.get("VW_VAULT_SOCKET") or Path(base) / "vw-vault.sock")


def settings() -> dict[str, str]:
    out: dict[str, str] = {}
    if ENV_FILE.is_file():
        for line in ENV_FILE.read_text().splitlines():
            key, sep, value = line.strip().partition("=")
            if sep and not key.startswith("#"):
                out[key.strip()] = value.strip().strip("'\"")
    out.update({k: v for k, v in os.environ.items() if k.startswith("VW_")})
    return out


def keyring_get(key: str) -> str:
    """The API key from the Secret Service (gnome-keyring), as the other vw tools keep it.

    The default python-keyring chain may pick KWallet first and pop up its dialog, so the
    Secret Service backend is asked directly; the default chain is the fallback.
    """
    try:
        from keyring.backends import SecretService
        value = SecretService.Keyring().get_password(KEYRING_SERVICE, key)
        if value:
            return value
    except Exception:
        pass
    try:
        import keyring
        return keyring.get_password(KEYRING_SERVICE, key) or ""
    except Exception:
        return ""


class VaultClient(VwClient):
    """VwClient whose bw trusts the loopback proxy's certificate."""

    def __init__(self, cfg: VwConfig, ca: str = ""):
        super().__init__(cfg)
        self._ca = ca

    def _run(self, args, stdin=None, extra_env=None):
        env = dict(extra_env or {})
        if self._ca:
            env["NODE_EXTRA_CA_CERTS"] = self._ca
        return super()._run(args, stdin=stdin, extra_env=env)


# --- requests ---------------------------------------------------------------------

READ_ONLY = {"status", "summary", "inventory", "export_inventory", "dedupe_plan", "job_status", "rotation_list",
             "collections_plan", "folders_plan"}


def dispatch(engine: Engine, cmd: str, args: dict):
    if cmd == "github_app_status":
        item = engine.items.get(str(args["id"]))
        if not item:
            raise VwError("no such item")
        return GitHubAppRotator({item.get("name")}).status(item)
    if cmd == "export_to_ansible_vault":
        return engine.export_to_ansible_vault(str(args["id"]), str(args["vault_file"]), str(args["variable"]),
                                              str(args.get("field") or "password"))
    if cmd == "send":
        return engine.send(str(args["id"]), str(args.get("field") or "password"),
                           args["expires_hours"] if "expires_hours" in args else 24,
                           args["max_views"] if "max_views" in args else 1,
                           args.get("password"), str(args.get("note") or ""))
    if cmd == "send_list":
        return engine.send_list()
    if cmd == "send_delete":
        return engine.send_delete(str(args["id"]))
    if cmd == "openrouter_keys":
        return engine.openrouter_keys()
    if cmd == "status":
        return {"unlocked": True, "loaded_at": engine.loaded_at, "job": engine.job_status()}
    if cmd == "summary":
        return engine.summary()
    if cmd == "inventory":
        return engine.inventory(**{k: args[k] for k in ("query", "include_deleted", "offset", "limit") if k in args})
    if cmd == "export_inventory":
        return {"file": engine.export_inventory()}
    if cmd == "reload":
        engine._sync()  # bw lists from its local copy: fetch the server's state first
        engine.load()
        return engine.summary()
    if cmd == "dedupe_plan":
        return engine.dedupe_plan()
    if cmd == "dedupe_apply":
        return engine.dedupe_apply(int(args.get("limit") or 0))
    if cmd == "backup":
        return engine.backup()
    if cmd == "trash":
        return engine.trash(list(args["ids"]), str(args.get("reason") or ""))
    if cmd == "restore":
        return engine.restore(list(args["ids"]))
    if cmd == "drop_field":
        return engine.drop_field(str(args["id"]), str(args["field"]))
    if cmd == "set_from_ansible_vault":
        return engine.set_from_ansible_vault(str(args["id"]), str(args["vault_file"]), str(args["variable"]))
    if cmd == "drop_kpex_fields":
        return engine.drop_kpex_fields(list(args["ids"]))
    if cmd == "convert_passkeys":
        return engine.convert_passkeys(list(args["ids"]))
    if cmd == "compare_keyring":
        return engine.compare_keyring(str(args["id"]), dict(args["attributes"]))
    if cmd == "folders_plan":
        return engine.folders_plan()
    if cmd == "delete_folders":
        return engine.delete_folders(list(args["names"]))
    if cmd == "dedupe_collections":
        return engine.dedupe_collections(str(args["organization"]))
    if cmd == "copy_to":
        return engine.copy_to(list(args["ids"]), str(args["collection"]), str(args["organization"]))
    if cmd == "unarchive":
        return engine.unarchive(list(args["ids"]))
    if cmd == "collections_plan":
        return engine.collections_plan()
    if cmd == "to_collection":
        return engine.to_collection(list(args["ids"]), str(args["collection"]), str(args["organization"]))
    if cmd == "move":
        return engine.move(list(args["ids"]), str(args.get("folder") or ""))
    if cmd == "set_uri":
        return engine.set_uri(str(args["id"]), str(args["old"]), str(args["new"]))
    if cmd == "rename":
        return engine.rename(str(args["id"]), str(args["name"]))
    if cmd == "check":
        return engine.check(str(args["name"]), args.get("paths"))
    if cmd == "check_logins":
        return engine.check_logins(bool(args.get("dry_run")), str(args.get("proof") or ""))
    if cmd == "job_status":
        return engine.job_status()
    if cmd == "rotation_list":
        return engine.rotation()
    if cmd == "rotate":
        return engine.rotate(list(args["ids"]))
    if cmd == "rotate_all":
        return engine.rotate_all()
    if cmd == "rotation_mark":
        return {"marked": engine.mark_rotation(list(args["ids"]), str(args["reason"]))}
    if cmd == "rotation_clear":
        return {"cleared": engine.clear_rotation(list(args["ids"]), str(args.get("reason") or "done"))}
    raise VwError(f"unknown command {cmd}")


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server: Daemon = self.server  # type: ignore[assignment]
        line = self.rfile.readline(1 << 20)
        try:
            req = json.loads(line)
            server.touch()
            if server.engine.guard_response(line.decode(errors="replace")):
                # a value in a request would end up in the journal or the rotation list
                raise VwError("request refused: it carried a vault value; the items are on the rotation list")
            result = {"ok": True, "result": dispatch(server.engine, str(req.get("cmd")), req.get("args") or {})}
        except VwError as exc:
            result = {"ok": False, "error": str(exc)}
        except (ValueError, KeyError, TypeError) as exc:
            result = {"ok": False, "error": f"bad request: {type(exc).__name__}"}
        text = json.dumps(result, ensure_ascii=False)
        if server.engine.guard_response(text):
            text = json.dumps({"ok": False, "error": "response withheld: it carried a vault value; "
                               "the items are on the rotation list"})
        self.wfile.write(text.encode() + b"\n")


class Daemon(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path: Path, engine: Engine, idle: int):
        self.engine, self.idle, self.last = engine, idle, time.time()
        super().__init__(str(path), Handler)
        os.chmod(path, 0o600)

    def touch(self) -> None:
        self.last = time.time()

    def watchdog(self) -> None:
        while True:
            time.sleep(30)
            if time.time() - self.last > self.idle and not self.engine.busy():
                self.shutdown()
                return


# --- commands -----------------------------------------------------------------------


def call(cmd: str, args: dict | None = None, timeout: float = 600) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(str(socket_path()))
        s.sendall(json.dumps({"cmd": cmd, "args": args or {}}).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(1 << 16)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf)


def running() -> bool:
    try:
        return bool(call("status", timeout=5).get("ok"))
    except OSError:
        return False


def unlock(enroll: bool = False) -> None:
    if running():
        print("vw-vault is already unlocked")
        return
    conf = settings()
    url = conf.get("VW_URL", "").strip()
    if not url:
        raise SystemExit("VW_URL is not set: put VW_URL=https://your-vaultwarden in the environment or ~/.config/vw/env")
    client_id, client_secret = keyring_get("client_id"), keyring_get("client_secret")
    client_id = client_id or input("API key client_id (user.…): ").strip()
    client_secret = client_secret or getpass.getpass("API key client_secret: ")
    fido_file = STATE_DIR / "fido-unlock.json"
    password = ""
    if not enroll and fidokey.load(fido_file):
        try:
            password = fidokey.unlock_password(fido_file)
        except fidokey.FidoError as exc:
            print(f"security key: {exc}; falling back to the master password")
    if not password:
        password = getpass.getpass("Master password: ")
    lan = conf.get("VW_VAULT_LAN_URL", "").strip()
    proxy = None
    if lan:
        # around the Cloudflare tunnel, which stalls on a large sync
        proxy = LanProxy(lan, int(conf.get("VW_VAULT_LAN_PORT") or 18443), STATE_DIR)
        proxy.start()
        url = proxy.url
    cfg = VwConfig(server_url=url, client_id=client_id, client_secret_file=Path("/nonexistent"),
                   master_password_file=Path("/nonexistent"), client_secret=client_secret,
                   master_password=password,
                   bw_data_dir=os.path.expanduser(
                       f"~/.local/state/vw/bw-personal-{'lan-' if proxy else ''}"
                       f"{hashlib.sha256(client_id.encode()).hexdigest()[:12]}"))
    client = VaultClient(cfg, ca=str(proxy.cert) if proxy else "")
    print("unlocking and reading the vault ...")
    # bw sync sometimes never exits after the data arrived (an idle keep-alive through the
    # proxy); the session is set before it runs, so a stuck sync is cut short and ignored
    client.timeout = 180
    try:
        client._unlock()
    except VwError:
        if not client._session:
            raise
        print("bw sync did not finish; going on with the data it fetched")
    client.timeout = 600
    # the session is all the daemon needs; the password and the key leave memory with cfg
    if enroll:
        # the password just unlocked the vault, so it is the right one to encrypt for the keys
        while True:
            try:
                print(f"registered: {fidokey.enroll(fido_file, password)}")
            except fidokey.FidoError as exc:
                print(f"security key: {exc}")
            if input("register another key? plug it in and answer y [y/N]: ").strip().lower() != "y":
                break
    client._cfg = dataclasses.replace(cfg, client_secret="", master_password="")
    del password
    # the API key stays in the daemon (it already holds the decrypted vault) for bulk trash
    engine = Engine(client, backup_cmd=conf.get("VW_VAULT_BACKUP_CMD", ""), api_key=(client_id, client_secret),
                    lan_url=lan, public_url=conf.get("VW_URL", "").strip() if lan else "")
    names = {n.strip() for n in conf.get("VW_VAULT_OPENROUTER_ITEMS", "").split(",") if n.strip()}
    if names:
        master = conf.get("VW_VAULT_OPENROUTER_MASTER") or MASTER_NAME
        consumers = load_consumers(conf["VW_VAULT_OPENROUTER_CONSUMERS"]) if conf.get(
            "VW_VAULT_OPENROUTER_CONSUMERS") else []
        engine.rotators.append(OpenRouterRotator(names, lambda: engine.master_value(master),
                                                 engine.write_password, consumers))
    cf_names = {n.strip() for n in conf.get("VW_VAULT_CLOUDFLARE_ITEMS", "").split(",") if n.strip()}
    if cf_names:
        cf_master = conf.get("VW_VAULT_CLOUDFLARE_MASTER") or CF_MASTER_NAME
        consumers = load_consumers(conf["VW_VAULT_CLOUDFLARE_CONSUMERS"]) if conf.get(
            "VW_VAULT_CLOUDFLARE_CONSUMERS") else []
        engine.rotators.append(CloudflareRotator(cf_names, lambda: engine.master_value(cf_master),
                                                 engine.write_password, consumers))
    gl_names = {n.strip() for n in conf.get("VW_VAULT_GITLAB_ITEMS", "").split(",") if n.strip()}
    if gl_names:
        consumers = load_consumers(conf["VW_VAULT_GITLAB_CONSUMERS"]) if conf.get(
            "VW_VAULT_GITLAB_CONSUMERS") else []
        engine.rotators.append(GitLabRotator(gl_names, engine.write_password, consumers,
                                             conf.get("VW_VAULT_GITLAB_URL", "")))
    ph_names = {n.strip() for n in conf.get("VW_VAULT_PIHOLE_ITEMS", "").split(",") if n.strip()}
    if ph_names and conf.get("VW_VAULT_PIHOLE_HOST"):
        engine.rotators.append(PiHoleRotator(
            ph_names, conf["VW_VAULT_PIHOLE_HOST"], engine.write_password, conf.get("VW_VAULT_PIHOLE_URL", ""),
            admin=conf.get("VW_VAULT_PIHOLE_SSH_USER") or "root"))
    px_names = {n.strip() for n in conf.get("VW_VAULT_PROXMOX_ITEMS", "").split(",") if n.strip()}
    if px_names and conf.get("VW_VAULT_PROXMOX_HOST"):
        px_cls = ProxmoxKeyRotator if conf.get("VW_VAULT_PROXMOX_MODE") == "key" else ProxmoxPasswordRotator
        engine.rotators.append(px_cls(px_names, conf["VW_VAULT_PROXMOX_HOST"], engine.write_password))
    mt_names = {n.strip() for n in conf.get("VW_VAULT_MIKROTIK_ITEMS", "").split(",") if n.strip()}
    if mt_names and conf.get("VW_VAULT_MIKROTIK_HOST"):
        engine.rotators.append(MikroTikRotator(mt_names, conf["VW_VAULT_MIKROTIK_HOST"], engine.write_password))
    bk_names = {n.strip() for n in conf.get("VW_VAULT_BACKUP_ITEMS", "").split(",") if n.strip()}
    if bk_names and conf.get("VW_VAULT_BACKUP_HOST"):
        engine.rotators.append(BackupRotator(
            bk_names, conf["VW_VAULT_BACKUP_HOST"], engine.write_password,
            tool=conf.get("VW_VAULT_BACKUP_TOOL") or "restic", repo=conf.get("VW_VAULT_BACKUP_REPO", ""),
            admin=conf.get("VW_VAULT_BACKUP_SSH_USER") or "root"))
    apps = {n.strip() for n in conf.get("VW_VAULT_GITHUB_APP_ITEMS", "").split(",") if n.strip()}
    if apps:
        consumers = load_github_consumers(conf["VW_VAULT_GITHUB_APP_CONSUMERS"]) if conf.get(
            "VW_VAULT_GITHUB_APP_CONSUMERS") else []
        engine.rotators.append(GitHubAppRotator(apps, consumers, conf.get("VW_VAULT_GITHUB_APP_INSTALLATION", "")))
    # no secret is rotated by default: both modules exist only when a config file is set
    for module in (selfgen.from_settings(conf, engine), cf_tunnel.from_settings(conf, engine)):
        if module:
            engine.rotators.append(module)
    # opt-in login checks: off without the extra, the allow list and the owner's confirmation here
    engine.login_checks, engine.login_checks_off = logins.setup(conf, engine, vault_host=logins.host_name(url) or "")
    if engine.login_checks:
        # the socket has no caller identity: a run needs this phrase, typed in the owner's terminal
        phrase = ask_check_phrase()
        if phrase:
            engine.set_owner_phrase(phrase)
        else:
            engine.login_checks, engine.login_checks_off = None, "login checks are off: no check phrase set at unlock"
    idle = int(conf.get("VW_VAULT_IDLE") or DEFAULT_IDLE)
    path = socket_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        path.unlink()
    print(f"unlocked: {engine.summary()['items']} items; idle timeout {idle // 60} min; socket {path}")
    if os.fork():
        return
    os.setsid()
    if os.fork():
        os._exit(0)
    if proxy:
        proxy.start()  # threads do not survive fork; the listening socket does
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    server = Daemon(path, engine, idle)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown).start())
    threading.Thread(target=server.watchdog, daemon=True).start()
    try:
        server.serve_forever()
    finally:
        try:
            client._run(["lock"])
        except VwError:
            pass
        path.unlink(missing_ok=True)
        os._exit(0)


def ask_check_phrase() -> str:
    """Set at unlock (twice); empty or mismatched means the checks stay off."""
    first = getpass.getpass("Check phrase for login runs (not the master password; empty = checks off): ")
    if first and getpass.getpass("Repeat the check phrase: ") != first:
        print("the phrases differ")
        return ""
    return first


def check_logins(dry_run: bool) -> None:
    """Owner's terminal only: ask the check phrase on the tty, start the run and follow the job."""
    if not sys.stdin.isatty():
        sys.exit("the logins check is started by the owner in an interactive terminal")
    proof = getpass.getpass("Check phrase: ")
    try:
        resp = call("check_logins", {"dry_run": dry_run, "proof": proof})
    except OSError:
        sys.exit("vw-vault is locked: run `vw-vault unlock` in the owner's terminal")
    if not resp.get("ok"):
        sys.exit(resp.get("error"))
    while True:
        time.sleep(3)
        job = call("job_status").get("result") or {}
        if job.get("state") != "running":
            break
    print(json.dumps(job, ensure_ascii=False, indent=1))


def main() -> None:
    args = sys.argv[1:]
    if args[:1] == ["unlock"]:
        unlock(enroll="--enroll" in args)
    elif args[:1] == ["forget-keys"]:
        (STATE_DIR / "fido-unlock.json").unlink(missing_ok=True)
        print("security keys forgotten: unlock asks for the master password again")
    elif args[:1] == ["status"]:
        print(json.dumps(call("status"), ensure_ascii=False, indent=1) if running() else "locked")
    elif args[:1] == ["lock"]:
        if not running():
            print("locked")
            return
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(str(socket_path()))
            # the daemon's pid from the socket peer credentials (Linux)
            pid = struct.unpack("3i", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0]
        os.kill(pid, signal.SIGTERM)
        print("locked")
    elif args[:1] == ["check"] and args[1:2] == ["logins"] and set(args[2:]) <= {"--dry-run"}:
        check_logins("--dry-run" in args)
    elif args[:1] == ["call"] and len(args) in (2, 3):
        if args[1] == "check_logins":
            sys.exit("check_logins is not available through call: run `vw-vault check logins` in your terminal")
        try:
            resp = call(args[1], json.loads(args[2]) if len(args) == 3 else {})
        except OSError:
            sys.exit("vw-vault is locked: run `vw-vault unlock` in the owner's terminal")
        print(json.dumps(resp, ensure_ascii=False, indent=1))
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
