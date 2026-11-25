"""vw-env: read a Vaultwarden collection with a read-only account and export it as variables.

In GitHub Actions (GITHUB_ENV set) every value is masked with ::add-mask:: before it is
appended to GITHUB_ENV. Elsewhere `export NAME=value` lines go to stdout, for `eval`;
`--format systemd` writes `NAME='value'` lines for a systemd EnvironmentFile instead.

The read-only account is configured with the usual VW_* variables, or with
--env-file (VW_ENV_FILE): KEY=VALUE lines of the same variables, a file that must not
be accessible by group or others (root 0600 on a runner host). The repository holds no secrets.
"""

import argparse
import os
import secrets
import shlex
import stat
import sys
from pathlib import Path

from .client import VwClient, VwError, load_config

ENV_FILE_VAR = "VW_ENV_FILE"

# Names that would let a secret change the behavior of later CI steps or of the shell that
# evals the exports. Compared case-insensitively; such items are skipped with a warning.
DANGEROUS_NAMES = frozenset({
    "PATH", "HOME", "SHELL", "IFS", "ENV", "BASH_ENV", "CDPATH", "PS4", "PROMPT_COMMAND",
    "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PERL5OPT",
    "PERL5LIB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS", "GIT_SSH_COMMAND",
})
DANGEROUS_PREFIXES = ("GITHUB_", "RUNNER_", "LD_", "DYLD_", "BASH_FUNC_")


def read_env_file(path: Path) -> dict[str, str]:
    try:
        mode = path.stat().st_mode
    except OSError:
        raise VwError("env file not found") from None
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise VwError("env file must not be accessible by group or others (use 0600)")
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        env[key] = value
    return env


def collection_values(env_file: Path | None = None, environ: dict[str, str] | None = None) -> dict[str, str]:
    environ = dict(os.environ if environ is None else environ)
    if env_file:
        environ.update(read_env_file(env_file))
    return VwClient(load_config(environ)).read_values()


def is_dangerous_name(name: str) -> bool:
    upper = name.upper()
    return upper in DANGEROUS_NAMES or upper.startswith(DANGEROUS_PREFIXES)


def filter_dangerous(values: dict[str, str]) -> dict[str, str]:
    """Drop names that could change how later steps run; warn with the name only."""
    safe = {}
    for name, value in values.items():
        if is_dangerous_name(name):
            print(f"vw-env: skipping {name}: name is on the denylist", file=sys.stderr)
        else:
            safe[name] = value
    return safe


def write_github_env(values: dict[str, str], github_env: Path, out) -> None:
    """Mask every value (each line separately), then append it to GITHUB_ENV."""
    for value in values.values():
        for part in value.splitlines():
            if part.strip():
                print(f"::add-mask::{part}", file=out)
    out.flush()
    with github_env.open("a") as f:
        for name, value in values.items():
            delim = f"vw_{secrets.token_hex(8)}"
            f.write(f"{name}<<{delim}\n{value}\n{delim}\n")


def write_exports(values: dict[str, str], out) -> None:
    for name, value in values.items():
        print(f"export {name}={shlex.quote(value)}", file=out)


def write_systemd(values: dict[str, str], out) -> None:
    """KEY='value' lines for a systemd EnvironmentFile (single quotes, no escapes inside); a value
    that cannot be written so (a quote, a newline) is skipped with its name on stderr."""
    for name, value in values.items():
        if "'" in value or "\n" in value or "\\" in value:
            print(f"vw-env: {name} skipped: not representable in an EnvironmentFile", file=sys.stderr)
            continue
        print(f"{name}='{value}'", file=out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vw-env", description=__doc__.split("\n")[0])
    parser.add_argument("--env-file", help=f"file with VW_* settings (default: ${ENV_FILE_VAR})")
    parser.add_argument("--format", choices=("auto", "export", "systemd"), default="auto",
                        help="auto: GITHUB_ENV in GitHub Actions, else export lines; "
                             "systemd: KEY='value' lines for an EnvironmentFile")
    args = parser.parse_args(argv)
    path = args.env_file or os.environ.get(ENV_FILE_VAR)
    try:
        values = filter_dangerous(collection_values(Path(path) if path else None))
        github_env = os.environ.get("GITHUB_ENV") if args.format == "auto" else None
        if args.format == "systemd":
            write_systemd(values, sys.stdout)
        elif github_env:
            write_github_env(values, Path(github_env), sys.stdout)
            print(f"vw-env: exported {len(values)} variables to GITHUB_ENV", file=sys.stderr)
        else:
            write_exports(values, sys.stdout)
    except VwError as exc:
        print(f"vw-env: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
