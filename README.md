# nxcblast

Spray credentials across every [NetExec](https://github.com/Pennyw0rth/NetExec) protocol at once -- hits only, lockout-aware, pastables on finish.

`nxcblast` is a thin Python wrapper around `nxc`. It does **not** reimplement SMB, WinRM, RDP, or any other protocol; every auth attempt is a real `nxc` subprocess. Console output is signal, not noise. Full verbose `nxc` output lands in a log file. When the spray finishes, you get paste-ready follow-up commands for each confirmed hit -- that you run yourself.

Inspired by [nxcspray](https://github.com/NTHSec/nxcspray). Big kudos to [NetExec](https://github.com/Pennyw0rth/NetExec) and [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec).

## Install

`nxc` must already be on your `PATH`. `nxcblast` is a single stdlib Python script -- no pip, no venv.

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

## vs vanilla NetExec

`nxc` is one protocol, one (or a few) targets, and a lot of stdout. `nxcblast` is the same `nxc` binary, pointed at every protocol you care about, with the noise stripped out.

- **Every protocol in one shot.** Omit protocols (or pass `all`) to hit smb, winrm, rdp, ssh, ftp, ldap, mssql, vnc, and wmi. Or pass a subset: `nxcblast smb,winrm targets.txt ...`
- **Hits only.** Failures, banners, and nxc chatter go to a log. The console is a table of confirmed access: target, protocol, creds, domain/local/mssql, and whether it was `(valid)` or `(Pwn3d!)`.
- **Does not auto-pwn.** nxcblast never runs enum or dump modules for you. At the end it prints **Pastables** -- ready-to-run `nxc`, evil-winrm, xfreerdp, smbexec, and similar follow-ups for the hits you actually got. Dump/exec suggestions only appear on `Pwn3d!` / shell.
- **Lockout-aware (soft guard).** Unique creds are counted per `(target, domain)` across protocols. Default pause is 3 unique creds, then 60s. Same password on SMB + WinRM + RDP counts as one attempt. This is not a policy oracle -- size `--lockout` yourself.
- **Concurrent, but not reckless.** Protocol×target lanes run in parallel (default 6). Each service on each box still takes one credential at a time.
- **Same auth shape as nxc.** `-u` / `-p` / `-H` take values or files. Multiple users and passwords are a cartesian product. `--nxcdb` replays confirmed creds from the current nxc workspace.
- **Safe defaults.** No user/password → null + guest. User and no secret → user-only. No target → refuse to run.

Flags, defaults, and every variant: `nxcblast -h`.

## Examples

```bash
nxcblast smb,winrm targets.txt -u admin -p 'Password1'
nxcblast targets.txt -u admin -p 'Password1'                 # no protocols = all
nxcblast 192.168.1.0/24 -u users.txt -p passwords.txt        # files, like nxc
nxcblast smb targets.txt -U users.txt -p 'Winter2026!' --lockout 3
nxcblast all targets.txt --nxcdb
nxcblast smb 10.10.10.5 -u admin -p Password1 --local-auth
```
