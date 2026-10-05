# fxsweep

[![CI](https://github.com/ReazGan/fxsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/ReazGan/fxsweep/actions/workflows/ci.yml)

Scans a FiveM server for backdoors. Leaked and resold resources are how
Cipher Panel, Blum Panel and similar kits end up on servers: one obfuscated
line in a script you downloaded, and someone else can run code on your
machine. fxsweep looks for the patterns these kits use, the infrastructure
they talk to, and a few server mistakes that make the damage worse.

Single binary. No Python or Node, no network calls, nothing leaves your machine.

![fxsweep finding a webhook leak, a hidden manifest entry and a remote loader in a leaked resource](https://raw.githubusercontent.com/ReazGan/fxsweep/main/docs/screenshot.svg)

## Install

Grab the binary for your system from [Releases](https://github.com/ReazGan/fxsweep/releases):
`fxsweep-windows-amd64.exe`, `fxsweep-linux-amd64` or `fxsweep-linux-arm64`.

Or with Go 1.22+:

```
go install github.com/ReazGan/fxsweep@latest
```

## Usage

On Windows, drop `fxsweep.exe` into your `server-data` folder and double click
it. From a terminal:

```
fxsweep C:\FXServer\server-data
fxsweep -min high .                     # only high severity
fxsweep -json . > report.json
fxsweep -quarantine ..\quarantine .     # move infected files out of the server
fxsweep -ioc my-indicators.txt .        # add your own domains or strings
```

Exit status is `0` when clean, `1` when there is a high severity finding and
`2` on errors, so it can gate a CI job or a deploy script.

`-quarantine` only moves files that are the malware itself (loaders, droppers,
files with known indicators). Leaked webhooks, manifest entries and
`server.cfg` problems are reported but left in place. Every move is logged to
`fxsweep-quarantine.txt` inside the quarantine folder.

## Checks

| Rule  | Severity    | Looks for |
|-------|-------------|-----------|
| FX001 | high        | Known panel domains, operator keys and runtime markers ([indicators.txt](indicators.txt)) |
| FX002 | high        | `PerformHttpRequest` or `https.get` followed by `load`, `eval`, `new Function` or `vm` |
| FX003 | high        | XOR decoding loops (`String.fromCharCode(a[i]^k)`) used by JS droppers |
| FX004 | high/medium | Long `\x..` or `\ddd` escape runs, high when the decoded text is a URL or code |
| FX005 | medium      | Luraph and javascript-obfuscator output |
| FX006 | medium      | `os.execute`, `io.popen` or `child_process` in server scripts |
| FX007 | high        | txAdmin files patched by the Blum replicator, backdoor admin accounts |
| FX008 | high        | `load(string.char(...))`, `eval(atob(...))` and friends |
| FX010 | high        | Manifest entries pointing at dot files, or a commented out entry with a hidden script padded onto the same line |
| FX011 | medium      | Manifest entries under `node_modules/.` or `.cache/`, or with dropper file names |
| FX012 | high/low    | File names the Blum replicator uses for its droppers |
| FX020 | high        | Discord webhooks in client scripts or NUI files, which every player downloads |
| FX021 | high        | Database credentials in client files |
| FX030 | medium      | `rcon_password` set in `server.cfg` |
| FX031 | high        | `add_ace builtin.everyone command allow` and similar |

Client side files are worked out from each resource's `fxmanifest.lua`
(`client_scripts`, `shared_scripts`, `ui_page`, `files`, globs included).
The `cache` folder FXServer creates, `.git` folders, binaries and files over
8 MB are skipped.

## If something is found

A high finding means the server may already be compromised. Pull the files out
(or use `-quarantine`), then treat everything the server process could read as
leaked: txAdmin passwords, the database password, Discord bot tokens, the
Cfx.re license key. Check txAdmin's admin list for accounts you did not add.
If FXServer ran as Administrator on Windows, a clean OS install is the only
safe way back.

## GitHub Action

If you sell or publish resources, scan them before every release:

```yaml
- uses: actions/checkout@v4
- uses: ReazGan/fxsweep@v0.1.0
  with:
    path: .
    min: medium
```

## Indicators

`indicators.txt` is compiled into the binary. Most Blum Panel entries come
from the public [reverse engineering by Justice Gaming Network](https://github.com/ImJer/blum-panel-fivem-backdoor-analysis).
Seen a new panel domain or marker? Open an issue with the string and where
you found it.

## License

MIT
