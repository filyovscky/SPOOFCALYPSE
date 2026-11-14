# SPOOFCALYPSE

[Russian documentation](README.ru.md)

SPF, DMARC, DKIM and MX checks for domain lists. DKIM signature verification for `.eml` files.
Reports: Markdown, CSV and JSON. No API keys required.

## Installation

Python 3.11+. Windows CMD:

```cmd
git clone https://github.com/filyovscky/SPOOFCALYPSE.git
cd SPOOFCALYPSE
python -m venv .venv
.venv\Scripts\python.exe -m pip install .
```

Linux / macOS:

```sh
git clone https://github.com/filyovscky/SPOOFCALYPSE.git
cd SPOOFCALYPSE
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/spoofcalypse --help
```

## Domain checks

Put one domain per line in `scope.txt`. See [scope.example.txt](scope.example.txt).

```cmd
spoofcalypse.cmd --file scope.txt --dkim-api --workers 4 --csv report.csv --md report.md
spoofcalypse.cmd example.com
spoofcalypse.cmd --file scope.txt --brief
spoofcalypse.cmd --file scope.txt --json > report.json
```

On Linux/macOS, replace `spoofcalypse.cmd` with `.venv/bin/spoofcalypse`.

## Email checks

```cmd
spoofcalypse.cmd --eml message.eml --md email_report.md
spoofcalypse.cmd --eml first.eml --eml second.eml --json > emails.json
```

Checks all DKIM signatures using selectors from the message and public keys from DNS.
`PASS` means at least one signature verifies. This mode does not evaluate DMARC From alignment.
Email results appear in Markdown and JSON. CSV contains domain results only.

## Statuses

| Check | Statuses |
| --- | --- |
| Domain | `SPOOFABLE`, `POSSIBLE`, `NOT_SPOOFABLE`, `UNKNOWN` |
| DKIM discovery | `FOUND`, `NOT_FOUND`, `PARTIAL`, `ERROR`, `SKIPPED` |
| DKIM key | `VALID`, `INVALID`, `REVOKED`, `UNSUPPORTED` |
| Email signature | `PASS`, `FAIL`, `ERROR`, `UNSIGNED` |

`NOT_SPOOFABLE`: no bypass identified by DNS checks. `UNKNOWN`: insufficient data.
Risk `0–100`: sum of risk factors. `N/A`: score not calculated.
`NOT_FOUND`: no key found among the checked selectors.
`NXDOMAIN`: the DNS name does not exist. Registration availability is not checked.

## Options

| Option | Function |
| --- | --- |
| `--file FILE` | Domain list |
| `--md FILE` | Detailed Markdown report |
| `--csv FILE` | Domain results table |
| `--json` | JSON to stdout |
| `--eml FILE` | Verify DKIM signatures. Repeatable |
| `--dkim-api` | Additional selectors from the public prove.email archive |
| `--selectors a,b` | Additional DKIM selectors |
| `--no-dkim` | Skip DKIM selector discovery |
| `--dns IP` | DNS resolver |
| `--workers N` | Worker threads. Default: 16 |
| `--timeout N` | DNS timeout in seconds. Default: 10 |
| `--brief` | Terminal summary only |

If the selector archive is unavailable, DNS checks continue without archived selectors.
DMARC processing follows RFC 9989. Deprecated `pct`, `rf` and `ri` tags produce diagnostics.

## Tests

```cmd
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m unittest discover -s . -v
spoofcalypse.cmd --selftest
```

## License and attribution

**CC BY-NC 4.0: non-commercial use with attribution.**
The decision matrix is adapted from [Spoofy](https://github.com/MattKeeley/Spoofy) by Matt Keeley.
Changes and dependency licenses: [THIRD_PARTY.md](THIRD_PARTY.md).
License text: [LICENSE](LICENSE). Attribution: [NOTICE](NOTICE).
Commercial use of the upstream matrix requires separate permission from its rights holder.
