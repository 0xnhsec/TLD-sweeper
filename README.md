```
███    ███ ██████   ██████  
████  ████ ██   ██ ██       
██ ████ ██ ██████  ██   ███ 
██  ██  ██ ██   ██ ██    ██ 
██      ██ ██████   ██████  
TLD sweeper tools
```

# tldsweep

A simple TLD sweeper tool supporting ccTLD, gTLD, sTLD, and custom AA–ZZ brute-force combinations.

Given a target domain name, **tldsweep** iterates through TLD combinations, sends HTTP/HTTPS requests, and reports live domains with their status codes, resolved IPs, ports, and web server fingerprints.

---

## Features

- **AA–ZZ brute-force** — sweep all 676 two-letter TLD combinations in alphabetical order
- **Multiple TLD modes** — ccTLD, gTLD, new gTLD, sTLD, or all at once
- **Protocol control** — choose `http`, `https`, or `both` (with automatic fallback)
- **IP resolution** — resolve A records and display ports alongside results
- **Hint detection** — flag onion-adjacent or dark-adjacent TLDs with `-ipn`
- **Verbose mode** — show all status codes (000–5xx), not just live results
- **Parallel scanning** — configurable worker threads for fast sweeps
- **Output to file** — save results to `.txt` for later analysis

---

## Requirements

```bash
pip install httpx
```

Python 3.8+ required.

---

## Usage

```
tldsweep [http|https|both] <target> -tld <mode> [options] [-o file.txt]
```

### Arguments

| Argument | Description |
|---|---|
| `http \| https \| both` | Protocol to use. `both` tries HTTPS first, falls back to HTTP |
| `target` | Domain name without TLD (e.g. `fsec`, not `fsec.com`) |
| `-tld MODE` | TLD sweep mode (see table below) |
| `-ip` | Display resolved IP and port |
| `-ipn` | Display IP, port, and onion/dark-adjacent hint |
| `-v` | Verbose — show all status codes including 4xx, 5xx, and dead |
| `-o FILE` | Save output to a `.txt` file |
| `-w N` | Number of parallel workers (default: `30`) |
| `-timeout S` | Request timeout in seconds (default: `8`) |

### TLD Modes

| Flag | Description | Count |
|---|---|---|
| `AA-ZZ` | Brute-force all two-letter combinations (aa → zz) | 676 |
| `cc` | Valid ccTLD list (IANA) | ~250 |
| `g` | Generic TLD (com, net, org, ...) | 19 |
| `ng` | New gTLD (app, dev, io, tech, ai, ...) | ~50 |
| `s` | Sponsored TLD (gov, edu, mil) | 4 |
| `all` | All of the above combined | varies |
| `<xyz>` | Single custom TLD, e.g. `-tld id` | 1 |

---

## Examples

```bash
# Sweep all 676 two-letter TLD combinations over HTTPS with full verbose output
tldsweep https fsec -tld AA-ZZ -ipn -v

# Same sweep, save results to file (default: only 2xx/3xx)
tldsweep both target -tld AA-ZZ -ip -o result.txt

# Sweep valid ccTLDs with IP resolution
tldsweep https target -tld cc -ip

# New gTLD sweep, verbose, with hint detection, save output
tldsweep http target -tld ng -v -ipn -o out.txt

# Full sweep across all TLD modes
tldsweep both target -tld all -ip -o all.txt

# Single TLD check
tldsweep https target -tld id -ip
```

---

## Output

### Default (2xx / 3xx only)

```
  STATUS | DOMAIN                         | IP                 |  PORT | SERVER               | HINT
  -------+--------------------------------+--------------------+-------+----------------------+--------------
  200   | https://fsec.ai                | 3.33.130.190       |   443 | -                    | -
  301   | https://fsec.io                | 104.21.44.12       |   443 | cloudflare           | -

  [+] Found    : 2 live (2xx/3xx)
  [i] Total    : 676 checked | Duration: 38.2s
```

### Verbose (`-v`)

```
  000   | fsec.aa                        | [CONN_REFUSED]     |     - | -                    | -
  000   | fsec.ab                        | [CONN_REFUSED]     |     - | -                    | -
  200   | https://fsec.ai                | 3.33.130.190       |   443 | -                    | -
  404   | https://fsec.am                | 185.220.101.34     |   443 | nginx                | -

  [+] Found    : 1 live (2xx/3xx)
  [!] Error    : 1 (4xx/5xx)
  [x] Dead     : 674 (000 / NXDOMAIN / refused)
```

### File output format (`.txt`)

```
# TLDSWEEP Result | fsec | 2026-04-21 09:00 WIB
# Method: HTTPS | TLD: AA-ZZ | IP: ON | Verbose: OFF

200 | https://fsec.ai | 3.33.130.190 | 443 | -
```

---

## Notes

- Status `000` means the domain did not respond (NXDOMAIN, connection refused, or timeout)
- AA–ZZ mode includes non-delegated TLDs — most will return `000` or `CONN_REFUSED`
- Use `-w` to tune speed vs. noise; higher values scan faster but may trigger rate limits
- Results are always printed in alphabetical TLD order regardless of thread completion order

---

## Author

**@0xnhsec** — [github.com/0xnhsec](https://github.com/0xnhsec)
