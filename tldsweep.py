#!/usr/bin/env python3
"""
TLDSWEEP v1.1 - TLD Bruteforce Scanner
by @0xnhsec | github.com/0xnhsec

Usage:
  tldsweep [http|https|both] <target> -tld <mode> [options] [-o file.txt]
"""

import argparse
import socket
import sys
import string
import time
from datetime import datetime
import concurrent.futures

try:
    import httpx
except ImportError:
    print("[!] Missing: pip install httpx")
    sys.exit(1)

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

BANNER = r"""
███    ███ ██████   ██████
████  ████ ██   ██ ██
██ ████ ██ ██████  ██   ███
██  ██  ██ ██   ██ ██    ██
██      ██ ██████   ██████
TLD sweeper tools                    v1.1
Anonsec Bojonegoro | 0xnhsec with 3 name
"""
SEP = "─" * 78

# TLD Lists
def gen_aa_zz():
    """676 kombinasi TERURUT: aa->ab->...->az->ba->...->zz"""
    for a in string.ascii_lowercase:
        for b in string.ascii_lowercase:
            yield a + b

GTLD_LIST = [
    "com","net","org","info","biz","name","pro","mobi","tel","travel",
    "jobs","cat","coop","museum","aero","int","edu","gov","mil"
]
NEW_GTLD_LIST = [
    "app","dev","io","tech","online","site","web","cloud","digital",
    "store","shop","blog","media","news","agency","studio","design",
    "network","solutions","services","systems","group","team","global",
    "world","life","live","click","link","top","xyz","space","fun",
    "ai","ml","crypto","security","red","black","blue","green",
    "zone","center","ninja","guru","expert","works","tools","run",
    "page","codes","email","social","chat","audio","video","photos"
]
STLD_LIST = ["gov","edu","mil","int"]
CCTLD_VALID = [
    "ac","ad","ae","af","ag","ai","al","am","ao","aq","ar","as","at","au","aw",
    "ax","az","ba","bb","bd","be","bf","bg","bh","bi","bj","bm","bn","bo","bq",
    "br","bs","bt","bv","bw","by","bz","ca","cc","cd","cf","cg","ch","ci","ck",
    "cl","cm","cn","co","cr","cu","cv","cw","cx","cy","cz","de","dj","dk","dm",
    "do","dz","ec","ee","eg","er","es","et","eu","fi","fj","fk","fm","fo","fr",
    "ga","gb","gd","ge","gf","gg","gh","gi","gl","gm","gn","gp","gq","gr","gs",
    "gt","gu","gw","gy","hk","hm","hn","hr","ht","hu","id","ie","il","im","in",
    "io","iq","ir","is","it","je","jm","jo","jp","ke","kg","kh","ki","km","kn",
    "kp","kr","kw","ky","kz","la","lb","lc","li","lk","lr","ls","lt","lu","lv",
    "ly","ma","mc","md","me","mf","mg","mh","mk","ml","mm","mn","mo","mp","mq",
    "mr","ms","mt","mu","mv","mw","mx","my","mz","na","nc","ne","nf","ng","ni",
    "nl","no","np","nr","nu","nz","om","pa","pe","pf","pg","ph","pk","pl","pm",
    "pn","pr","ps","pt","pw","py","qa","re","ro","rs","ru","rw","sa","sb","sc",
    "sd","se","sg","sh","si","sj","sk","sl","sm","sn","so","sr","ss","st","su",
    "sv","sx","sy","sz","tc","td","tf","tg","th","tj","tk","tl","tm","tn","to",
    "tr","tt","tv","tw","tz","ua","ug","uk","um","us","uy","uz","va","vc","ve",
    "vg","vi","vn","vu","wf","ws","ye","yt","za","zm","zw"
]
ONION_HINTS   = {"onion","i2p","bit","p2p","zkey"}
DARK_ADJACENT = {"to","li","mx","cc","ws"}


def get_tld_list(tld_arg):
    arg = tld_arg.strip().upper()
    if arg == "AA-ZZ":
        return list(gen_aa_zz()), "AA-ZZ (ccTLD-format, 676 combinations)"
    if arg in ("G","GTLD"):
        return GTLD_LIST, "gTLD"
    if arg in ("NG","NEWGTLD","NEW"):
        return NEW_GTLD_LIST, "new gTLD"
    if arg in ("S","STLD"):
        return STLD_LIST, "sTLD"
    if arg in ("CC","CCTLD"):
        return CCTLD_VALID, f"ccTLD ({len(CCTLD_VALID)} valid entries)"
    if arg == "ALL":
        combined = list(dict.fromkeys(
            list(gen_aa_zz()) + GTLD_LIST + NEW_GTLD_LIST + STLD_LIST + CCTLD_VALID
        ))
        return combined, f"ALL ({len(combined)} entries)"
    return [tld_arg.lower()], f"single (.{tld_arg.lower()})"


def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

def get_hint(tld):
    if tld in ONION_HINTS:   return "onion-like"
    if tld in DARK_ADJACENT: return "dark-adj?"
    return "-"


def check_domain(name, tld, method, show_ip, show_ipn, timeout):
    domain = f"{name}.{tld}"
    result = {
        "tld":"", "domain":domain, "status":0,
        "scheme":"-", "ip":"-", "port":"-",
        "server":"-", "hint":"-", "error":"NXDOMAIN",
    }
    result["tld"] = tld

    if method == "https":
        schemes = [("https", 443)]
    elif method == "http":
        schemes = [("http", 80)]
    else:
        schemes = [("https", 443), ("http", 80)]

    for scheme, default_port in schemes:
        url = f"{scheme}://{domain}"
        try:
            with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
                r = c.get(url, headers={"User-Agent":"Mozilla/5.0 (TLDSWEEP/1.1)"})
            result["status"] = r.status_code
            result["scheme"] = scheme
            result["server"] = (r.headers.get("server") or "-")[:20]
            result["error"]  = None
            result["port"]   = str(default_port)
            if show_ip or show_ipn:
                ip = resolve_ip(domain)
                result["ip"] = ip if ip else "[NO_A_RECORD]"
            if show_ipn:
                result["hint"] = get_hint(tld)
            return result
        except httpx.ConnectError:
            result["error"] = "CONN_REFUSED"
            continue
        except httpx.TimeoutException:
            result["error"] = "TIMEOUT"
            break
        except Exception as e:
            result["error"] = str(e)[:25]
            break

    if result["status"] == 0 and (show_ip or show_ipn):
        ip = resolve_ip(domain)
        result["ip"] = ip if ip else f"[{result['error']}]"
        if show_ipn:
            result["hint"] = get_hint(tld)
    return result


def color_status(code):
    s = str(code) if code else "000"
    if code and 200 <= code < 300: return f"{GREEN}{BOLD}{s}{RESET}"
    if code and 300 <= code < 400: return f"{CYAN}{s}{RESET}"
    if code and 400 <= code < 500: return f"{YELLOW}{s}{RESET}"
    if code and 500 <= code < 600: return f"{RED}{s}{RESET}"
    return f"{DIM}{s}{RESET}"

COL_D=30; COL_I=18; COL_P=5; COL_S=20

def table_header(show_ipn):
    if show_ipn:
        print(f"  {'STATUS':^6} | {'DOMAIN':<{COL_D}} | {'IP':<{COL_I}} | {'PORT':>{COL_P}} | {'SERVER':<{COL_S}} | HINT")
        print("  " + "-"*7 + "+-" + "-"*COL_D + "-+-" + "-"*COL_I + "-+-" + "-"*COL_P + "-+-" + "-"*COL_S + "-+--------------")
    else:
        print(f"  {'STATUS':^6} | {'DOMAIN':<{COL_D}} | {'IP':<{COL_I}} | {'PORT':>{COL_P}} | SERVER")
        print("  " + "-"*7 + "+-" + "-"*COL_D + "-+-" + "-"*COL_I + "-+-" + "-"*COL_P + "-+----------------------")

def fmt_row(r, show_ipn):
    code = r["status"]
    dstr = f"{r['scheme']}://{r['domain']}" if r["scheme"] != "-" else r["domain"]
    cs   = color_status(code)
    if show_ipn:
        return f"  {cs:>3}   | {dstr:<{COL_D}} | {r['ip']:<{COL_I}} | {r['port']:>{COL_P}} | {r['server']:<{COL_S}} | {r['hint']}"
    return f"  {cs:>3}   | {dstr:<{COL_D}} | {r['ip']:<{COL_I}} | {r['port']:>{COL_P}} | {r['server']}"

def should_show(code, verbose):
    if verbose: return True
    return bool(code and 200 <= code < 400)


def main():
    p = argparse.ArgumentParser(
        prog="tldsweep",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="TLDSWEEP v1.1 - TLD Bruteforce Scanner by @0xnhsec",
        epilog="""
USAGE:
  tldsweep [http|https|both] <target> -tld <mode> [options] [-o file.txt]

CONTOH:
  tldsweep https fsec  -tld AA-ZZ -ipn -v
  tldsweep both  target -tld AA-ZZ -ip -v -o result.txt
  tldsweep https target -tld cc -ip
  tldsweep http  target -tld ng -v -ipn -o out.txt
  tldsweep both  target -tld all -ip -o all.txt

TLD MODE:
  AA-ZZ   676 kombinasi 2-huruf berurutan (aa->ab->...->az->ba->...->zz)
  cc      ccTLD valid (iana)
  g       gTLD  (com, net, org, ...)
  ng      new gTLD  (app, dev, io, tech, ai, ...)
  s       sTLD  (gov, edu, mil)
  all     Semua digabung
  <xyz>   Single TLD  contoh: -tld id
        """
    )
    p.add_argument("method", choices=["http","https","both"],
                   help="Protocol: http | https | both")
    p.add_argument("target", help="Nama domain, contoh: fsec")
    p.add_argument("-tld", required=True, metavar="MODE")
    p.add_argument("-ip",  action="store_true", help="Tampilkan IP + Port")
    p.add_argument("-ipn", action="store_true", help="IP + Port + hint")
    p.add_argument("-v",   action="store_true", help="Verbose semua status code")
    p.add_argument("-o",   metavar="FILE",      help="Output ke file .txt")
    p.add_argument("-w",   type=int, default=30, metavar="N", help="Workers (default:30)")
    p.add_argument("-timeout", type=int, default=8, metavar="S", help="Timeout detik (default:8)")
    args = p.parse_args()

    name     = args.target.split(".")[0]
    method   = args.method
    show_ip  = args.ip or args.ipn
    show_ipn = args.ipn
    tld_list, tld_desc = get_tld_list(args.tld)
    total    = len(tld_list)

    print(CYAN + BANNER + RESET)
    print(SEP)
    print(f"  [*] Target    : {BOLD}{name}{RESET}")
    print(f"  [*] TLD Mode  : {tld_desc}")
    m_label = {"https":"HTTPS only","http":"HTTP only","both":"HTTPS -> HTTP fallback"}[method]
    print(f"  [*] Method    : {m_label}")
    if show_ipn:   print(f"  [*] IP Resolve: ON (+hint)")
    elif show_ip:  print(f"  [*] IP Resolve: ON")
    if args.v:     print(f"  [*] Verbose   : ON (all status codes)")
    if args.o:     print(f"  [*] Output    : {args.o}")
    print(SEP)
    print()
    print(f"  {DIM}[~] Scanning... ({total} combinations){RESET}\n")
    table_header(show_ipn)

    # ── Scan paralel, simpan ke dict[index] ──────────────────────────────────
    # Kunci = index asli TLD list → setelah selesai, sort by index → output TERURUT
    results_map = {}
    start = time.time()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.w) as ex:
            future_to_idx = {
                ex.submit(check_domain, name, tld, method, show_ip, show_ipn, args.timeout): idx
                for idx, tld in enumerate(tld_list)
            }
            done = 0
            for future in concurrent.futures.as_completed(future_to_idx):
                idx = future_to_idx[future]
                results_map[idx] = future.result()
                done += 1
                if done % 100 == 0 or done == total:
                    pct = int(done / total * 100)
                    sys.stderr.write(f"\r  {DIM}[~] Progress: {done}/{total} ({pct}%)...{RESET}   ")
                    sys.stderr.flush()
    except KeyboardInterrupt:
        sys.stderr.write(f"\n\n  {YELLOW}[!] Interrupted{RESET}\n")

    sys.stderr.write("\r" + " "*60 + "\r")
    sys.stderr.flush()

    # ── Print TERURUT (sort by original TLD index) ────────────────────────────
    results_sorted = [results_map[i] for i in sorted(results_map)]
    live_list=[]; error_list=[]; dead_list=[]

    for r in results_sorted:
        code = r["status"]
        if should_show(code, args.v):
            print(fmt_row(r, show_ipn))
        if code and 200 <= code < 400:   live_list.append(r)
        elif code and 400 <= code < 600: error_list.append(r)
        else:                            dead_list.append(r)

    elapsed = time.time() - start
    print()
    print(SEP)
    print(f"  {GREEN}[+] Found    : {len(live_list)} live (2xx/3xx){RESET}")
    if args.v:
        print(f"  {YELLOW}[!] Error    : {len(error_list)} (4xx/5xx){RESET}")
        print(f"  {DIM}[x] Dead     : {len(dead_list)} (000 / NXDOMAIN / refused){RESET}")
    print(f"  {DIM}[i] Total    : {len(results_map)} checked | Duration: {elapsed:.1f}s{RESET}")

    if args.o:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M WIB")
        lines = [
            f"# TLDSWEEP Result | {name} | {ts}",
            f"# Method: {method.upper()} | TLD: {args.tld.upper()} | IP: {'ON' if show_ip else 'OFF'} | Verbose: {'ON' if args.v else 'OFF'}",
            "",
        ]
        def to_line(r):
            dstr = f"{r['scheme']}://{r['domain']}" if r["scheme"] != "-" else r["domain"]
            line = f"{r['status']} | {dstr} | {r['ip']} | {r['port']} | {r['server']}"
            if show_ipn: line += f" | {r['hint']}"
            return line

        for r in live_list: lines.append(to_line(r))
        if args.v:
            lines += ["","# --- 4xx/5xx ---"]
            for r in error_list: lines.append(to_line(r))
            lines += ["","# --- Dead/NXDOMAIN ---"]
            for r in dead_list:  lines.append(f"000 | {r['domain']} | {r['ip']} | - | -")

        try:
            with open(args.o, "w") as f:
                f.write("\n".join(lines) + "\n")
            print(f"  {GREEN}[+] Saved    : {args.o}{RESET}")
        except Exception as e:
            print(f"  {RED}[!] Gagal: {e}{RESET}")
    print()

if __name__ == "__main__":
    main()
