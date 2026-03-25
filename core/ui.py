"""
UI and Terminal Formatting for FriendlyDNSReporter.
"""
import re
import sys
import shutil
from core.version import VERSION

COLOR_ENABLED = sys.stdout.isatty()

def _ansi(code):
    return code if COLOR_ENABLED else ""

# ANSI Palette
RESET = _ansi("\033[0m")
OK    = _ansi("\033[92m")  # Green
FAIL  = _ansi("\033[91m")  # Red
WARN  = _ansi("\033[93m")  # Yellow
INFO  = _ansi("\033[96m")  # Cyan
CRIT  = _ansi("\033[95m")  # Magenta/Purple
BOLD  = _ansi("\033[1m")
UNDER = _ansi("\033[4m")
BLINK = _ansi("\033[5m")
BRIGHT_RED = _ansi("\033[91;1m")

_PROGRESS_LAST = {}
_PROGRESS_LINE_LEN = {}

def strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", str(text))

def _status_tag(level):
    mapping = {
        "OK":   f"{OK}[OK]{RESET}",
        "WARN": f"{WARN}[WARN]{RESET}",
        "FAIL": f"{FAIL}[FAIL]{RESET}",
        "CRIT": f"{BRIGHT_RED}[CRIT]{RESET}",
        "INFO": f"{INFO}[INFO]{RESET}",
        "SKIP": f"{WARN}[SKIP]{RESET}",
    }
    return mapping.get(level, f"{INFO}[INFO]{RESET}")

def _format_metrics(items, width=3):
    chunks = []
    row = []
    for key, value in items:
        row.append(f"{key}: {value}")
        if len(row) == width:
            chunks.append(" | ".join(row))
            row = []
    if row:
        chunks.append(" | ".join(row))
    return chunks

def _ellipsize(text, width):
    text = str(text)
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[:width - 3] + "..."

def _compact_status(status, width=12):
    normalized = str(status)
    replacements = {
        "UNREACHABLE": "UNREACH",
        "NO_RECURSION": "NO_RECUR",
        "DISABLED": "DISABLED",
        "REFUSED": "REFUSED",
    }
    normalized = replacements.get(normalized, normalized)
    return _ellipsize(normalized, width)

def _fmt_latency(value, precision=0, na="N/A", warn_ms=150, crit_ms=500):
    if value is None:
        return f"{RESET}{na}{RESET}"
    try:
        val = float(value)
        clr = OK
        if val >= crit_ms: clr = FAIL
        elif val >= warn_ms: clr = WARN
        return f"{clr}{val:.{precision}f}ms{RESET}"
    except (TypeError, ValueError):
        return f"{RESET}{na}{RESET}"

def _fmt_reliability_bar(loss_pct, count=10):
    """Create a visual bar for packet loss: [●●●●●●●○○○]."""
    if loss_pct is None: return "[----------]"
    lost = round((loss_pct / 100.0) * count)
    ok = count - lost
    # Using dots for OK and circles for FAIL
    bar = f"{OK}{'●' * ok}{RESET}{FAIL}{'○' * lost}{RESET}"
    return f"[{bar}]"

def _fmt_probe_evidence(data, probe_name, label=None):
    label = label or probe_name
    protocol = data.get(f"{probe_name}_protocol")
    rcode = data.get(f"{probe_name}_rcode")
    flags = data.get(f"{probe_name}_flags") or []
    query_size = data.get(f"{probe_name}_query_size")
    response_size = data.get(f"{probe_name}_response_size")
    authority_count = data.get(f"{probe_name}_authority_count")
    answer_count = data.get(f"{probe_name}_answer_count")
    aa = data.get(f"{probe_name}_aa")
    tc = data.get(f"{probe_name}_tc")
    http_status = data.get(f"{probe_name}_http_status")
    ra = data.get(f"{probe_name}_ra")

    details = []
    if protocol:
        details.append(f"proto={protocol}")
    if rcode:
        details.append(f"rcode={rcode}")
    if flags:
        details.append(f"flags={','.join(str(f) for f in flags[:4])}")
    if query_size is not None:
        details.append(f"q={query_size}B")
    if response_size is not None:
        details.append(f"r={response_size}B")
    if authority_count is not None:
        details.append(f"auth={authority_count}")
    if answer_count is not None:
        details.append(f"answers={answer_count}")
    if aa is not None:
        details.append(f"aa={'Y' if aa else 'N'}")
    if tc is not None:
        details.append(f"tc={'Y' if tc else 'N'}")
    if http_status is not None:
        details.append(f"http={http_status}")
    if ra is not None:
        details.append(f"ra={'Y' if ra else 'N'}")

    if not details:
        return f"{label}=N/A"
    return f"{label}=" + ",".join(details)

def _fmt_probe_repeat(data, probe_name, label=None):
    label = label or probe_name
    sample_count = data.get(f"{probe_name}_sample_count", 0) or 0
    if sample_count <= 0:
        return f"{label}=N/E"
    avg_latency = _fmt_latency(data.get(f"{probe_name}_latency_avg"))
    min_latency = _fmt_latency(data.get(f"{probe_name}_latency_min"))
    max_latency = _fmt_latency(data.get(f"{probe_name}_latency_max"))
    jitter = _fmt_latency(data.get(f"{probe_name}_latency_jitter"))
    stable = data.get(f"{probe_name}_status_consistent")
    stable_str = "stable" if stable is True else ("flap" if stable is False else "n/e")
    return f"{label}={sample_count}x {stable_str} [{min_latency}/{avg_latency}/{max_latency}] j={jitter}"

def get_score_color(score):
    if score >= 90: return OK
    if score >= 70: return WARN
    return FAIL

def format_grade(score):
    """Return a colored letter grade based on score."""
    if score >= 95: return f"{OK}A+{RESET}"
    if score >= 90: return f"{OK}A{RESET}"
    if score >= 80: return f"{OK}B{RESET}"
    if score >= 70: return f"{WARN}C{RESET}"
    if score >= 60: return f"{WARN}D{RESET}"
    return f"{FAIL}F{RESET}"

def print_banner(version=VERSION):
    print("\n" + "=" * 80)
    print(f"{BOLD}FRIENDLY DNS REPORTER {version}{RESET}")
    print("=" * 80)

def print_disclaimer():
    """Print the sarcastic legal disclaimer."""
    print(f"{CRIT}{BOLD}[!] LEGAL DISCLAIMER (OR 'DON'T SUE ME'){RESET}")
    print("This script is like a horoscope for your DNS: based on facts, interpreted by")
    print("algorithms, and subject to the mood of the network gods. By running it, you accept that:")
    
    print(f"\n1. {BOLD}Responsibility? Zero.{RESET} If your DNS explodes, your internet vanishes, or your cat")
    print("   learns COBOL because of this script, it's on you. We aren't lawyers;")
    print("   we're just people who run `dig` too much.")
    
    print(f"\n2. {BOLD}The Journey is Dark.{RESET} The script analyzes what it receives but lacks a crystal ball")
    print("   to know who intercepted your packet mid-flight. Creative ISPs, paranoid firewalls,")
    print("   and solar flares are not included in the report.")
    
    print(f"\n3. {BOLD}Scores are just Numbers.{RESET} The 0-100 score is a moral guide, not an absolute truth.")
    print("   A score of 100 doesn't make you master of the universe, and a 0 doesn't")
    print("   necessarily mean you should change careers.")
    
    print(f"\n4. {BOLD}Technological Hallucinations.{RESET} The results are a snapshot in time. If your")
    print("   environment's reality differs from what the script saw, trust your brain")
    print("   and analyze with caution.")
    
    print(f"\n5. {BOLD}Use at your own risk.{RESET} If you use this as the sole evidence to pick a fight,")
    print("   remember: 'Because it is always DNS' is a meme for a reason.")
    print("-" * 80)


def print_header(threads, consistency, target):
    output_mode = "rich console" if COLOR_ENABLED else "plain/export-safe"
    print(f"Threads: {threads} | Consistency: {consistency}x | Dataset: {target} | Output: {output_mode}")
    print("-" * 80)

def print_phase(name, objective=None):
    print(f"\n{BOLD}{INFO}>>> PHASE {name}{RESET}")
    if objective:
        print(f"  {_status_tag('INFO')} {objective}")

def print_phase_snapshot(title, items, interpretation=None):
    width = 80
    print(f"\n  ┏━ {BOLD}{title.upper()}{RESET} {'━' * (width - len(title) - 6)}┓")
    
    formatted_rows = _format_metrics(items, width=3)
    for row in formatted_rows:
        clean_row = strip_ansi(row)
        padding = width - len(clean_row) - 3
        print(f"  ┃ {row}{' ' * padding} ┃")
    
    if interpretation:
        print(f"  ┠{'─' * (width - 2)}┨")
        # Wrap interpretation if too long
        words = interpretation.split()
        lines = []
        curr = []
        for w in words:
            if sum(len(x)+1 for x in curr) + len(w) > width - 15:
                lines.append(" ".join(curr))
                curr = [w]
            else: curr.append(w)
        if curr: lines.append(" ".join(curr))
        
        for i, line in enumerate(lines):
            prefix = f"{BOLD}[TAKEAWAY]{RESET}: " if i == 0 else "            "
            padding = width - len(strip_ansi(prefix)) - len(line) - 3
            print(f"  ┃ {prefix}{line}{' ' * padding} ┃")
            
    print(f"  ┗{'━' * (width - 2)}┛")

def _print_boxed_card(title, lines, width=80):
    """Generic helper to print a boxed help/info card."""
    print(f"\n  ┌─ {BOLD}{title}{RESET} {'─' * (width - len(title) - 6)}┐")
    for line in lines:
        clean_line = strip_ansi(line)
        if len(clean_line) > width - 4:
            line = _ellipsize(line, width - 7)
            clean_line = strip_ansi(line)
        padding = width - len(clean_line) - 4
        print(f"  │ {line}{' ' * padding} │")
    print(f"  └{'─' * (width - 2)}┘")

def print_phase_header(name):
    if "1" in name:
        # Layout: IP ADDRESS | Reliability (Ping) | U53 (ms) | T53 (ms) | DoT (ms) | DoH (ms) | Sc | Status
        print(f"  {'IP ADDRESS':15} | {'RELIABILITY (PING)':20} | {'U53 (ms)':8} | {'T53 (ms)':8} | {'DoT (ms)':8} | {'DoH (ms)':8} | {'Sc':3} | Status")
        print("-" * 111)
    elif "2" in name:
        # Layout: SERVER | SOA SERIAL | LATENCY | Sc | AA | AXFR
        print(f"  {'SERVER':15} | {'SOA SERIAL':16} | {'LATENCY':8} | {'Sc':3} | {'AA':4} | {'AXFR':12}")
        print("-" * 72)
    elif "3" in name:
        # Layout: SERVER | TYPE | STATUS | LATENCY | Sync
        print(f"  {'SERVER':15} | {'TYPE':5} | {'STATUS':12} | {'LATENCY':8} | Sync")
        print("-" * 55)

def print_summary_table(total, success, fail, div, sync_issues, reports, duration: float = 0.0, sec_score=0, priv_score=0, show_legend=True, scores_available=False, security_available=False, privacy_available=False, show_security=True, show_privacy=True, takeaways=None, score_breakdown=None):
    width = 80
    build_tag = f"build v{VERSION}"
    
    print("\n" + "┏" + "━" * (width - 2) + "┓")
    print(f"┃ {BOLD}FINAL DIAGNOSTIC DASHBOARD{RESET} {' ' * (width - 32 - len(build_tag))} {INFO}{build_tag}{RESET} ┃")
    print("┣" + "━" * (width - 2) + "┫")
    
    metrics = [
        ("Total Queries", f"{total}"),
        ("Successful   ", f"{OK}{success}{RESET}"),
        ("Failures     ", f"{(FAIL if fail > 0 else OK)}{fail}{RESET}"),
        ("Divergences  ", f"{(WARN if div > 0 else OK)}{div}{RESET}"),
        ("Sync Issues  ", f"{(FAIL if sync_issues > 0 else OK)}{sync_issues}{RESET}")
    ]
    
    for label, val in metrics:
        clean_val = strip_ansi(val)
        padding = (width - 4) - len(label) - len(clean_val)
        print(f"┃ {label}: {val}{' ' * padding} ┃")
    
    print("┣" + "━" * (width - 2) + "┫")

    # Scores
    if show_security:
        sec_clr = get_score_color(sec_score)
        val_str = f"{sec_clr}{sec_score}/100{RESET}" if security_available else f"{WARN}N/A{RESET}"
        lbl = "SECURITY SCORE"
        print(f"┃ {BOLD}{lbl:18}:{RESET} {val_str}{' ' * (width - 24 - len(strip_ansi(val_str)))} ┃")

    if show_privacy:
        priv_clr = get_score_color(priv_score)
        val_str = f"{priv_clr}{priv_score}/100{RESET}" if privacy_available else f"{WARN}N/A{RESET}"
        lbl = "PRIVACY SCORE"
        print(f"┃ {BOLD}{lbl:18}:{RESET} {val_str}{' ' * (width - 24 - len(strip_ansi(val_str)))} ┃")

    if scores_available:
        avg_score = (sec_score + priv_score) / 2
        grade = format_grade(avg_score)
        val_str = f"{grade} ({avg_score:.1f}%)"
        lbl = "GLOBAL GRADE"
        print(f"┃ {BOLD}{lbl:18}:{RESET} {val_str}{' ' * (width - 24 - len(strip_ansi(val_str)))} ┃")

    if score_breakdown:
        print("┣" + "━" * (width - 2) + "┫")
        print(f"┃ {UNDER}SCORING BREAKDOWN{RESET}{' ' * (width - 21)} ┃")
        for item in score_breakdown[:6]: # Limit to top 6
            icon = f"{OK}✔{RESET}" if "OK" in item.upper() or "+" in item else (f"{FAIL}✘{RESET}" if "FAIL" in item.upper() or "-" in item else f"{INFO}•{RESET}")
            clean_item = strip_ansi(item)
            padding = (width - 8) - len(clean_item)
            print(f"┃  {icon} {item}{' ' * padding} ┃")

    if takeaways:
        print("┣" + "━" * (width - 2) + "┫")
        print(f"┃ {BOLD}EXECUTIVE TAKEAWAYS{RESET}{' ' * (width - 23)} ┃")
        for item in takeaways[:5]:
            clean_item = strip_ansi(item)
            padding = (width - 8) - len(clean_item)
            print(f"┃  {WARN}!{RESET} {item:75} ┃")
    
    print("┣" + "━" * (width - 2) + "┫")
    timer_str = f"{duration:6.2f}s"
    print(f"┃ {BOLD}TIME:{RESET} {timer_str} | {INFO}friendly-dns-reporter{RESET}{' ' * (width - 12 - len(timer_str) - 21 - 4)} ┃")
    print("┗" + "━" * (width - 2) + "┛")
    
    if show_legend:
        print_legend_summary()

    if reports:
        print(f"\n  {BOLD}Artifacts Generated:{RESET}")
        for label, path in reports.items():
            print(f"  {INFO}└─ {label:8}:{RESET} {path}")
    
    print(f"\n  {INFO}CONTRIBUTE: https://github.com/flashbsb/friendly_dns_reporter{RESET}\n")

def print_interrupt():
    print("\n\n" + "!" * 80)
    print(f" {FAIL}INTERRUPTED: User cancellation requested.{RESET}")
    print(" Terminating pending threads... please wait.")
    print("!" * 80 + "\n")

def _get_tree_connector(level, is_last):
    """Return the correct tree prefix (├─ or └─) based on level and position."""
    if level <= 0: return ""
    prefix = "   " * (level - 1)
    connector = "└─ " if is_last else "├─ "
    return prefix + connector

def print_tree_node(title, level=0, is_last=False, color=INFO):
    """Print a tree node header (e.g. [DOMAIN: google.com])."""
    conn = _get_tree_connector(level, is_last)
    print(f"  {conn}{color}[{title}]{RESET}")

def _fmt_port_serv(port_status, serv_status, lat):
    """Deep Service notation: OK (Service up), P_ONLY (Port only), CLOSE (Closed)."""
    if port_status == "CLOSED" or port_status == "FAIL":
        return FAIL, "CLOSE"
    if serv_status == "OK":
        return OK, f"OK({_fmt_latency(lat, 0)})" if lat is not None else "OK(N/A)"
    # Port is open but service failed/timeout
    return WARN, f"P_ONLY({_fmt_latency(lat, 0)})" if lat is not None else "P_ONLY(N/A)"

def _fmt_soa_timers(timers):
    """Format SOA timers into a readable RFC-centric block."""
    if not timers or len(timers) < 4:
        return f"{FAIL}N/A (Missing){RESET}"
    
    try:
        ref, ret, exp, mn = timers
        # Simple RFC 1912 compliance coloring
        def _c(val, min_v, max_v):
             try:
                 v = int(val)
                 if min_v <= v <= max_v: return f"{OK}{val}{RESET}"
                 return f"{WARN}{val}{RESET}"
             except: return str(val)

        # Refresh: 20m-12h | Retry: 2m-2h | Expire: 2w-4w | Min: 3m-1d
        ref_s = _c(ref, 1200, 43200)
        ret_s = _c(ret, 120, 7200)
        exp_s = _c(exp, 1209600, 2419200)
        min_s = _c(mn, 180, 86400)
        
        return f"[Ref: {ref_s} | Ret: {ret_s} | Exp: {exp_s} | Min: {min_s}]"
    except:
        return f"{FAIL}ERROR{RESET}"

def print_infra_detail(srv, data, level=1, is_last=False):
    ping_loss = data.get('packet_loss', 0.0)
    ping_count = data.get('ping_count', 0)
    lat_warn = data.get('ping_latency_warn', 100)
    lat_crit = data.get('ping_latency_crit', 250)
    loss_warn = data.get('ping_loss_warn', 15)
    loss_crit = data.get('ping_loss_crit', 50)
    
    loss_pct = int(ping_loss * 100)
    lat = data.get('latency') or 0
    rel_bar = _fmt_reliability_bar(loss_pct, ping_count if ping_count > 0 else 10)
    
    if data['ping'] == "OK":
        if loss_pct >= loss_crit or lat >= lat_crit: rel_clr = FAIL
        elif loss_pct >= loss_warn or lat >= lat_warn: rel_clr = WARN
        else: rel_clr = OK
        rel_str = f"{rel_bar} {rel_clr}{loss_pct:3d}%{RESET}"
    else:
        rel_str = f"{FAIL}[XXXXXXXXXX] 100%{RESET}"
        
    # Column Latencies
    u53_lat = _fmt_latency(data.get('recursion_lat'), 0)
    t53_lat = _fmt_latency(data.get('port53t_lat'), 0)
    dot_lat = _fmt_latency(data.get('dot_lat'), 0)
    doh_lat = _fmt_latency(data.get('doh_lat'), 0)
    
    # Privacy/Security Capabilities (S E K Q X)
    def _cap(key, char):
        val = data.get(key)
        if val in [True, "OK"]: return f"{OK}{char}{RESET}"
        return f"{FAIL}-{RESET}"
    
    caps = f"{_cap('dnssec', 'S')}{_cap('edns0', 'E')}{_cap('cookies', 'K')}{_cap('qname_min', 'Q')}{_cap('ecs', 'X')}"

    # Status
    alive_str = f"{OK}ALIVE{RESET}" if not data['is_dead'] else f"{FAIL}DEAD{RESET}"
    
    # Granular Score
    score = data.get('infrastructure_score', 0)
    score_clr = get_score_color(score)
    score_str = f"{score_clr}{score:3d}{RESET}"

    # Tree Connector
    conn = _get_tree_connector(level, is_last)
    tree_indent = "   " * level

    # Layout: GROUP (Removed) | IP ADDRESS | Reliability (PING) | U53 | T53 | DoT | DoH | Sc | Status
    print(f"  {conn}{srv:15} | {rel_str:20} | {u53_lat:8} | {t53_lat:8} | {dot_lat:8} | {doh_lat:8} | {score_str} | {alive_str}")

    profile = data.get("server_profile", "unknown")
    resolver_class = data.get("classification", "UNKNOWN")
    resolver_conf = data.get("confidence", "NONE")
    version = data.get("version", "N/A")
    web_risks = data.get("web_risks", [])
    web_risk_str = f"{FAIL}" + ",".join(str(p) for p in web_risks) + f"{RESET}" if web_risks else f"{OK}none{RESET}"
    
    dnssec_mode = data.get('dnssec_mode', 'DATA_SERVING')
    dnssec_clr = OK if dnssec_mode in ["DATA_SERVING", "VALIDATING"] else (WARN if dnssec_mode == "PARTIAL" else FAIL)
    
    qname_min = data.get('qname_min_confidence', 'NONE').upper()
    qname_clr = OK if qname_min in ["HIGH", "MEDIUM"] else (WARN if qname_min == "LOW" else FAIL)

    # Indent sub-lines
    sub_prefix = "  " + tree_indent + "├─ "
    last_sub_prefix = "  " + tree_indent + "└─ "

    # ├─ Profile/Resolver/Version
    print(f"{sub_prefix}{BOLD}Profile{RESET}  : {profile:9} | {BOLD}Resolver{RESET}: {resolver_class}/{resolver_conf:7} | {BOLD}Version{RESET}: {version}")
    
    # ├─ Transit (Ping/UDP/TCP)
    ping_avg = _fmt_latency(data.get('latency'))
    ping_range = f"[{_fmt_latency(data.get('latency_min'))}..{_fmt_latency(data.get('latency_max'))}]"
    udp53 = _fmt_latency(data.get('udp53_probe_lat'))
    tcp53 = _fmt_latency(data.get('port53t_probe_lat'))
    print(f"{sub_prefix}{BOLD}Transit{RESET}  : Ping={OK if data.get('ping')=='OK' else FAIL}{ping_avg}{RESET} {ping_range} | DNS: UDP={udp53} | TCP={tcp53}")
    
    # ├─ Crypto (DoT/DoH)
    dot_status = data.get('dot', 'FAIL')
    doh_status = data.get('doh', 'FAIL')
    dot_full = _fmt_latency(data.get('dot_lat'))
    doh_full = _fmt_latency(data.get('doh_lat'))
    print(f"{sub_prefix}{BOLD}Crypto{RESET}   : DoT={OK if dot_status=='OK' else FAIL}{dot_full}{RESET} | DoH={OK if doh_status=='OK' else FAIL}{doh_full}{RESET}")
    
    # └─ Features (Caps/DNSSEC/QNAME)
    print(f"{last_sub_prefix}{BOLD}Features{RESET} : {caps} | {BOLD}DNSSEC{RESET}={dnssec_clr}{dnssec_mode}{RESET} | {BOLD}QNAME-Min{RESET}={qname_clr}{qname_min}{RESET} | {BOLD}WebRisk{RESET}={web_risk_str}")

def print_zone_detail(srv, domain, res, level=2, is_last=False):
    serial = res.get('serial', '?')
    status = res.get('status', 'ERROR')
    axfr_ok = res.get('axfr_vulnerable', False)
    aa = res.get('aa', False)
    lat = res.get('latency')
    synced = res.get('zone_is_synced', True)
    
    # SOA Serial Status Formatting
    if status == "NOERROR" and serial != "?":
        if synced:
            serial_str = f"{OK}OK({serial}){RESET}"
        else:
            serial_str = f"{FAIL}FAIL({serial}){RESET}"
    elif status != "NOERROR":
        # Show the error status instead of '?' for clearer diagnostics
        serial_str = f"{FAIL}{_compact_status(status, 12)}{RESET}"
    else:
        # Query succeeded but no SOA record found
        serial_str = f"{FAIL}NODATA      {RESET}"
        
    # AXFR Policy & Color Logic
    axfr_detail = res.get('axfr_detail', 'DISABLED')
    allowed_groups = res.get('axfr_allowed_groups', [])
    current_group = res.get('group', 'UNCATEGORIZED').upper()
    is_expected = any(g in current_group for g in allowed_groups) if allowed_groups else False
    
    if axfr_ok:
        axfr_str = f"XFR-OK ({axfr_detail.split(' ')[0]} nodes)" if "nodes" in axfr_detail else "XFR-OK"
        axfr_clr = OK if is_expected else FAIL
    else:
        if "REFUSED" in axfr_detail or "REJECTED" in axfr_detail:
            axfr_str = "REFUSED"
            axfr_clr = WARN if is_expected else OK
        elif "TIMEOUT" in axfr_detail:
            axfr_str = "TIMEOUT"
            axfr_clr = WARN
        elif "DISABLED" in axfr_detail:
            axfr_str = "DISABLED"
            axfr_clr = RESET
        else:
            axfr_str = "ERROR"
            axfr_clr = FAIL

    # AA Status
    aa_str = f"{OK}YES{RESET}" if aa else f"{FAIL} NO{RESET}"
    if status != "NOERROR": aa_str = "--  "
    
    # Latency Color Logic
    warn_ms = res.get('soa_latency_warn', 500)
    crit_ms = res.get('soa_latency_crit', 1500)
    lat_str = _fmt_latency(lat, 0, warn_ms=warn_ms, crit_ms=crit_ms)
    
    # Granular Score
    score = res.get('zone_score', 0)
    score_clr = get_score_color(score)
    score_str = f"{score_clr}{score:3d}{RESET}"

    # Tree Connector
    conn = _get_tree_connector(level, is_last)
    tree_indent = "   " * level

    server_str = _ellipsize(srv, 15)
    serial_out = serial_str if status == "NOERROR" else f"{FAIL}{_compact_status(status, 12):16}{RESET}"
    axfr_out = _ellipsize(axfr_str, 12)
    
    # Layout: DOMAIN (Removed) | GROUP (Removed) | SERVER | SOA SERIAL | LATENCY | Sc | AA | AXFR
    print(f"  {conn}{server_str:15} | {serial_out:16} | {lat_str:8} | {score_str} | {aa_str} | {axfr_clr}{axfr_out:12}{RESET}")

    dnssec = res.get("dnssec")
    dnssec_str = f"{OK}SIGNED{RESET}" if dnssec is True else (f"{FAIL}UNSIGNED{RESET}" if dnssec is False else "N/E")
    caa_count = len(res.get("caa_records", []))
    caa_str = f"{OK}{caa_count}{RESET}" if caa_count > 0 else f"{WARN}0{RESET}"
    ns_consistent_val = res.get("ns_consistent")
    ns_consistent = f"{OK}YES{RESET}" if ns_consistent_val is True else (f"{FAIL}NO{RESET}" if ns_consistent_val is False else "N/E")
    
    scope = res.get("check_scope", "FULL")
    scope_clr = OK if scope == "FULL" else WARN
    
    audit_data = res.get("zone_audit", {})
    timer_audit_str = f"{OK}RFC-OK{RESET}" if audit_data.get("timers_ok", True) else f"{FAIL}RFC-FAIL{RESET}"

    # Indent sub-lines
    sub_prefix = "  " + tree_indent + "├─ "
    last_sub_prefix = "  " + tree_indent + "└─ "

    # ├─ Audit (Scope/DNSSEC/CAA/NS)
    print(f"{sub_prefix}{BOLD}Audit{RESET}    : Scope={scope_clr}{scope}{RESET} | DNSSEC={dnssec_str} | CAA={caa_str} | NS-Consistent={ns_consistent}")
    
    # ├─ Timers (The new comparison table)
    timer_line = _fmt_soa_timers(res.get("soa_timers"))
    print(f"{sub_prefix}{BOLD}Timers{RESET}   : {timer_line} ({timer_audit_str})")
    
    # ├─ Transit (Ping/SOA/NS/AXFR)
    ping_lat = _fmt_latency(res.get('ping_latency'))
    soa_lat_full = _fmt_latency(res.get('soa_latency'))
    ns_lat_full = _fmt_latency(res.get('ns_latency'))
    print(f"{sub_prefix}{BOLD}Transit{RESET}  : Ping={ping_lat} | SOA: UDP={soa_lat_full} | NS: UDP={ns_lat_full}")
    
    # └─ Evidence (SOA/AXFR/CAA)
    soa_ev = _fmt_probe_evidence(res, 'soa', 'SOA')
    axfr_ev = f"{axfr_clr}{res.get('axfr_detail', 'N/A')}{RESET}"
    print(f"{last_sub_prefix}{BOLD}Evidence{RESET} : {soa_ev} | AXFR={axfr_ev}")

def print_zone_audit_block(domain, audit):
    """Print a concise summary of advanced zone diagnostics."""
    print(f"  {INFO}>> [ZONE AUDIT: {domain}]{RESET}")
    
    # DNSSEC
    sec_str = f"{OK}SIGNED{RESET}" if audit.get("dnssec") else f"{WARN}UNSIGNED{RESET}"
    
    # Timers
    t_ok = audit.get("timers_ok", True)
    tim_str = f"{OK}RFC-OK{RESET}" if t_ok else f"{FAIL}NON-COMPLIANT{RESET}"
    
    # MNAME (Optional)
    m_reach = audit.get("mname_reachable")
    m_str = ""
    if m_reach:
        upper_reach = str(m_reach).upper()
        m_clr = OK if "(UP)" in upper_reach else (FAIL if "(DOWN)" in upper_reach else WARN)
        m_str = f" [MNAME: {m_clr}{m_reach}{RESET}]"
        
    # Web Risk
    w_risk = audit.get("web_risk", False)
    web_str = f"{FAIL}EXPOSED!{RESET}" if w_risk else f"{OK}SAFE{RESET}"
    
    print(f"     [DNSSEC: {sec_str}] [TIMERS: {tim_str}]{m_str} [WEB-RISK: {web_str}]")
    
    if not t_ok and audit.get("timers_issues"):
        for issue in audit["timers_issues"]:
            print(f"       {WARN}! {issue}{RESET}")
    print("") # Spacer

def print_warning(msg):
    print(f"  {WARN}{msg}{RESET}")

def print_phase_footer(name, metrics, duration: float = 0.0, insights=None):
    width = 80
    print(f"\n  {BOLD}RESULT SUMMARY: PHASE {name.upper()}{RESET}")
    print(f"  {'═' * width}")
    
    rows = _format_metrics(list(metrics.items()), width=3)
    for r in rows:
        print(f"  {r}")

    if insights:
        print(f"\n  {BOLD}ANALYTICAL SIGNALS{RESET}")
        for k, v in insights.items():
            # Determine icon based on key
            icon = f"{INFO}[i]{RESET}"
            if any(x in k.upper() for x in ["HEALTH", "COMPLIANCE", "STABILITY"]): icon = f"{OK}[H]{RESET}"
            if any(x in k.upper() for x in ["EXPOSURE", "RISK", "VULN"]): icon = f"{FAIL}[×]{RESET}"
            if any(x in k.upper() for x in ["FALLBACK", "LATENCY"]): icon = f"{WARN}[!]{RESET}"
            
            print(f"  {icon} {BOLD}{k:22}{RESET}: {v}")

    if duration > 0.0:
        print(f"\n  {INFO}>> Process completed in {duration:.2f}s{RESET}")
    print("  " + "─" * width)

def format_result(target, group, server, rtype, status, latency, is_consistent, level=3, is_last=False, warn_ms=150, crit_ms=500, ad=False):
    if status == "NOERROR" or status == "NXDOMAIN":
        status_clr = OK
    elif "TIMEOUT" in status or "UNREACHABLE" in status:
        status_clr = WARN
    else:
        status_clr = FAIL
        
    status_str = _compact_status(status, 12)
    if ad:
        status_str = f"{status_str[:9]}(AD+)" if len(status_str) > 9 else f"{status_str}(AD+)"

    lat_str = _fmt_latency(latency, 1, warn_ms=warn_ms, crit_ms=crit_ms)
    consistency_str = f" [{WARN}DIV!{RESET}]" if not is_consistent else f"{OK}OK{RESET}"
    
    server_str = _ellipsize(server, 15)
    
    # Tree Connector
    conn = _get_tree_connector(level, is_last)
    
    # Layout: TARGET (Removed) | GROUP (Removed) | SERVER | TYPE | STATUS | LATENCY | Sync
    return f"  {conn}{server_str:15} | {rtype:5} | {status_clr}{status_str:12}{RESET} | {lat_str:8} | {consistency_str}"

def print_record_findings(findings):
    """Print semantic findings/warnings for a specific record."""
    if not findings:
        return
        
    for finding in findings:
        # Identify severity (simple keyword matching)
        if any(w in finding.upper() for w in ["INVAL!", "MISSING", "REQUIRED", "DANGLING"]):
            clr = FAIL
        elif any(w in finding.upper() for w in ["PERMISSIVE", "INSECURE", "HIGH", "MONITORING"]):
            clr = WARN
        else:
            clr = INFO
            
        print(f"       {clr}-> {finding}{RESET}")

def print_record_context(record, level=3):
    """Print structured diagnostic context for the record."""
    answers = str(record.get("answers", ""))
    if len(answers) > 110:
        answers = answers[:107] + "..."

    # Amplification Ratio
    q_size = record.get("query_size") or 1
    r_size = record.get("response_size") or 0
    ratio = r_size / q_size if q_size > 0 else 0
    ratio_clr = FAIL if ratio > 10 else (WARN if ratio > 5 else OK)
    amp_str = f"{ratio_clr}{ratio:.1f}x{RESET} ({r_size}B/{q_size}B)"

    # Chain Depth
    chain = record.get("chain_depth", 1)
    chain_str = f"{chain} hops" if chain > 1 else "Direct"

    nsid = _ellipsize(record.get("nsid") or "-", 15)
    
    # Indent sub-lines
    tree_indent = "   " * level
    sub_prefix = "  " + tree_indent + "├─ "
    last_sub_prefix = "  " + tree_indent + "└─ "

    print(f"{sub_prefix}Transit: Ping={_fmt_latency(record.get('ping_latency'))} | DNS: UDP={_fmt_latency(record.get('latency'))} | Amplification: {amp_str}")
    print(f"{sub_prefix}Crypto : DoT={_fmt_latency(record.get('dot_latency'))} | DoH={_fmt_latency(record.get('doh_latency'))}")
    print(f"{sub_prefix}Perf   : Jitter={_fmt_latency(record.get('latency_jitter'))} | Avg={_fmt_latency(record.get('latency_avg'))} | Chain: {chain_str}")
    print(f"{last_sub_prefix}NSID: {nsid} | Answers: {answers}")

def print_progress(current, total, prefix="", length=30, status_suffix=""):
    """Prints a carriage-return progress bar."""
    percent = (current / total) * 100
    if current >= total:
        status_suffix = ""
    if not COLOR_ENABLED:
        bucket = int(percent // 10)
        if current in (1, total) or _PROGRESS_LAST.get(prefix) != bucket:
            _PROGRESS_LAST[prefix] = bucket
            suffix = f" | {status_suffix}" if status_suffix else ""
            print(f"  {_status_tag('INFO')} {prefix}: {percent:3.0f}% ({current}/{total}){suffix}")
        return
    filled = int(length * current // total)
    bar = "#" * filled + "-" * (length - filled)
    suffix = f" | {status_suffix}" if status_suffix else ""
    line = f"  {INFO}{prefix}{RESET} |{bar}| {percent:3.0f}% ({current}/{total}){suffix}"
    plain_line = strip_ansi(line)
    last_len = _PROGRESS_LINE_LEN.get(prefix, 0)
    width = shutil.get_terminal_size((120, 20)).columns
    pad = max(last_len - len(plain_line), 0)
    visible_line = plain_line if len(plain_line) <= width - 1 else plain_line[:width - 1]
    render_line = line if len(plain_line) <= width - 1 else strip_ansi(line)[:width - 1]
    print(f"\r{render_line}{' ' * pad}", end="", flush=True)
    _PROGRESS_LINE_LEN[prefix] = len(visible_line)
    if current == total:
        _PROGRESS_LINE_LEN[prefix] = 0
        print()

def format_progress_status(active_items=None, idle_for=0.0):
    active_items = active_items or []
    focus = ", ".join(active_items[:3]) if active_items else "waiting for worker completion"
    suffix = f"active: {focus}"
    if len(active_items) > 3:
        suffix += f" (+{len(active_items) - 3} more)"
    suffix += f" | idle {idle_for:.0f}s"
    return suffix

def print_legend_phase1_table():
    """Legend for Phase 1 results table (Infrastructure)."""
    _print_boxed_card("PHASE 1 HELP: Infrastructure Check", [
        f"{BOLD}RELIABILITY{RESET} : Ping loss visual bar and percentage.",
        f"{BOLD}U53 / T53 {RESET}    : DNS Port 53 Availability (UDP/TCP).",
        f"{BOLD}DoT / DoH {RESET}    : Encrypted DNS Latency (Po853/Po443).",
        f"{BOLD}Sc / Status{RESET}   : Individual infra score and reachability.",
        f"{BOLD}Features {RESET}     : [S]igned [E]dns [K]ookies [Q]name [X]ecs"
    ])

def print_legend_phase1_analytics():
    """Legend for Phase 1 analytical summary."""
    _print_boxed_card("PHASE 1 ANALYTICS CRITERIA", [
        f"{BOLD}Infra Health{RESET} : Average score (100% = Full modern security).",
        f"{BOLD}Adoption{RESET}     : Percentage of servers with modern features.",
        f"{BOLD}Net-Health{RESET}   : Composite latency index (not ping alone)."
    ])

def print_legend_phase2_table():
    """Legend for Phase 2 results table (Zone Integrity)."""
    _print_boxed_card("PHASE 2 HELP: Zone Integrity Check", [
        f"{BOLD}SOA SERIAL{RESET} : Version sync status ({OK}OK{RESET}=Synced | {FAIL}FAIL{RESET}=Desync).",
        f"{BOLD}LATENCY   {RESET} : Response time for authoritative probes.",
        f"{BOLD}AA / AXFR {RESET} : Auth-Answer flag and Zone Transfer vulnerability.",
        f"{BOLD}Timers    {RESET} : SOA RFC-compliance check (Ref/Ret/Exp/Min)."
    ])

def print_legend_phase2_analytics():
    """Legend for Phase 2 analytical summary."""
    _print_boxed_card("PHASE 2 ANALYTICS CRITERIA", [
        f"{BOLD}Zone Compliance{RESET}: Overall adherence to security standards.",
        f"{BOLD}Sync Health    {RESET}: Percentage of zones fully synchronized.",
        f"{BOLD}CAA Adoption   {RESET}: SSL policy visibility (RFC 8659)."
    ])

def print_legend_phase3_table():
    """Legend for Phase 3 results table (Record Consistency)."""
    _print_boxed_card("PHASE 3 HELP: Record Consistency Check", [
        f"{BOLD}STATUS {RESET}      : {OK}NOERROR{RESET}, {WARN}NXDOMAIN{RESET}, {FAIL}FAIL{RESET} states.",
        f"{BOLD}Sync   {RESET}      : Record stability check ({OK}OK{RESET} or {WARN}DIV!{RESET}).",
        f"{BOLD}AD+ flag{RESET}     : DNSSEC Authenticated Data bit from resolver.",
        f"{BOLD}Amplification{RESET}: Byte ratio (High risk if >10x)."
    ])

def print_legend_phase3_analytics():
    """Legend for Phase 3 analytical summary."""
    _print_boxed_card("PHASE 3 ANALYTICS CRITERIA", [
        f"{BOLD}Stability Index{RESET}: Result consistency across sequential checks.",
        f"{BOLD}Finding Density{RESET}: Average volume of issues per query.",
        f"{BOLD}Network Jitter {RESET}: Timing variance across repeated probes."
    ])

def print_legend_summary():
    """Legend for Final Audit Summary."""
    _print_boxed_card("FINAL DASHBOARD LEGEND & CRITERIA", [
        f"{INFO}SECURITY SCORE{RESET} : DNSSEC, CAA, AXFR, Cookies, OpenRes.",
        f"{INFO}PRIVACY SCORE {RESET} : DoT, DoH, QNAME-Min, ECS Masking.",
        f"{INFO}GRADING SYSTEM{RESET} : {OK}A/A+(90+){RESET} | {WARN}C/D(60-80){RESET} | {FAIL}F(<60){RESET}."
    ])
