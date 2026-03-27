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
DIM   = _ansi("\033[90m")  # Grey/Dim
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
        return f"{DIM}{na}{RESET}"
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
    # Using light green for dots (as per user request for lighter feel)
    dot_clr = _ansi("\033[38;5;121m") if COLOR_ENABLED else OK
    bar = f"{dot_clr}{'●' * ok}{RESET}{FAIL}{'○' * lost}{RESET}"
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
    d = DIM
    if protocol:
        details.append(f"{d}proto={RESET}{INFO}{protocol}{RESET}")
    if rcode:
        # Colorize common RCODEs
        clr = OK if rcode == "NOERROR" else (WARN if rcode in ["NXDOMAIN", "REFUSED"] else FAIL)
        details.append(f"{d}rcode={RESET}{clr}{rcode}{RESET}")
    if flags:
        details.append(f"{d}flags={RESET}{INFO}{','.join(str(f) for f in flags[:4])}{RESET}")
    if query_size is not None:
        details.append(f"{d}q={RESET}{INFO}{query_size}B{RESET}")
    if response_size is not None:
        details.append(f"{d}r={RESET}{INFO}{response_size}B{RESET}")
    if authority_count is not None:
        details.append(f"{d}auth={RESET}{INFO}{authority_count}{RESET}")
    if answer_count is not None:
        details.append(f"{d}answers={RESET}{INFO}{answer_count}{RESET}")
    if aa is not None:
        details.append(f"{d}aa={RESET}{OK if aa else FAIL}{'Y' if aa else 'N'}{RESET}")
    if tc is not None:
        details.append(f"{d}tc={RESET}{WARN if tc else OK}{'Y' if tc else 'N'}{RESET}")
    if http_status is not None:
        clr = OK if http_status == 200 else FAIL
        details.append(f"{d}http={RESET}{clr}{http_status}{RESET}")
    if ra is not None:
        details.append(f"{d}ra={RESET}{OK if ra else FAIL}{'Y' if ra else 'N'}{RESET}")

    if not details:
        return f"{DIM}{label}=N/A{RESET}"
    return f"{BOLD}{label}{RESET}=" + ",".join(details)

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
    width = 80
    print(f"\n{BOLD}{INFO}━━ PHASE {name.upper()} {'━' * (width - len(name) - 12)}{RESET}")
    if objective:
        print(f"  {objective}")
    print("")

def print_phase_progress(done, total, label):
    """Print a compact progress bar for phase processing."""
    width = 20
    pct = done / total if total > 0 else 0
    filled = int(pct * width)
    bar = f"{'█' * filled}{'░' * (width - filled)}"
    pct_str = f"{pct * 100:.0f}%"
    print(f"  PROGRESS ▏{bar}▏ {pct_str} ({done}/{total}) {label}")

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
    # Clean separator between phase intro and data rows
    print(f"  {'─' * 78}")

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
    """Print a tree node header. Level 0 uses ▶ for main groups."""
    if level == 0:
        print(f"  {color}▶ {title}{RESET}")
    else:
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
        def _c(val, min_v, max_v, extra_check=True):
             try:
                 v = int(val)
                 if min_v <= v <= max_v and extra_check: return f"{INFO}{val}{RESET}"
                 return f"{WARN}{val}{RESET}"
             except: return str(val)

        # RFC 1912 ranges + Retry < Refresh check
        ref_s = _c(ref, 1200, 43200)
        ret_s = _c(ret, 120, 7200, extra_check=(int(ret) < int(ref)))
        exp_s = _c(exp, 1209600, 2419200)
        min_s = _c(mn, 180, 86400)
        
        d = DIM
        r = RESET
        return f"{d}[Ref: {r}{ref_s} {d}| Ret: {r}{ret_s} {d}| Exp: {r}{exp_s} {d}| Min: {r}{min_s}{d}]{r}"
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

    # Layout: IP ADDRESS= srv | RELIABILITY (PING)= rel_str | U53 (ms)= u53 | T53 (ms)= t53 | DoT (ms)= dot | DoH (ms)= doh | Sc= score | Status= alive
    print(f"  {conn}IP ADDRESS={DIM} {RESET}{srv} | RELIABILITY (PING)={rel_str} | U53 (ms)={u53_lat} | T53 (ms)={t53_lat} | DoT (ms)={dot_lat} | DoH (ms)={doh_lat} | Sc={score_str} | Status={alive_str}")

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
    profile_clr = OK if profile == "authoritative" else (INFO if profile == "recursive" else WARN)
    
    # Resolver Classification Color
    if resolver_class == "PUBLIC": resolver_clr = FAIL
    elif resolver_class == "RESTRICTED": resolver_clr = OK
    else: resolver_clr = INFO # UNKNOWN or other
    
    # Confidence Color
    norm_conf = resolver_conf.upper()
    if norm_conf == "HIGH": conf_clr = OK
    elif norm_conf == "MEDIUM": conf_clr = WARN
    elif norm_conf == "LOW": conf_clr = FAIL
    else: conf_clr = RESET

    # Secure is HIDDEN (Green), revealed version is a leak (Red)
    if version in ["HIDDEN", "N/A", "DISABLED"]:
        version_clr = OK
    elif version in ["TIMEOUT", "ERROR"]:
        version_clr = WARN
    else:
        version_clr = FAIL
    
    # Combine Resolver and Confidence for cleaner alignment
    res_combined = f"{resolver_class}/{resolver_conf}"
    # Calculate padding to keep the Version field aligned (total 18 chars for resolver block)
    res_padding = " " * max(0, 18 - len(res_combined))
    res_display = f"{resolver_clr}{resolver_class}{RESET}/{conf_clr}{resolver_conf}{RESET}{res_padding}"

    print(f"{sub_prefix}{BOLD}Profile{RESET}  : {profile_clr}{profile:9}{RESET} | {BOLD}Resolver{RESET}: {res_display} | {BOLD}Version{RESET}: {version_clr}{version}{RESET}")
    
    # ├─ Transit (Ping/UDP/TCP)
    ping_avg = _fmt_latency(data.get('latency'))
    ping_range = f"[{_fmt_latency(data.get('latency_min'))}..{_fmt_latency(data.get('latency_max'))}]"
    udp53 = _fmt_latency(data.get('udp53_probe_lat'))
    tcp53 = _fmt_latency(data.get('port53t_probe_lat'))
    ping_status_clr = (OK if data.get('ping')=='OK' else FAIL) if data.get('latency') is not None else DIM
    print(f"{sub_prefix}{BOLD}Transit{RESET}  : Ping={ping_status_clr}{ping_avg}{RESET} {ping_range} | DNS: UDP={udp53} | TCP={tcp53}")
    
    # ├─ Crypto (DoT/DoH)
    dot_status = data.get('dot', 'FAIL')
    doh_status = data.get('doh', 'FAIL')
    dot_full = _fmt_latency(data.get('dot_lat'))
    doh_full = _fmt_latency(data.get('doh_lat'))
    # If it's N/A, we use DIM, otherwise we use the status color
    dot_clr = (OK if dot_status=='OK' else FAIL) if data.get('dot_lat') is not None else DIM
    doh_clr = (OK if doh_status=='OK' else FAIL) if data.get('doh_lat') is not None else DIM
    print(f"{sub_prefix}{BOLD}Crypto{RESET}   : DoT={dot_clr}{dot_full}{RESET} | DoH={doh_clr}{doh_full}{RESET}")
    
    # └─ Features (Caps/DNSSEC/QNAME)
    # Re-evaluating colors for potential N/A
    dnssec_mode_str = str(dnssec_mode)
    if dnssec_mode_str in ["N/A", "DISABLED", "UNKNOWN", "DEAD"]: d_clr = DIM
    else: d_clr = dnssec_clr
    
    qname_min_str = str(qname_min)
    if qname_min_str in ["N/A", "DISABLED", "NONE", "UNKNOWN"]: q_clr = DIM
    else: q_clr = qname_clr

    print(f"{last_sub_prefix}{BOLD}Features{RESET} : {caps} | {BOLD}DNSSEC{RESET}={d_clr}{dnssec_mode}{RESET} | {BOLD}QNAME-Min{RESET}={q_clr}{qname_min}{RESET} | {BOLD}WebRisk{RESET}={web_risk_str}")

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
    
    # Layout: SERVER= srv | SOA SERIAL= serial_out | LATENCY= lat_str | Sc= score_str | AA= aa_str | AXFR= axfr_out
    print(f"  {conn}SERVER={DIM} {RESET}{server_str} | SOA SERIAL={serial_out} | LATENCY={lat_str} | Sc={score_str} | AA={aa_str} | AXFR={axfr_clr}{axfr_out}{RESET}")

    dnssec = res.get("dnssec")
    dnssec_str = f"{OK}SIGNED{RESET}" if dnssec is True else (f"{FAIL}UNSIGNED{RESET}" if dnssec is False else "N/E")
    caa_count = len(res.get("caa_records", []))
    caa_str = f"{OK}{caa_count}{RESET}" if caa_count > 0 else f"{WARN}0{RESET}"
    ns_consistent_val = res.get("ns_consistent")
    ns_consistent = f"{OK}YES{RESET}" if ns_consistent_val is True else (f"{FAIL}NO{RESET}" if ns_consistent_val is False else "N/E")
    
    scope = res.get("check_scope", "FULL")
    scope_clr = OK if scope == "FULL" else (FAIL if scope == "ERROR" else WARN)
    
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
    """Print zone audit as a boxed block for visual clarity."""
    sec_str = f"{OK}SIGNED{RESET}" if audit.get("dnssec") else f"{WARN}UNSIGNED{RESET}"
    t_ok = audit.get("timers_ok", True)
    tim_str = f"{OK}RFC-OK{RESET}" if t_ok else f"{FAIL}NON-COMPLIANT{RESET}"
    m_reach = audit.get("mname_reachable")
    m_str = ""
    if m_reach:
        upper_reach = str(m_reach).upper()
        m_clr = OK if "(UP)" in upper_reach else (FAIL if "(DOWN)" in upper_reach else WARN)
        m_str = f" MNAME:{m_clr}{m_reach}{RESET}"
    w_risk = audit.get("web_risk", False)
    web_str = f"{FAIL}EXPOSED!{RESET}" if w_risk else f"{OK}SAFE{RESET}"
    glue_ok = audit.get("glue_ok")
    glue_str = f"{OK}OK{RESET}" if glue_ok else (f"{FAIL}FAIL{RESET}" if glue_ok is False else f"{WARN}N/E{RESET}")

    print(f"     ┌─ {BOLD}ZONE AUDIT: {domain}{RESET} ──────────────────────────────────────")
    print(f"     │ DNSSEC: {sec_str}  Timers: {tim_str}{m_str}")
    print(f"     │ Glue: {glue_str}  Web-Risk: {web_str}")
    if not t_ok and audit.get("timers_issues"):
        for issue in audit["timers_issues"]:
            print(f"     │ {WARN}⚠ {issue}{RESET}")
    if audit.get("axfr_exposed"):
        print(f"     │ {FAIL}⚠ AXFR VULNERABLE — zone transfer accepted{RESET}")
    print(f"     └─────────────────────────────────────────────────────────")

def print_warning(msg):
    print(f"  {WARN}{msg}{RESET}")

def print_phase_footer(name, metrics, duration: float = 0.0, insights=None):
    width = 80
    print(f"  ── PHASE {name.upper()} SUMMARY {'─' * (width - len(name) - 20)}")
    
    rows = _format_metrics(list(metrics.items()), width=3)
    for r in rows:
        print(f"  {r}")

    if insights:
        print(f"  ── ANALYTICAL SIGNALS {'─' * (width - 24)}")
        for k, v in insights.items():
            # Determine icon based on key
            icon = f"{INFO}[i]{RESET}"
            if any(x in k.upper() for x in ["HEALTH", "COMPLIANCE", "STABILITY"]): icon = f"{OK}[H]{RESET}"
            if any(x in k.upper() for x in ["EXPOSURE", "RISK", "VULN"]): icon = f"{FAIL}[×]{RESET}"
            if any(x in k.upper() for x in ["FALLBACK", "LATENCY"]): icon = f"{WARN}[!]{RESET}"
            print(f"  {icon} {BOLD}{k:22}{RESET}: {v}")

    if duration > 0.0:
        print(f"  Done in {duration:.2f}s")
    print(f"  {'─' * width}")

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
    consistency_str = f" [{FAIL}DIV!{RESET}]" if not is_consistent else f"[{OK}OK{RESET}]"
    
    server_str = _ellipsize(server, 15)
    
    # Tree Connector
    conn = _get_tree_connector(level, is_last)
    
    # Layout: SERVER= server_str | TYPE= rtype | STATUS= status_str | LATENCY= lat_str | Sync= consistency_str
    return f"  {conn}SERVER={DIM} {RESET}{server_str} | TYPE={INFO}{rtype}{RESET} | STATUS={status_clr}{status_str}{RESET} | LATENCY={lat_str} | Sync={consistency_str}"

def print_record_findings(findings):
    """Print semantic findings/warnings as a boxed block for visual clarity."""
    if not findings:
        return
        
    print(f"       ┌─ {BOLD}FINDINGS{RESET} ─────────────────────────────────────────────┐")
    for finding in findings:
        if any(w in finding.upper() for w in ["INVAL!", "MISSING", "REQUIRED", "DANGLING"]):
            clr = FAIL
        elif any(w in finding.upper() for w in ["PERMISSIVE", "INSECURE", "HIGH", "MONITORING"]):
            clr = WARN
        else:
            clr = INFO
        # Truncate long findings to fit box
        display = finding if len(finding) <= 55 else finding[:52] + "..."
        print(f"       │ {clr}⚠ {display}{RESET}")
    print(f"       └─────────────────────────────────────────────────────────┘")

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
    if chain <= 1:
        chain_str = f"{OK}Direct{RESET}"
    elif chain <= 3:
        chain_str = f"{WARN}{chain} hops{RESET}"
    else:
        chain_str = f"{FAIL}{chain} hops{RESET}"

    nsid = _ellipsize(record.get("nsid") or "-", 15)
    
    # Indent sub-lines
    tree_indent = "   " * level
    sub_prefix = "  " + tree_indent + "├─ "
    last_sub_prefix = "  " + tree_indent + "└─ "

    print(f"{sub_prefix}Transit: {BOLD}Ping{RESET}={_fmt_latency(record.get('ping_latency'))} | {BOLD}DNS: UDP{RESET}={_fmt_latency(record.get('latency'))} | {BOLD}Amplification{RESET}: {amp_str}")
    print(f"{sub_prefix}Crypto : {BOLD}DoT{RESET}={_fmt_latency(record.get('dot_latency'))} | {BOLD}DoH{RESET}={_fmt_latency(record.get('doh_latency'))}")
    print(f"{sub_prefix}Perf   : {BOLD}Jitter{RESET}={_fmt_latency(record.get('latency_jitter'))} | {BOLD}Avg{RESET}={_fmt_latency(record.get('latency_avg'))} | {BOLD}Chain{RESET}: {chain_str}")
    print(f"{last_sub_prefix}{BOLD}NSID{RESET}: {INFO}{nsid}{RESET} | {BOLD}Answers{RESET}: {INFO}{answers}{RESET}")

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
    """Legend for Phase 1 results table (Infrastructure) — full field reference."""
    _print_boxed_card("PHASE 1 HELP: Infrastructure Check — Field Reference", [
        f"{BOLD}IP ADDRESS{RESET}       : Target resolver or authoritative server IP.",
        f"{BOLD}RELIABILITY{RESET}      : Ping loss visual bar ({OK}●{RESET}=OK, {FAIL}○{RESET}=Lost) + loss %." ,
        f"{BOLD}U53 (ms){RESET}         : UDP port 53 DNS responsiveness and latency.",
        f"{BOLD}T53 (ms){RESET}         : TCP port 53 DNS responsiveness and latency.",
        f"{BOLD}DoT (ms){RESET}         : DNS-over-TLS (TCP/853) encrypted latency.",
        f"{BOLD}DoH (ms){RESET}         : DNS-over-HTTPS (TCP/443) encrypted latency.",
        f"{BOLD}Sc{RESET}               : Infrastructure Score (0-100). Weighted by profile.",
        f"{BOLD}Status{RESET}           : {OK}ALIVE{RESET} = reachable, {FAIL}DEAD{RESET} = unreachable.",
        f"",
        f"{BOLD}Profile{RESET}          : recursive / authoritative / mixed / unknown.",
        f"{BOLD}Resolver{RESET}         : {FAIL}PUBLIC{RESET}=open recursion, {OK}RESTRICTED{RESET}=controlled, {INFO}UNKNOWN{RESET}.",
        f"{BOLD}Confidence{RESET}       : {OK}HIGH{RESET}/{WARN}MEDIUM{RESET}/{FAIL}LOW{RESET} — reliability of the classification.",
        f"{BOLD}Version{RESET}          : DNS software version. {OK}HIDDEN{RESET}=good, {FAIL}revealed{RESET}=leak.",
        f"",
        f"{BOLD}Caps{RESET}             : [S]DNSSEC [E]DNS [K]ookies [Q]name-Min [X]ECS." ,
        f"{BOLD}WebRisk{RESET}          : Open web ports (80/443) on the same host. Context, not DNS flaw.",
        f"{BOLD}DNSSEC Mode{RESET}      : DATA_SERVING / VALIDATING / PARTIAL / UNSIGNED / N/A.",
        f"{BOLD}QNAME-Min{RESET}        : {OK}HIGH{RESET}/{WARN}MEDIUM{RESET}/{FAIL}LOW{RESET} — heuristic query name minimization confidence.",
    ])

def print_legend_phase1_analytics():
    """Legend for Phase 1 analytical summary — full criteria."""
    _print_boxed_card("PHASE 1 ANALYTICS CRITERIA", [
        f"{BOLD}Infra Health{RESET}     : Average infrastructure score across alive servers (100% = full modern security).",
        f"{BOLD}Transport Consist.{RESET}: % of servers where UDP53 and TCP53 both responded consistently.",
        f"{BOLD}Control Plane{RESET}    : % of servers with version hidden and recursion restricted.",
        f"{BOLD}Exposure Posture{RESET} : Ratio of PUBLIC vs RESTRICTED vs UNKNOWN resolvers.",
        f"{BOLD}Observability{RESET}    : % of probes that returned timing data (not N/A or timeout).",
        f"{BOLD}Probe Coverage{RESET}   : % of repeated probe samples that actually measured latency.",
        f"{BOLD}Probe Jitter{RESET}     : Average latency spread (max-min) across repeated probes.",
        f"{BOLD}Adoption{RESET}         : % of servers supporting modern features (EDNS, Cookies, QNAME, ECS).",
        f"{BOLD}Net-Health{RESET}       : Composite latency index combining ping + DNS + encrypted transport.",
    ])

def print_legend_phase2_table():
    """Legend for Phase 2 results table (Zone Integrity) — full field reference."""
    _print_boxed_card("PHASE 2 HELP: Zone Integrity Check — Field Reference", [
        f"{BOLD}SERVER{RESET}           : DNS server that answered the zone query.",
        f"{BOLD}SOA SERIAL{RESET}       : Zone version. {OK}OK(serial){RESET}=synced, {FAIL}FAIL(serial){RESET}=desync.",
        f"{BOLD}LATENCY{RESET}          : SOA query response time (UDP 53).",
        f"{BOLD}Sc{RESET}               : Zone Score (0-100). Sync + authority + AXFR + DNSSEC + CAA.",
        f"{BOLD}AA{RESET}               : Authoritative Answer flag. {OK}YES{RESET}=expected, {FAIL} NO{RESET}=lame delegation.",
        f"{BOLD}AXFR{RESET}             : Zone transfer status. {OK}REFUSED{RESET}=good, {FAIL}XFR-OK{RESET}=exposed.",
        f"",
        f"{BOLD}Audit > Scope{RESET}    : {OK}FULL{RESET}=complete audit, {WARN}SOA_ONLY{RESET}=limited (connectivity issue).",
        f"{BOLD}Audit > DNSSEC{RESET}   : Whether the zone appeared signed from this server.",
        f"{BOLD}Audit > CAA{RESET}      : Number of CAA records (SSL certificate authority policy).",
        f"{BOLD}Audit > NS-Consist.{RESET}: Whether NS answers matched across servers for same zone.",
        f"",
        f"{BOLD}Timers{RESET}           : SOA timers (Refresh/Retry/Expire/MinTTL). {INFO}Cyan{RESET}=RFC-ok, {WARN}Yellow{RESET}=out of range.",
        f"{BOLD}Timers > RFC-OK{RESET}  : All timers within RFC 1912 recommended ranges.",
        f"{BOLD}Timers > RFC-FAIL{RESET}: At least one timer outside RFC range (policy risk).",
        f"",
        f"{BOLD}Transit{RESET}          : Ping, SOA UDP, NS UDP latencies for this zone/server pair.",
        f"{BOLD}Evidence{RESET}         : Detailed DNS probe metadata (protocol, rcode, flags, amplification, aa, ra).",
    ])

def print_legend_phase2_analytics():
    """Legend for Phase 2 analytical summary — full criteria."""
    _print_boxed_card("PHASE 2 ANALYTICS CRITERIA", [
        f"{BOLD}Zone Compliance{RESET}  : % of zone checks with all audit flags passing (DNSSEC, timers, NS, CAA).",
        f"{BOLD}Sync Health{RESET}      : % of zones where serial matched across all tested servers.",
        f"{BOLD}Authority Integrity{RESET}: % of zones with AA flag present when expected.",
        f"{BOLD}Transfer Exposure{RESET} : % of zones where AXFR was refused (100% = fully secure).",
        f"{BOLD}Zone Hygiene{RESET}     : Combined metric: DNSSEC + CAA + timer compliance.",
        f"{BOLD}CAA Adoption{RESET}     : % of zones with at least one CAA record (RFC 8659).",
        f"{BOLD}Zone Response Health{RESET}: % health based on average zone latency vs SOA latency threshold.",
        f"{BOLD}Fallback Dependency{RESET}: % of zones that required SOA fallback query (primary failed).",
        f"{BOLD}Scope Confidence{RESET}  : % of zones with FULL scope (SOA_ONLY limits audit depth).",
        f"{BOLD}Zone Stability{RESET}   : % of SOA/NS repeated probes that returned consistent serial.",
    ])

def print_legend_phase3_table():
    """Legend for Phase 3 results table (Record Consistency) — full field reference."""
    _print_boxed_card("PHASE 3 HELP: Record Consistency Check — Field Reference", [
        f"{BOLD}SERVER{RESET}           : DNS server that answered the query.",
        f"{BOLD}TYPE{RESET}             : Record type queried (A, AAAA, MX, TXT, SOA, CNAME, NS, etc.).",
        f"{BOLD}STATUS{RESET}           : DNS response code. {OK}NOERROR{RESET}=success, {WARN}NXDOMAIN{RESET}=not found, {FAIL}FAIL{RESET}=error.",
        f"{BOLD}LATENCY{RESET}          : Response time for the representative query.",
        f"{BOLD}Sync{RESET}             : Repeated query consistency. {OK}[OK]{RESET}=matched, {WARN}[DIV!]{RESET}=diverged.",
        f"",
        f"{BOLD}Ping{RESET}             : Phase 1 ping status reused as transport context.",
        f"{BOLD}Recursion{RESET}        : Phase 1 recursion status reused as context.",
        f"{BOLD}DoT / DoH{RESET}        : Phase 1 encrypted DNS capability markers.",
        f"{BOLD}NSID{RESET}             : Name Server ID (EDNS option). Identifies the server instance.",
        f"{BOLD}Wildcard{RESET}         : Whether random subdomains resolved (zone-level wildcard).",
        f"",
        f"{BOLD}Answers{RESET}          : Truncated preview of the DNS response records.",
        f"{BOLD}AD Flag{RESET}          : DNSSEC Authenticated Data bit. {OK}AD+{RESET}=validated chain.",
        f"{BOLD}Amplification{RESET}    : Response/Query byte ratio. {FAIL}>10x{RESET} = potential amplification risk.",
        f"{BOLD}Timings{RESET}          : First/Avg/Min/Max latency across repeated queries.",
        f"{BOLD}Jitter{RESET}           : Latency spread (max-min). High = unstable network or load balancing.",
        f"{BOLD}Chain Depth{RESET}      : Number of hops to resolve. {OK}Direct{RESET}=1 hop, {WARN}/{FAIL}=indirect.",
        f"{BOLD}Chain/MX25/Wildcard{RESET}: Supplementary latencies: chain resolution, MX port 25, wildcard probe.",
    ])

def print_legend_phase3_analytics():
    """Legend for Phase 3 analytical summary — full criteria."""
    _print_boxed_card("PHASE 3 ANALYTICS CRITERIA", [
        f"{BOLD}Stability Index{RESET}  : % of repeated queries that returned identical answers.",
        f"{BOLD}Finding Density{RESET}  : Average number of semantic findings per query result.",
        f"{BOLD}Record Response Health{RESET}: % health based on average record latency vs threshold.",
        f"{BOLD}Network Jitter{RESET}   : Average latency spread (max-min) across all repeated probes.",
    ])

def print_legend_summary():
    """Legend for Final Audit Summary — full scoring explanation."""
    _print_boxed_card("FINAL DASHBOARD LEGEND & SCORING CRITERIA", [
        f"{BOLD}SECURITY SCORE{RESET} (0-100): Weighted combination of:",
        f"  DNSSEC data serving (15%), CAA presence (10%), AXFR blocked (15%),",
        f"  Cookies (10%), EDNS support (10%), Resolver restricted (15%),",
        f"  Web ports closed (10%), QNAME-Min (10%), Version hidden (5%).",
        f"",
        f"{BOLD}PRIVACY SCORE{RESET} (0-100): Weighted combination of:",
        f"  DoT support (30%), DoH support (30%), QNAME-Min HIGH (20%),",
        f"  ECS disabled (20%). Only applies when recursive servers are evaluated.",
        f"",
        f"{BOLD}GLOBAL GRADE{RESET}: Derived from available scores.",
        f"  {OK}A+ (95+){RESET} | {OK}A (90+){RESET} | {OK}B (80+){RESET} | {WARN}C (70+){RESET} | {WARN}D (60+){RESET} | {FAIL}F (<60){RESET}.",
        f"  When privacy does not apply, grade becomes security-only.",
        f"",
        f"{BOLD}SCORING BREAKDOWN{RESET}: Line-by-line contribution of each component.",
        f"  {OK}✔{RESET} = positive contribution, {FAIL}✘{RESET} = negative, {INFO}•{RESET} = neutral/informational.",
    ])

def print_legend_advanced_analytics():
    """Legend for Advanced Analytics section."""
    _print_boxed_card("ADVANCED ANALYTICS LEGEND & CRITERIA", [
        f"{BOLD}SERVER HEALTH INDEX{RESET} (0-100): Consolidated per-server score.",
        f"  50% Infrastructure Score + 30% Zone Avg + 20% Record Consistency %.",
        f"  Issues tagged: PUBLIC_RESOLVER, PING_FAIL, AXFR_EXPOSED, ZONE_DESYNC, RECORD_DIV.",
        f"",
        f"{BOLD}WORST/BEST SERVERS{RESET}: Top-5 lowest and highest health index.",
        f"  Dead servers (score=0) are listed separately below the rankings.",
        f"",
        f"{BOLD}CROSS-PHASE CORRELATIONS{RESET}: Servers flagged in 2+ phases simultaneously.",
        f"  {FAIL}DEGRADED{RESET} = 4+ flags across phases (critical pattern).",
        f"  {WARN}STRESSED{RESET}  = 2-3 flags across phases (needs attention).",
        f"  Infra flags: exposed, ping_fail, udp_fail, tcp_fail.",
        f"  Zone flags: axfr_exposed, desync, lame.",
        f"  Record flags: div:N, findings:N, wildcard:N.",
        f"",
        f"{BOLD}PROBLEM RANKING{RESET}: All problems ranked by severity (10=critical, 1=info).",
        f"  {FAIL}[10]{RESET} PUBLIC_RESOLVER | {FAIL}[9]{RESET} AXFR_EXPOSED | {FAIL}[7]{RESET} ZONE_DESYNC",
        f"  {WARN}[6]{RESET} RECORD_DIV | {WARN}[5]{RESET} WILDCARD/FINDINGS | {INFO}[3]{RESET} LAME_DELEGATION",
        f"",
        f"{BOLD}COVERAGE RELIABILITY{RESET}: % of checks that actually measured data.",
        f"  Low coverage = results may not reflect real server behavior.",
        f"  Phase 1: per-probe measurement rate. Phase 2: FULL vs SOA_ONLY ratio.",
        f"  Phase 3: successful query rate and latency measurement rate.",
    ])


def print_advanced_analytics(advanced):
    """Print the consolidated advanced analytics with visual bars and structured cards."""
    width = 80

    # Worst & Best Servers with visual progress bars
    wb = advanced.get("worst_best_servers", {})
    worst = wb.get("worst", [])
    best = wb.get("best", [])
    if worst or best:
        print(f"\n  {BOLD}SERVER HEALTH RANKINGS{RESET}")
        print(f"  {'─' * width}")

        if worst:
            print(f"  {FAIL}WORST SERVERS{RESET}")
            for i, s in enumerate(worst):
                bar_len = 12
                filled = int((s['total'] / 100) * bar_len) if s['total'] > 0 else 0
                bar = f"{'█' * filled}{'░' * (bar_len - filled)}"
                score_clr = get_score_color(s['total'])
                issues = ", ".join(s.get("issues", [])) or "Healthy"
                print(f"    #{i+1} {s['server']:15} {bar} {score_clr}{s['total']:3d}{RESET}  {issues}")

        if best:
            print(f"\n  {OK}BEST SERVERS{RESET}")
            for i, s in enumerate(best):
                bar_len = 12
                filled = int((s['total'] / 100) * bar_len) if s['total'] > 0 else 0
                bar = f"{'█' * filled}{'░' * (bar_len - filled)}"
                score_clr = get_score_color(s['total'])
                issues = ", ".join(s.get("issues", [])) or "Healthy"
                print(f"    #{i+1} {s['server']:15} {bar} {score_clr}{s['total']:3d}{RESET}  {issues}")

        dead = wb.get("dead_count", 0)
        if dead:
            print(f"\n  {FAIL}⚠ {dead} dead server(s) scored 0{RESET}")

    # Cross-Phase Correlations with structured cards
    cross = advanced.get("cross_phase_correlations", [])
    if cross:
        print(f"\n  {BOLD}CROSS-PHASE CORRELATIONS{RESET}")
        print(f"  {'─' * width}")
        for c in cross[:8]:
            pattern_clr = FAIL if c['pattern'] == "degraded" else WARN
            p_label = c['pattern'].upper()
            flags = (
                [f"infra:{f}" for f in c['infra']] +
                [f"zone:{f}" for f in c['zones']] +
                [f"rec:{f}" for f in c['records']]
            )
            print(f"  ┌─ {c['server']:15} {pattern_clr}{p_label:8}{RESET} {'─' * 40}")
            # Print flags in rows of ~5
            for j in range(0, len(flags), 5):
                chunk = flags[j:j+5]
                print(f"  │ [{'] ['.join(chunk)}]")
            print(f"  └{'─' * 58}")

    # Problem Ranking with severity badges
    problems = advanced.get("problem_ranking", [])
    if problems:
        print(f"\n  {BOLD}TOP PROBLEMS BY SEVERITY{RESET}")
        print(f"  {'─' * width}")
        for p in problems[:12]:
            sev_clr = FAIL if p['severity'] >= 7 else (WARN if p['severity'] >= 5 else INFO)
            sev_badge = f"{sev_clr}[{p['severity']:2d}]{RESET}"
            cat_clr = FAIL if p['severity'] >= 7 else (WARN if p['severity'] >= 5 else INFO)
            print(f"  {sev_badge} {cat_clr}{p['category']:8}{RESET} {p['subject']:35} {p['detail']}")

    # Coverage Reliability with visual bars
    cov = advanced.get("coverage_reliability", {})
    if cov:
        print(f"\n  {BOLD}COVERAGE RELIABILITY{RESET}")
        print(f"  {'─' * width}")
        for phase_key, phase_label in [("phase1", "Phase 1"), ("phase2", "Phase 2"), ("phase3", "Phase 3")]:
            phase_data = cov.get(phase_key, {})
            if not phase_data:
                continue
            for k, v in phase_data.items():
                if phase_key == "phase1" and k == "sample_size":
                    continue
                # Extract percentage from string like "5/5 (100%)"
                pct_str = ""
                if isinstance(v, str) and "%" in v:
                    try:
                        pct = int(v.split("(")[1].split("%")[0])
                        bar_len = 8
                        filled = int((pct / 100) * bar_len)
                        pct_clr = OK if pct >= 80 else (WARN if pct >= 50 else FAIL)
                        pct_str = f" {'█' * filled}{'░' * (bar_len - filled)} {pct_clr}{pct}%{RESET}"
                    except (IndexError, ValueError):
                        pass
                print(f"    {phase_label} {k:15}: {v}{pct_str}")
