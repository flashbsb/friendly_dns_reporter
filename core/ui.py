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
OK     = _ansi("\033[92m")  # Green
FAIL   = _ansi("\033[91m")  # Red
WARN   = _ansi("\033[93m")  # Yellow
INFO   = _ansi("\033[96m")  # Cyan
CRIT   = _ansi("\033[95m")  # Magenta
BOLD   = _ansi("\033[1m")
UNDER  = _ansi("\033[4m")

_PROGRESS_LAST = {}
_PROGRESS_LINE_LEN = {}

def strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", str(text))

def _status_tag(level):
    mapping = {
        "OK": f"{OK}[OK]{RESET}",
        "WARN": f"{WARN}[WARN]{RESET}",
        "CRIT": f"{FAIL}[CRIT]{RESET}",
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

def _fmt_latency(value, precision=0, na="N/A"):
    if value is None:
        return na
    try:
        return f"{float(value):.{precision}f}ms"
    except (TypeError, ValueError):
        return na

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
    print(f"\n  {BOLD}{title}{RESET}")
    print(f"  {'-' * len(title)}")
    for line in _format_metrics(items):
        print(f"  {line}")
    if interpretation:
        print(f"  Interpretation: {interpretation}")
    print("")

def print_phase_header(name):
    if "1" in name:
        print(f"  {INFO}{'GROUP':11}{RESET} | {INFO}{'IP ADDRESS':15}{RESET} | {'PING':16} | {'U53':10} | {'T53':10} | {'DoT':5} | {'DoH':5} | {'Sc':3} | {'CAPS':15} | {'Resolver':12} | Status")
        print("-" * 137)
    elif "2" in name:
        print(f"  {'Domain':28} | {'Group':11} | {'Server':15} | {'SOA Serial':16} | {'Lat':7} | {'Sc':3} | {'AA':4} | {'AXFR':12}")
        print("-" * 114)
    elif "3" in name:
        print(f"  {'Domain':28} | {'Group':11} | {'Server':15} | {'Type':5} | {'Status':12} | {'Lat':7} | Sync")
        print("-" * 113)

def print_summary_table(total, success, fail, div, sync_issues, reports, duration: float = 0.0, sec_score=0, priv_score=0, show_legend=True, scores_available=False, security_available=False, privacy_available=False, show_security=True, show_privacy=True, takeaways=None):
    print("\n" + "=" * 80)
    print(f"{BOLD}FINAL DIAGNOSTIC SUMMARY{RESET}")
    print("=" * 80)
    for line in _format_metrics([
        ("Total Record Queries", total),
        ("Successful", f"{OK}{success}{RESET}"),
        ("Failures", f"{(FAIL if fail > 0 else OK)}{fail}{RESET}"),
        ("Divergences", f"{(WARN if div > 0 else OK)}{div}{RESET}"),
        ("Zone Issues", f"{(FAIL if sync_issues > 0 else OK)}{sync_issues}{RESET}")
    ], width=2):
        print(f"  {line}")
    
    # Advanced Scores
    def _score_clr(s):
        if s >= 90: return OK
        if s >= 70: return WARN
        return FAIL

    if security_available:
        print(f"  {BOLD}SECURITY SCORE      : {_score_clr(sec_score)}{sec_score}/100{RESET}")
    elif show_security: # Only show 'N/A' if we actually WANT to see security scores
        print(f"  {BOLD}SECURITY SCORE      : {WARN}N/A{RESET}")

    if privacy_available:
        print(f"  {BOLD}PRIVACY SCORE       : {_score_clr(priv_score)}{priv_score}/100{RESET}")
    elif show_privacy: # Only show 'N/A' if we actually WANT to see privacy scores
        print(f"  {BOLD}PRIVACY SCORE       : {WARN}N/A (no recursive-profile servers){RESET}")

    if show_security or show_privacy:
        if scores_available:
            avg_score = (sec_score + priv_score) / 2
            print(f"  {BOLD}GLOBAL HEALTH GRADE : {format_grade(avg_score)} ({avg_score:.1f}%){RESET}")
        else:
            if security_available:
                print(f"  {BOLD}GLOBAL HEALTH GRADE : {format_grade(sec_score)} ({sec_score:.1f}% security-only){RESET}")
            else:
                print(f"  {BOLD}GLOBAL HEALTH GRADE : {WARN}N/A (requires Phase 1 data){RESET}")
    
    print(f"  {BOLD}TOTAL EXECUTION TIME: {duration:.2f}s{RESET}")

    if takeaways:
        print("-" * 80)
        print(f"  {BOLD}EXECUTIVE TAKEAWAYS{RESET}")
        for item in takeaways:
            print(f"  - {item}")
    
    if show_legend:
        print("-" * 80)
        print_legend_summary()

    if reports:
        print("-" * 80)
        print(f"  Reports Generated:")
        for label, path in reports.items():
            print(f"  {INFO}{label:5}:{RESET} {path}")
            
    print("-" * 80)
    print(f"  {INFO}Check for updates & Contribute:{RESET}")
    print(f"  https://github.com/flashbsb/friendly_dns_reporter")
    print("=" * 80)
    print("=" * 80 + "\n")

def print_interrupt():
    print("\n\n" + "!" * 80)
    print(f" {FAIL}INTERRUPTED: User cancellation requested.{RESET}")
    print(" Terminating pending threads... please wait.")
    print("!" * 80 + "\n")

def _fmt_port_serv(port_status, serv_status, lat):
    """Deep Service notation: OK (Service up), P_ONLY (Port only), CLOSE (Closed)."""
    if port_status == "CLOSED" or port_status == "FAIL":
        return FAIL, "CLOSE"
    if serv_status == "OK":
        return OK, f"OK({_fmt_latency(lat, 0)})" if lat is not None else "OK(N/A)"
    # Port is open but service failed/timeout
    return WARN, f"P_ONLY({_fmt_latency(lat, 0)})" if lat is not None else "P_ONLY(N/A)"

def print_infra_detail(srv, data):
    ping_loss = data.get('packet_loss', 0.0)
    ping_count = data.get('ping_count', 0)
    
    lat_warn = data.get('ping_latency_warn', 100)
    lat_crit = data.get('ping_latency_crit', 250)
    loss_warn = data.get('ping_loss_warn', 15)
    loss_crit = data.get('ping_loss_crit', 50)
    
    if data['ping'] == "OK":
        loss_pct = int(ping_loss * 100)
        lat = data.get('latency') or 0
        if loss_pct >= loss_crit or lat >= lat_crit: ping_clr = CRIT
        elif loss_pct >= loss_warn or lat >= lat_warn: ping_clr = WARN
        else: ping_clr = OK
        
        if ping_count >= 3:
            lost_pkts = int(ping_count * ping_loss)
            recv_pkts = ping_count - lost_pkts
            ping_str = f"{recv_pkts}/{ping_count} {loss_pct}% {lat:.0f}ms"
        else:
            ping_str = f"OK ({lat:.0f}ms)"
    else:
        ping_clr = FAIL
        ping_str = "FAIL"
        
    # Deep Probes
    p53u_clr, p53u_str = _fmt_port_serv(data.get('port53u', 'OPEN'), data.get('port53u_serv', 'FAIL'), data.get('recursion_lat'))
    # Note: Using port53t_serv and port53t_lat for consistency
    p53t_clr, p53t_str = _fmt_port_serv(data.get('port53t', 'CLOSED'), data.get('port53t_serv', 'FAIL'), data.get('port53t_lat'))
    dot_clr, dot_str = _fmt_port_serv(data.get('port853', 'CLOSED'), data.get('port853_serv', 'FAIL'), data.get('dot_lat'))
    doh_clr, doh_str = _fmt_port_serv(data.get('port443', 'CLOSED'), data.get('port443_serv', 'FAIL'), data.get('doh_lat'))
    
    # Privacy/Security Capabilities (S=SEC, E=EDNS, C=Cookies, Q=QNAME-Min, X=ECS)
    def _cap(key, char):
        val = data.get(key)
        # Handle both True/False and "OK"/"FAIL" strings
        if val in [True, "OK"]: return f"{OK}{char}{RESET}"
        return f"{FAIL}-{RESET}"
    
    caps = f"{_cap('dnssec', 'S')} {_cap('edns0', 'E')} {_cap('cookies', 'K')} {_cap('qname_min', 'Q')} {_cap('ecs', 'X')}"

    openres = data.get('open_resolver', 'UNKNOWN')
    if openres == "OPEN":
        openres_clr = FAIL
    elif openres in ["TIMEOUT", "SERVFAIL", "ERROR"]:
        openres_clr = WARN
    else:
        openres_clr = OK
    openres_str = openres
    if openres in ["OPEN", "REFUSED", "SERVFAIL", "NO_RECURSION"]:
        openres_lat = _fmt_latency(data.get('open_resolver_lat'), 0)
        openres_str = f"{openres}/{openres_lat}"
    openres_str = _ellipsize(openres_str, 12)
    
    alive_str = f"{OK}ALIVE{RESET}" if not data['is_dead'] else f"{FAIL}DEAD{RESET}"
    group_str = data.get('groups', '')
    if len(group_str) > 11: group_str = group_str[:8] + "..."
    
    # Granular Score
    score = data.get('infrastructure_score', 0)
    score_clr = get_score_color(score)
    score_str = f"{score_clr}{score:3d}{RESET}"

    # Layout: Group | Server | Ping | U53 | T53 | DoT | DoH | Sc | Caps | OpenRes | Status
    print(f"  {INFO}{group_str:11}{RESET} | {srv:15} | {ping_clr}{_ellipsize(ping_str, 16):16}{RESET} | {p53u_clr}{p53u_str:10}{RESET} | {p53t_clr}{p53t_str:10}{RESET} | {dot_clr}{dot_str:5.5}{RESET} | {doh_clr}{doh_str:5.5}{RESET} | {score_str} | {caps} | {openres_clr}{openres_str:12}{RESET} | {alive_str}")

    profile = data.get("server_profile", "unknown")
    resolver_class = data.get("classification", "UNKNOWN")
    resolver_conf = data.get("confidence", "NONE")
    version = data.get("version", "N/A")
    web_risks = data.get("web_risks", [])
    web_risk_str = ",".join(str(p) for p in web_risks) if web_risks else "none"
    print(
        f"      Profile={profile} | Resolver={resolver_class}/{resolver_conf} | "
        f"Version={version} | DNSSEC={data.get('dnssec_mode', 'DATA_SERVING')} | "
        f"QNAME-Min={data.get('qname_min_confidence', 'NONE')} | WebRisk={web_risk_str} | "
        f"Coverage={data.get('probe_coverage_ratio', 'N/A')}%"
    )
    print(
        "      Timings: "
        f"Ping={_fmt_latency(data.get('latency'))} [{_fmt_latency(data.get('latency_min'))}..{_fmt_latency(data.get('latency_max'))}] | "
        f"UDP53={_fmt_latency(data.get('udp53_probe_lat'))} | "
        f"TCP53(conn/probe)={_fmt_latency(data.get('port53t_conn_lat'))}/{_fmt_latency(data.get('port53t_probe_lat'))} | "
        f"Version={_fmt_latency(data.get('version_lat'))} | Recursion={_fmt_latency(data.get('recursion_lat'))} | "
        f"DoT(conn/probe)={_fmt_latency(data.get('port853_conn_lat'))}/{_fmt_latency(data.get('dot_lat'))} | "
        f"DoH(conn/probe)={_fmt_latency(data.get('port443_conn_lat'))}/{_fmt_latency(data.get('doh_lat'))} | "
        f"DNSSEC={_fmt_latency(data.get('dnssec_lat'))} | EDNS0={_fmt_latency(data.get('edns0_lat'))} | "
        f"ECS={_fmt_latency(data.get('ecs_lat'))} | QNAME={_fmt_latency(data.get('qname_min_lat'))} | "
        f"Cookies={_fmt_latency(data.get('cookies_lat'))} | WebRisk={_fmt_latency(data.get('web_risk_lat'))} | "
        f"OpenRes={_fmt_latency(data.get('open_resolver_lat'))}"
    )
    print(
        "      Observability: "
        f"UDP53={data.get('udp53_probe_timing_source', '-')}:{data.get('udp53_probe_failure_reason', '-')} | "
        f"TCP53={data.get('tcp53_probe_timing_source', '-')}:{data.get('tcp53_probe_failure_reason', '-')} | "
        f"ECS={data.get('ecs_timing_source', '-')}:{data.get('ecs_failure_reason', '-')} | "
        f"QNAME={data.get('qname_min_timing_source', '-')}:{data.get('qname_min_failure_reason', '-')} | "
        f"Cookies={data.get('cookies_timing_source', '-')}:{data.get('cookies_failure_reason', '-')} | "
        f"Web80={data.get('web_risk_status', {}).get(80, '-')} Web443={data.get('web_risk_status', {}).get(443, '-')}"
    )
    print(
        "      Evidence: "
        f"{_fmt_probe_evidence(data, 'version', 'Version')} | "
        f"{_fmt_probe_evidence(data, 'recursion', 'Recursion')} | "
        f"{_fmt_probe_evidence(data, 'dnssec', 'DNSSEC')} | "
        f"{_fmt_probe_evidence(data, 'edns0', 'EDNS0')} | "
        f"{_fmt_probe_evidence(data, 'open_resolver', 'OpenRes')} | "
        f"{_fmt_probe_evidence(data, 'doh_probe', 'DoH')}"
    )
    print(
        "      Repeatability: "
        f"{_fmt_probe_repeat(data, 'udp53_probe', 'UDP53')} | "
        f"{_fmt_probe_repeat(data, 'tcp53_probe', 'TCP53')} | "
        f"{_fmt_probe_repeat(data, 'dot_probe', 'DoT')} | "
        f"{_fmt_probe_repeat(data, 'doh_probe', 'DoH')} | "
        f"{_fmt_probe_repeat(data, 'open_resolver', 'OpenRes')}"
    )

def print_zone_detail(srv, domain, res):
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
        serial_str = f"{FAIL}{status:12}{RESET}"
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
    lat_warn = res.get('soa_latency_warn', 500)
    lat_crit = res.get('soa_latency_crit', 1500)
    
    lat_eval = lat or 0
    if lat_eval >= lat_crit:
        lat_clr = FAIL
    elif lat_eval >= lat_warn:
        lat_clr = WARN
    else:
        lat_clr = OK
        
    lat_str = f"{lat_clr}{lat_eval:4.0f}ms{RESET}" if lat is not None else " N/A "
    
    group_str = res.get('group', 'UNCATEGORIZED')
    if len(group_str) > 11:
        group_str = group_str[:8] + "..."

    # Granular Score
    score = res.get('zone_score', 0)
    score_clr = get_score_color(score)
    score_str = f"{score_clr}{score:3d}{RESET}"

    domain_str = _ellipsize(domain, 28)
    server_str = _ellipsize(srv, 15)
    serial_out = serial_str if status == "NOERROR" else f"{FAIL}{_compact_status(status, 16):16}{RESET}"
    axfr_out = _ellipsize(axfr_str, 12)
    print(f"  {domain_str:28} | {INFO}{group_str:11}{RESET} | {server_str:15} | {serial_out:16} | {lat_str} | {score_str} | {aa_str} | {axfr_clr}{axfr_out:12}{RESET}")

    dnssec = res.get("dnssec")
    dnssec_str = "SIGNED" if dnssec is True else ("UNSIGNED" if dnssec is False else "N/E")
    caa_count = len(res.get("caa_records", []))
    ns_consistent_val = res.get("ns_consistent")
    ns_consistent = "YES" if ns_consistent_val is True else ("NO" if ns_consistent_val is False else "N/E")
    scope = res.get("check_scope", "FULL")
    web_risk = ",".join(str(p) for p in res.get("web_risks", [])) or "none"
    print(
        f"      Status={status} | Scope={scope} | DNSSEC={dnssec_str} | "
        f"CAA={caa_count} | NS-Consistent={ns_consistent} | WebRisk={web_risk} | "
        f"Confidence={res.get('scope_confidence', 'N/A')} | Fallback={'YES' if res.get('used_fallback') else 'NO'}"
    )
    print(
        "      Timings: "
        f"SOA={_fmt_latency(res.get('soa_latency'))} | "
        f"SOA-Fallback={_fmt_latency(res.get('soa_fallback_latency'))} | "
        f"NS={_fmt_latency(res.get('ns_latency'))} | "
        f"AXFR={_fmt_latency(res.get('axfr_latency'))} | "
        f"CAA={_fmt_latency(res.get('caa_latency'))} | "
        f"Zone-DNSSEC={_fmt_latency(res.get('zone_dnssec_latency'))}"
    )
    print(
        "      Evidence: "
        f"{_fmt_probe_evidence(res, 'soa', 'SOA')} | "
        f"{_fmt_probe_evidence(res, 'ns', 'NS')} | "
        f"{_fmt_probe_evidence(res, 'caa', 'CAA')} | "
        f"{_fmt_probe_evidence(res, 'zone_dnssec', 'ZoneDNSSEC')}"
    )
    print(
        "      Repeatability: "
        f"{_fmt_probe_repeat(res, 'soa', 'SOA')} | "
        f"{_fmt_probe_repeat(res, 'ns', 'NS')}"
    )

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
    print(f"\n  {BOLD}{UNDER}Phase {name} Summary{RESET}")
    for line in _format_metrics(list(metrics.items()), width=2):
        print(f"  {line}")

    if insights:
        print(f"  {BOLD}Interpretation{RESET}")
        for k, v in insights.items():
            print(f"  - {k}: {v}")

    if duration > 0.0:
        print(f"  Execution Time: {duration:.2f}s")
    print("  " + "-" * 60)

def format_result(target, group, server, rtype, status, latency, is_consistent, warn_ms=150, crit_ms=500):
    if status == "NOERROR" or status == "NXDOMAIN":
        status_clr = OK
    elif "TIMEOUT" in status or "UNREACHABLE" in status:
        status_clr = WARN
    else:
        status_clr = FAIL
        
    lat_clr = OK
    latency_eval = latency or 0
    if latency_eval >= crit_ms:
        lat_clr = FAIL
    elif latency_eval >= warn_ms:
        lat_clr = WARN
        
    consistency_str = f" [{WARN}DIV!{RESET}]" if not is_consistent else f"{OK}OK{RESET}"
    target_str = _ellipsize(target, 28)
    group_str = _ellipsize(group, 11)
    server_str = _ellipsize(server, 15)
    status_str = _compact_status(status, 12)
    latency_str = f"{lat_clr}{latency_eval:4.1f}ms{RESET}" if latency is not None else " N/A "
    return f"  [{INFO}REC{RESET}] {target_str:28} | {INFO}{group_str:11}{RESET} | {server_str:15} | {rtype:5} | {status_clr}{status_str:12}{RESET} | {latency_str} | {consistency_str}"

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

def print_record_context(record):
    """Print a concise second line with query context and answer preview."""
    answers = str(record.get("answers", ""))
    if len(answers) > 110:
        answers = answers[:107] + "..."

    nsid = record.get("nsid") or "-"
    nsid = _ellipsize(nsid, 24)
    print(
        "       "
        f"Ping={record.get('ping', 'N/A')} | Port53={record.get('port53', 'N/A')} | "
        f"Rec={record.get('recursion', 'N/A')} | DoT={record.get('dot', 'N/A')} | "
        f"DoH={record.get('doh', 'N/A')} | Query={_fmt_latency(record.get('latency'), 1)} | "
        f"First/Avg={_fmt_latency(record.get('latency_first'), 1)}/{_fmt_latency(record.get('latency_avg'), 1)} | "
        f"Min/Max={_fmt_latency(record.get('latency_min'), 1)}/{_fmt_latency(record.get('latency_max'), 1)} | "
        f"Chain={_fmt_latency(record.get('chain_latency'), 1)} | MX25={_fmt_latency(record.get('mx_port25_latency'), 1)} | "
        f"Wildcard={_fmt_latency(record.get('wildcard_latency'), 1)} | NSID={nsid} | Answers={answers}"
    )

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
    print(f"\n  {BOLD}PHASE 1: TECHNICAL COLUMN LEGEND{RESET}")
    print(f"  - {BOLD}PING [R/S % ms]{RESET} : [Received/Sent Packets] [Loss %] [Latency in ms].")
    print(f"  - {BOLD}U53 / T53{RESET}       : Standard DNS Port 53 Availability (UDP / TCP).")
    print(f"  - {BOLD}DoT / DoH{RESET}       : Encrypted DNS Support (DNS-over-TLS Port 853 / DNS-over-HTTPS Port 443).")
    print(f"  - {BOLD}PROBE STATUSES{RESET}   : {OK}OK(ms){RESET} = Service Up | {WARN}P_ONLY{RESET} = Port Open but Service Failed | {FAIL}CLOSE{RESET} = Port Closed.")
    print(f"  - {BOLD}Sc{RESET}               : Individual infra score derived from observed security/privacy signals and server role.")
    print(f"  - {BOLD}Caps (S E K Q X){RESET}: {OK}S{RESET}=DNSSEC data serving, {OK}E{RESET}=EDNS, {OK}K{RESET}=Cookies, {OK}Q{RESET}=QNAME-Min heuristic, {OK}X{RESET}=ECS seen.")
    print(f"  - {BOLD}OpenRes{RESET}          : Public recursion exposure test ({FAIL}OPEN{RESET}=public recursion seen, {OK}NO_RECURSION/REFUSED{RESET}=restricted).")
    print("-" * 145)

def print_legend_phase1_analytics():
    """Legend for Phase 1 analytical summary."""
    print(f"  {BOLD}PHASE 1: ANALYTICS CRITERIA{RESET}")
    print(f"  - {BOLD}Infra Health{RESET} : Average health score across infrastructure. 100% = All services up with modern security.")
    print(f"  - {BOLD}Adoption{RESET}     : Percentage of servers deployed with DoH, DoT, DNSSEC and Cookies.")
    print(f"  - {BOLD}Net-Health{RESET}   : Composite latency index based on all successful probe timings, not ping alone.")
    print("-" * 50)

def print_legend_phase2_table():
    """Legend for Phase 2 results table (Zone Integrity)."""
    print(f"\n  {BOLD}PHASE 2: TECHNICAL COLUMN LEGEND{RESET}")
    print(f"  - {BOLD}SOA Serial{RESET}  : Zone Version ID. {OK}OK{RESET} = Servers in Sync | {FAIL}FAIL{RESET} = Desynchronized (Desync).")
    print(f"  - {BOLD}Sc{RESET}          : Zone Compliance Score (0-100) based on Weights (Sync 30%, AA 20%, AXFR 30%, CAA 20%).")
    print(f"  - {BOLD}AA{RESET}          : Authoritative Answer flag. {OK}YES{RESET} = Correct | {FAIL}NO{RESET} = Lame Delegation detected.")
    print(f"  - {BOLD}AXFR Status{RESET} : {OK}REFUSED{RESET} = Secure | {FAIL}XFR-OK{RESET} = Vulnerable to data leakage.")
    print("-" * 120)

def print_legend_phase2_analytics():
    """Legend for Phase 2 analytical summary."""
    print(f"  {BOLD}PHASE 2: ANALYTICS CRITERIA{RESET}")
    print(f"  - {BOLD}Zone Compliance{RESET}: Overall adherence score to zone security and synchronization standards.")
    print(f"  - {BOLD}Sync Health{RESET}    : Percentage of tested domains whose authoritative servers shared the same SOA serial.")
    print(f"  - {BOLD}CAA Adoption{RESET}   : Certificate Authority Authorization usage to prevent SSL hijacking.")
    print(f"  - {BOLD}Zone Resp-Health{RESET}: Composite latency index across successful SOA, NS, AXFR, CAA and zone-DNSSEC probes.")
    print("-" * 50)

def print_legend_phase3_table():
    """Legend for Phase 3 results table (Record Consistency)."""
    print(f"\n  {BOLD}PHASE 3: TECHNICAL COLUMN LEGEND{RESET}")
    print(f"  - {BOLD}Status{RESET}      : {OK}NOERROR{RESET} (Success), {WARN}NXDOMAIN{RESET} (No exist), {FAIL}SERVFAIL/REFUSED/TIMEOUT{RESET}.")
    print(f"  - {BOLD}Sync{RESET}        : Stability marker. {OK}OK{RESET} = Consistent results | {WARN}DIV!{RESET} = Flapping/Divergent records.")
    print(f"  - {BOLD}-> ! [Issue]{RESET} : Forensic findings like Dangling DNS plus heuristic TTL/SPF/DMARC checks.")
    print("-" * 115)

def print_legend_phase3_analytics():
    """Legend for Phase 3 analytical summary."""
    print(f"  {BOLD}PHASE 3: ANALYTICS CRITERIA{RESET}")
    print(f"  - {BOLD}Stability Index{RESET}: Percentage of queries that returned identical results across sequential checks.")
    print(f"  - {BOLD}Finding Density{RESET}: Average volume of semantic issues detected per record query.")
    print(f"  - {BOLD}Resp-Health / Jitter{RESET}: Timing quality based on avg response latency and spread across repeated checks.")
    print("-" * 50)

def print_legend_summary():
    """Legend for Final Audit Summary."""
    print(f"  {BOLD}SUMMARY LEGEND & SCORING CRITERIA:{RESET}")
    print(f"  {INFO}SECURITY SCORE (0-100):{RESET}")
    print(f"  - {BOLD}DNSSEC/CAA{RESET}   : Checks DNSSEC data serving and SSL issuance policies; this is not full resolver validation testing.")
    print(f"  - {BOLD}DNS Cookies{RESET}  : RFC 7873 resistance against IP spoofing and amplification.")
    print(f"  - {BOLD}AXFR Block{RESET}   : Evaluation of zone transfer security (RFC 5936).")
    print(f"  - {BOLD}OpenResolver{RESET} : Detection of public recursion exposure using third-party recursion requests.")
    print(f"  {INFO}PRIVACY SCORE (0-100):{RESET}")
    print(f"  - {BOLD}DoT/DoH{RESET}      : DNS encryption (TLS/HTTPS) to prevent ISP/MITM snooping.")
    print(f"  - {BOLD}QNAME-Min{RESET}    : Heuristic RFC 7816 signal for recursive resolvers only.")
    print(f"  - {BOLD}ECS Masking{RESET}  : RFC 7871 client privacy protection (Subnet masking).")
    print(f"  {INFO}GRADING SYSTEM:{RESET}")
    print(f"  - {OK}A+ / A (90+){RESET}   : Professional compliance | {WARN}C / D (60-80){RESET} : Warnings | {FAIL}F (<60){RESET} : Critical Risks.")
