"""
UI and Terminal Formatting for FriendlyDNSReporter.
"""

# ANSI Palette
RESET = "\033[0m"
OK     = "\033[92m"  # Green
FAIL   = "\033[91m"  # Red
WARN   = "\033[93m"  # Yellow
INFO   = "\033[96m"  # Cyan
CRIT   = "\033[95m"  # Magenta
BOLD   = "\033[1m"
UNDER  = "\033[4m"

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

def print_banner(version=""):
    print("\n" + "=" * 80)
    print(f"{BOLD}FRIENDLY DNS REPORTER v6.5.0{RESET}")
    print("=" * 80)

def print_header(threads, consistency, target):
    print(f"Threads: {threads} | Consistency: {consistency}x | Dataset: {target}")
    print("-" * 80)

def print_phase(name):
    print(f"\n{BOLD}{INFO}>>> PHASE {name}{RESET}")

def print_phase_header(name):
    if "1" in name:
        print(f"  {INFO}{'GROUP':11}{RESET} | {INFO}{'IP ADDRESS':15}{RESET} | {'PING (R/S % ms)':16} | {'U53':10} | {'T53':10} | {'DoT':5} | {'DoH':5} | {'Sc':3} | {'CAPS (S E K Q X)':15} | {'OpenRes':9} | Status")
        print("-" * 145)
    elif "2" in name:
        print(f"  {'Domain':30} | {'Group':11} | {'Server':15} | {'SOA Serial':18} | {'Lat':7} | {'Sc':3} | {'AA':4} | AXFR Status")
        print("-" * 120)
    elif "3" in name:
        print(f"  {'Domain':30} | {'Group':11} | {'Server':15} | {'Type':5} | {'Status':12} | {'Lat':7} | Sync")
        print("-" * 115)

def print_summary_table(total, success, fail, div, sync_issues, reports, duration: float = 0.0, sec_score=0, priv_score=0, show_legend=True):
    print("\n" + "=" * 80)
    print(f"{BOLD}FINAL DIAGNOSTIC SUMMARY{RESET}")
    print("=" * 80)
    print(f"  Total Record Queries : {total}")
    print(f"  Successful (OK)      : {OK}{success}{RESET}")
    print(f"  Failures (ERR)       : {(FAIL if fail > 0 else OK)}{fail}{RESET}")
    print(f"  Divergences (DIV)    : {(WARN if div > 0 else OK)}{div}{RESET}")
    print(f"  Sync/Zone Issues     : {(FAIL if sync_issues > 0 else OK)}{sync_issues}{RESET}")
    
    # Advanced Scores
    def _score_clr(s):
        if s >= 90: return OK
        if s >= 70: return WARN
        return FAIL

    print(f"  {BOLD}SECURITY SCORE      : {_score_clr(sec_score)}{sec_score}/100{RESET}")
    print(f"  {BOLD}PRIVACY SCORE       : {_score_clr(priv_score)}{priv_score}/100{RESET}")
    
    avg_score = (sec_score + priv_score) / 2
    print(f"  {BOLD}GLOBAL HEALTH GRADE : {format_grade(avg_score)} ({avg_score:.1f}%){RESET}")
    
    print(f"  Total Execution Time : {duration:.2f}s")
    
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
        return OK, f"OK({lat:.0f}ms)"
    # Port is open but service failed/timeout
    return WARN, f"P_ONLY({lat:.0f}ms)"

def print_infra_detail(srv, data):
    ping_loss = data.get('packet_loss', 0.0)
    ping_count = data.get('ping_count', 0)
    
    lat_warn = data.get('ping_latency_warn', 100)
    lat_crit = data.get('ping_latency_crit', 250)
    loss_warn = data.get('ping_loss_warn', 15)
    loss_crit = data.get('ping_loss_crit', 50)
    
    if data['ping'] == "OK":
        loss_pct = int(ping_loss * 100)
        lat = data['latency']
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
    p53u_clr, p53u_str = _fmt_port_serv(data.get('port53u', 'OPEN'), data.get('port53u_serv', 'FAIL'), data.get('recursion_lat', 0))
    # Note: Using port53t_serv and port53t_lat for consistency
    p53t_clr, p53t_str = _fmt_port_serv(data.get('port53t', 'CLOSED'), data.get('port53t_serv', 'FAIL'), data.get('port53t_lat', 0))
    dot_clr, dot_str = _fmt_port_serv(data.get('port853', 'CLOSED'), data.get('port853_serv', 'FAIL'), data.get('dot_lat', 0))
    doh_clr, doh_str = _fmt_port_serv(data.get('port443', 'CLOSED'), data.get('port443_serv', 'FAIL'), data.get('doh_lat', 0))
    
    # Privacy/Security Capabilities (S=SEC, E=EDNS, C=Cookies, Q=QNAME-Min, X=ECS)
    def _cap(key, char):
        val = data.get(key)
        # Handle both True/False and "OK"/"FAIL" strings
        if val in [True, "OK"]: return f"{OK}{char}{RESET}"
        return f"{FAIL}-{RESET}"
    
    caps = f"{_cap('dnssec', 'S')} {_cap('edns0', 'E')} {_cap('cookies', 'K')} {_cap('qname_min', 'Q')} {_cap('ecs', 'X')}"

    openres = data.get('open_resolver', 'SAFE')
    if openres == "OPEN": openres_clr = FAIL
    elif openres == "TIMEOUT": openres_clr = WARN
    else: openres_clr = OK
    openres_str = f"{openres} ({data.get('open_resolver_lat', 0):.0f}ms)" if openres in ["OPEN", "REFUSED", "SERVFAIL", "NOERROR"] else openres
    
    alive_str = f"{OK}ALIVE{RESET}" if not data['is_dead'] else f"{FAIL}DEAD{RESET}"
    group_str = data.get('groups', '')
    if len(group_str) > 11: group_str = group_str[:8] + "..."
    
    # Granular Score
    score = data.get('infrastructure_score', 0)
    score_clr = get_score_color(score)
    score_str = f"{score_clr}{score:3d}{RESET}"

    # Layout: Group | Server | Ping | U53 | T53 | DoT | DoH | Sc | Caps | OpenRes | Status
    print(f"  {INFO}{group_str:11}{RESET} | {srv:15} | {ping_clr}{ping_str:16}{RESET} | {p53u_clr}{p53u_str:10}{RESET} | {p53t_clr}{p53t_str:10}{RESET} | {dot_clr}{dot_str:5.5}{RESET} | {doh_clr}{doh_str:5.5}{RESET} | {score_str} | {caps} | {openres_clr}{openres_str:9}{RESET} | {alive_str}")

def print_zone_detail(srv, domain, res):
    serial = res.get('serial', '?')
    status = res.get('status', 'ERROR')
    axfr_ok = res.get('axfr_vulnerable', False)
    aa = res.get('aa', False)
    lat = res.get('latency', 0)
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
    
    if lat >= lat_crit:
        lat_clr = FAIL
    elif lat >= lat_warn:
        lat_clr = WARN
    else:
        lat_clr = OK
        
    lat_str = f"{lat_clr}{lat:4.0f}ms{RESET}" if status == "NOERROR" else " --  "
    
    group_str = res.get('group', 'UNCATEGORIZED')
    if len(group_str) > 11:
        group_str = group_str[:8] + "..."

    # Granular Score
    score = res.get('zone_score', 0)
    score_clr = get_score_color(score)
    score_str = f"{score_clr}{score:3d}{RESET}"

    print(f"  {domain:30} | {INFO}{group_str:11}{RESET} | {srv:15} | {serial_str:18} | {lat_str} | {score_str} | {aa_str} | {axfr_clr}{axfr_str:18}{RESET}")

def print_zone_audit_block(domain, audit):
    """Print a concise summary of advanced zone diagnostics."""
    print(f"  {INFO}>> 🔍 [ZONE AUDIT: {domain}]{RESET}")
    
    # DNSSEC
    sec_str = f"{OK}SIGNED{RESET}" if audit.get("dnssec") else f"{WARN}UNSIGNED{RESET}"
    
    # Timers
    t_ok = audit.get("timers_ok", True)
    tim_str = f"{OK}RFC-OK{RESET}" if t_ok else f"{FAIL}NON-COMPLIANT{RESET}"
    
    # MNAME (Optional)
    m_reach = audit.get("mname_reachable")
    m_str = ""
    if m_reach:
        m_clr = OK if m_reach == "UP" else (FAIL if m_reach == "DOWN" else WARN)
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
    print(f"  {BOLD}{UNDER}--- Phase {name} - Analytical Insights ---{RESET}")
    for k, v in metrics.items():
        print(f"  {k:20}: {v}")
    
    if insights:
        print(f"  {BOLD}Analytics:{RESET}")
        for k, v in insights.items():
            print(f"  ↳ {k:18}: {v}")
            
    if duration > 0.0:
        print(f"  {'Execution Time':20}: {duration:.2f}s")
    print("-" * 50)

def format_result(target, group, server, rtype, status, latency, is_consistent, warn_ms=150, crit_ms=500):
    if status == "NOERROR" or status == "NXDOMAIN":
        status_clr = OK
    elif "TIMEOUT" in status or "UNREACHABLE" in status:
        status_clr = WARN
    else:
        status_clr = FAIL
        
    lat_clr = OK
    if latency >= crit_ms:
        lat_clr = FAIL
    elif latency >= warn_ms:
        lat_clr = WARN
        
    consistency_str = f" [{WARN}DIV!{RESET}]" if not is_consistent else f"{OK}OK{RESET}"
    return f"  [{INFO}REC{RESET}] {target:30} | {INFO}{group:11}{RESET} | {server:15} | {rtype:5} | {status_clr}{status:12}{RESET} | {lat_clr}{latency:4.1f}ms{RESET} | {consistency_str}"

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
            
        print(f"       {clr}↳ ! {finding}{RESET}")

def print_progress(current, total, prefix="", length=30):
    """Prints a carriage-return progress bar."""
    percent = (current / total) * 100
    filled = int(length * current // total)
    bar = "█" * filled + "-" * (length - filled)
    print(f"\r  {INFO}{prefix}{RESET} |{bar}| {percent:3.0f}% ({current}/{total})", end="", flush=True)
    if current == total: print() # New line when done

def print_legend_phase1_table():
    """Legend for Phase 1 results table (Infrastructure)."""
    print(f"\n  {BOLD}PHASE 1: TECHNICAL COLUMN LEGEND{RESET}")
    print(f"  - {BOLD}PING [R/S % ms]{RESET} : [Received/Sent Packets] [Loss %] [Latency in ms].")
    print(f"  - {BOLD}U53 / T53{RESET}       : Standard DNS Port 53 Availability (UDP / TCP).")
    print(f"  - {BOLD}DoT / DoH{RESET}       : Encrypted DNS Support (DNS-over-TLS Port 853 / DNS-over-HTTPS Port 443).")
    print(f"  - {BOLD}PROBE STATUSES{RESET}   : {OK}OK(ms){RESET} = Service Up | {WARN}P_ONLY{RESET} = Port Open but Service Failed | {FAIL}CLOSE{RESET} = Port Closed.")
    print(f"  - {BOLD}Sc{RESET}               : Individual Infra Score (0-100) based on Weights (Ping 20%, Probes 40%, Security 40%).")
    print(f"  - {BOLD}Caps (S E K Q X){RESET}: {OK}S{RESET}EC (DNSSEC), {OK}E{RESET}DNS, {OK}K{RESET}ookies, {OK}Q{RESET}name-Min, {OK}X{RESET}=ClientSubnet.")
    print(f"  - {BOLD}OpenRes{RESET}          : Recursion safety ({OK}SAFE{RESET}, {FAIL}OPEN{RESET}=Vulnerable to DDoS Amplification).")
    print("-" * 145)

def print_legend_phase1_analytics():
    """Legend for Phase 1 analytical summary."""
    print(f"  {BOLD}PHASE 1: ANALYTICS CRITERIA{RESET}")
    print(f"  - {BOLD}Infra Health{RESET} : Average health score across infrastructure. 100% = All services up with modern security.")
    print(f"  - {BOLD}Adoption{RESET}     : Percentage of servers deployed with DoH, DoT, DNSSEC and Cookies.")
    print(f"  - {BOLD}Net-Health{RESET}   : Network SLA index (Latency vs Warn/Crit limits configured in settings.ini).")
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
    print(f"  - {BOLD}Sync Health{RESET}    : Global consistency rate. 100% = All server serials match for all zones.")
    print(f"  - {BOLD}CAA Adoption{RESET}   : Certificate Authority Authorization usage to prevent SSL hijacking.")
    print("-" * 50)

def print_legend_phase3_table():
    """Legend for Phase 3 results table (Record Consistency)."""
    print(f"\n  {BOLD}PHASE 3: TECHNICAL COLUMN LEGEND{RESET}")
    print(f"  - {BOLD}Status{RESET}      : {OK}NOERROR{RESET} (Success), {WARN}NXDOMAIN{RESET} (No exist), {FAIL}SERVFAIL/REFUSED/TIMEOUT{RESET}.")
    print(f"  - {BOLD}Sync{RESET}        : Stability marker. {OK}OK{RESET} = Consistent results | {WARN}DIV!{RESET} = Flapping/Divergent records.")
    print(f"  - {BOLD}↳ ! [Issue]{RESET} : Forensic findings like Dangling DNS, TTL logic errors, SPF/DMARC syntax.")
    print("-" * 115)

def print_legend_phase3_analytics():
    """Legend for Phase 3 analytical summary."""
    print(f"  {BOLD}PHASE 3: ANALYTICS CRITERIA{RESET}")
    print(f"  - {BOLD}Stability Index{RESET}: Percentage of queries that returned identical results across sequential checks.")
    print(f"  - {BOLD}Finding Density{RESET}: Average volume of semantic issues detected per record query.")
    print("-" * 50)

def print_legend_summary():
    """Legend for Final Audit Summary."""
    print(f"  {BOLD}SUMMARY LEGEND & SCORING CRITERIA:{RESET}")
    print(f"  {INFO}SECURITY SCORE (0-100):{RESET}")
    print(f"  - {BOLD}DNSSEC/CAA{RESET}   : Validates trust chain (DS/RRSIG) and SSL issuance policies.")
    print(f"  - {BOLD}DNS Cookies{RESET}  : RFC 7873 resistance against IP spoofing and amplification.")
    print(f"  - {BOLD}AXFR Block{RESET}   : Evaluation of zone transfer security (RFC 5936).")
    print(f"  - {BOLD}OpenResolver{RESET} : Detection of recursive infrastructure exposed to the public internet.")
    print(f"  {INFO}PRIVACY SCORE (0-100):{RESET}")
    print(f"  - {BOLD}DoT/DoH{RESET}      : DNS encryption (TLS/HTTPS) to prevent ISP/MITM snooping.")
    print(f"  - {BOLD}QNAME-Min{RESET}    : RFC 7816 reduction in query data leakage to upstream servers.")
    print(f"  - {BOLD}ECS Masking{RESET}  : RFC 7871 client privacy protection (Subnet masking).")
    print(f"  {INFO}GRADING SYSTEM:{RESET}")
    print(f"  - {OK}A+ / A (90+){RESET}   : Professional compliance | {WARN}C / D (60-80){RESET} : Warnings | {FAIL}F (<60){RESET} : Critical Risks.")
