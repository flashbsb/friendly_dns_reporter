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

def print_banner(version=""):
    print("\n" + "=" * 80)
    print(f"{BOLD}FRIENDLY DNS REPORTER {version}{RESET}")
    print("=" * 80)

def print_header(threads, consistency, target):
    print(f"Threads: {threads} | Consistency: {consistency}x | Dataset: {target}")
    print("-" * 80)

def print_phase(name):
    print(f"\n{BOLD}{INFO}>>> PHASE {name}{RESET}")

def print_phase_header(name):
    if "1" in name:
        print(f"  {INFO}{'GROUP':11}{RESET} | {INFO}{'IP ADDRESS':15}{RESET} | {'PING (R/S % ms)':16} | {'53 UDP':11} | {'53 TCP':11} | {'DNSSEC':11} | {'EDNS0':11} | {'DoT (853)':11} | {'DoH (443)':11} | {'OpenRes':9} | Status")
        print("-" * 140)
    elif "2" in name:
        print(f"  {'Domain':30} | {'Group':11} | {'Server':15} | {'SOA Serial':18} | {'Lat':7} | {'AA':4} | AXFR Status")
        print("-" * 115)
    elif "3" in name:
        print(f"  {'Domain':30} | {'Group':11} | {'Server':15} | {'Type':5} | {'Status':12} | {'Lat':7} | Sync")
        print("-" * 115)

def print_summary_table(total, success, fail, div, sync_issues, reports, duration: float = 0.0):
    print("\n" + "=" * 80)
    print(f"{BOLD}FINAL DIAGNOSTIC SUMMARY{RESET}")
    print("=" * 80)
    print(f"  Total Record Queries : {total}")
    print(f"  Successful (OK)      : {OK}{success}{RESET}")
    print(f"  Failures (ERR)       : {(FAIL if fail > 0 else OK)}{fail}{RESET}")
    print(f"  Divergences (DIV)    : {(WARN if div > 0 else OK)}{div}{RESET}")
    print(f"  Sync/Zone Issues     : {(FAIL if sync_issues > 0 else OK)}{sync_issues}{RESET}")
    print(f"  Total Execution Time : {duration:.2f}s")
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
    
    edns_clr = OK if data.get('edns0') == "OK" else FAIL
    edns_str = f"OK ({data.get('edns0_lat', 0):.0f}ms)" if data.get('edns0') == "OK" else data.get('edns0', '--')
    dsec_clr = OK if data.get('dnssec') == "OK" else FAIL
    dsec_str = f"OK ({data.get('dnssec_lat', 0):.0f}ms)" if data.get('dnssec') == "OK" else data.get('dnssec', '--')
    
    openres = data.get('open_resolver', 'SAFE')
    if openres == "OPEN": openres_clr = FAIL
    elif openres == "TIMEOUT": openres_clr = WARN
    else: openres_clr = OK
    openres_str = f"{openres} ({data.get('open_resolver_lat', 0):.0f}ms)" if openres in ["OPEN", "REFUSED", "SERVFAIL", "NOERROR"] else openres
    
    alive_str = f"{OK}ALIVE{RESET}" if not data['is_dead'] else f"{FAIL}DEAD{RESET}"
    group_str = data.get('groups', '')
    if len(group_str) > 11: group_str = group_str[:8] + "..."
        
    # Layout: Group | Server | Ping | 53U | 53T | SEC | EDNS | DoT | DoH | OpenRes | Status
    print(f"  {INFO}{group_str:11}{RESET} | {srv:15} | {ping_clr}{ping_str:16}{RESET} | {p53u_clr}{p53u_str:11}{RESET} | {p53t_clr}{p53t_str:11}{RESET} | {dsec_clr}{dsec_str:11}{RESET} | {edns_clr}{edns_str:11}{RESET} | {dot_clr}{dot_str:11}{RESET} | {doh_clr}{doh_str:11}{RESET} | {openres_clr}{openres_str:9}{RESET} | {alive_str}")

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

    print(f"  {domain:30} | {INFO}{group_str:11}{RESET} | {srv:15} | {serial_str:18} | {lat_str} | {aa_str} | {axfr_clr}{axfr_str:18}{RESET}")

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

def print_phase_footer(name, metrics, duration: float = 0.0):
    print(f"  {BOLD}--- Phase {name} Summary ---{RESET}")
    for k, v in metrics.items():
        print(f"  {k:20}: {v}")
    if duration > 0.0:
        print(f"  {'Execution Time':20}: {duration:.2f}s")
    print("-" * 40)

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

def print_legend_phase1():
    """Legend for Phase 1: Infrastructure."""
    print(f"\n  {BOLD}PHASE 1 LEGEND (Infrastructure):{RESET}")
    print(f"  {INFO}COLUMNS:{RESET}")
    print(f"  - {BOLD}GROUP{RESET}      : Server profile/category (CORE, GOOGLE, etc.).")
    print(f"  - {BOLD}IP ADDRESS{RESET} : Network address of the DNS server.")
    print(f"  - {BOLD}PING (R/S){RESET} : Packets Received/Sent and Packet Loss (%).")
    print(f"  - {BOLD}53 UDP/TCP{RESET} : Availability of DNS service on standard port 53.")
    print(f"  - {BOLD}DNSSEC/EDNS{RESET}: Support for security extensions and large payloads.")
    print(f"  - {BOLD}DoT/DoH{RESET}    : DNS-over-TLS (853) and DNS-over-HTTPS (443) support.")
    print(f"  - {BOLD}OpenRes{RESET}    : Open Resolver detection (Recursion safety).")
    print(f"  {INFO}VALUES & COLORS:{RESET}")
    print(f"  - {OK}OK (ms){RESET}    : Service reachable and responding (Green < 100ms, Yellow/Magenta Alert).")
    print(f"  - {WARN}P_ONLY{RESET}     : Port is OPEN, but DNS Service is NOT responding.")
    print(f"  - {FAIL}CLOSE/FAIL{RESET} : Port or Service is definitively unreachable.")
    print(f"  - {OK}SAFE{RESET}       : Properly protected (Not an open resolver).")
    print(f"  - {FAIL}OPEN{RESET}       : Vulnerable open resolver (RECURSION ENABLED).")
    print(f"  - {OK}ALIVE{RESET}/{FAIL}DEAD{RESET}: Server's final reachability status.")
    print("-" * 140)

def print_legend_phase2():
    """Legend for Phase 2: Zones."""
    print(f"\n  {BOLD}PHASE 2 LEGEND (Zone Integrity):{RESET}")
    print(f"  {INFO}COLUMNS:{RESET}")
    print(f"  - {BOLD}Domain{RESET}      : The DNS zone being tested.")
    print(f"  - {BOLD}SOA Serial{RESET}  : Zone version ID (must be identical across all servers).")
    print(f"  - {BOLD}Lat{RESET}         : Response time for the SOA query.")
    print(f"  - {BOLD}AA{RESET}          : Authoritative Answer flag (Expected for Zone Masters/Slaves).")
    print(f"  - {BOLD}AXFR Status{RESET} : Zone Transfer vulnerability assessment.")
    print(f"  {INFO}VALUES & COLORS:{RESET}")
    print(f"  - {OK}OK(serial){RESET}  : Zone is synchronized and healthy.")
    print(f"  - {FAIL}FAIL(serial){RESET}: Desynchronized zone (Delayed propagation or outdated serial).")
    print(f"  - {OK}YES{RESET}/{FAIL}NO{RESET}       : AA Flag (YES is healthy, NO indicates Lame Delegation).")
    print(f"  - {OK}REFUSED{RESET}     : Secure (AXFR properly blocked).")
    print(f"  - {FAIL}XFR-OK{RESET}     : VULNERABILITY (Zone transfer allowed on non-secondary server).")
    print(f"  {INFO}ZONE AUDIT DETAILS:{RESET}")
    print(f"  - {BOLD}DNSSEC{RESET}      : Zone signing status ({OK}SIGNED{RESET} or {WARN}UNSIGNED{RESET}).")
    print(f"  - {BOLD}TIMERS{RESET}      : SOA Timer compliance ({OK}RFC-OK{RESET} or {FAIL}NON-COMPLIANT{RESET} with RFC 1912).")
    print(f"  - {BOLD}MNAME{RESET}       : Primary Master Server reachability ({OK}UP{RESET}, {FAIL}DOWN{RESET}, or {WARN}UNKNOWN{RESET}).")
    print(f"  - {BOLD}WEB-RISK{RESET}    : Checks if HTTP/HTTPS ports (80/443) are exposed on the DNS server ({OK}SAFE{RESET} or {FAIL}EXPOSED!{RESET}).")
    print("-" * 115)

def print_legend_phase3():
    """Legend for Phase 3: Records."""
    print(f"\n  {BOLD}PHASE 3 LEGEND (Record Consistency):{RESET}")
    print(f"  {INFO}COLUMNS:{RESET}")
    print(f"  - {BOLD}Type{RESET}        : Record type (A, AAAA, MX, TXT, etc.).")
    print(f"  - {BOLD}Status{RESET}      : Query result (NOERROR, NXDOMAIN, TIMEOUT, etc.).")
    print(f"  - {BOLD}Sync{RESET}        : Result stability across multiple sequential queries.")
    print(f"  {INFO}VALUES & COLORS:{RESET}")
    print(f"  - {OK}OK{RESET}           : Success (NOERROR) or intentional Negative Response.")
    print(f"  - {FAIL}FAIL/ERROR{RESET}  : Protocol failure or service timeout.")
    print(f"  - {OK}OK{RESET} (Sync)    : Stable result (All repeated queries returned identical data).")
    print(f"  - {WARN}DIV!{RESET} (Sync)   : Divergence (Sequential queries returned different data - Flapping).")
    print(f"  - {FAIL}↳ ! [Issue]{RESET} : Semantic findings (Dangling DNS, low TTL, SPF errors).")
    print("-" * 115)
