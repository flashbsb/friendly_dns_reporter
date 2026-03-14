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
    print(f"{BOLD}FRIENDLY DNS REPORTER - PYTHON EDITION {version}{RESET}")
    print("=" * 80)

def print_header(threads, consistency, target):
    print(f"Threads: {threads} | Consistency: {consistency}x | Dataset: {target}")
    print("-" * 80)

def print_phase(name):
    print(f"\n{BOLD}{INFO}>>> PHASE {name}{RESET}")

def print_phase_header(name):
    if "1" in name:
        print(f"  {'IP Address':15} | {'Group':11} | {'PING (R/S % ms)':16} | {'53 UDP':11} | {'53 TCP':11} | {'DNSSEC':11} | {'EDNS0':11} | {'DoT (853)':11} | {'DoH (443)':11} | {'OpenRes':9} | Status")
        print("-" * 140)
    elif "2" in name:
        print(f"  {'Domain':25} -> {'Server':15} | {'Group':11} | {'SOA Serial':18} | {'Lat':7} | {'AA':4} | AXFR Status")
        print("-" * 114)
    elif "3" in name:
        print(f"  {'Group':10} | {'Target':30} -> {'Server':15} | {'Type':5} | {'Status':12}")
        print("-" * 105)

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
    print("-" * 80)
    print(f"  Reports Generated:")
    for label, path in reports.items():
        print(f"  {INFO}{label:5}:{RESET} {path}")
    print("=" * 80 + "\n")

def print_interrupt():
    print("\n\n" + "!" * 80)
    print(f" {FAIL}INTERRUPTED: User cancellation requested.{RESET}")
    print(" Terminating pending threads... please wait.")
    print("!" * 80 + "\n")

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
        
        # Color Logic
        if loss_pct >= loss_crit or lat >= lat_crit:
            ping_clr = CRIT
        elif loss_pct >= loss_warn or lat >= lat_warn:
            ping_clr = WARN
        else:
            ping_clr = OK
            
        # String Formatting
        if ping_count >= 3:
            lost_pkts = int(ping_count * ping_loss)
            recv_pkts = ping_count - lost_pkts
            ping_str = f"{recv_pkts}/{ping_count} {loss_pct}% {lat:.0f}ms"
        else:
            ping_str = f"OK ({lat:.0f}ms)"
    else:
        ping_clr = FAIL
        ping_str = "FAIL"
        
    p53t_clr = OK if data['port53'] == "OPEN" else FAIL
    p53t_str = f"OK ({data['port53_lat']:.0f}ms)" if data['port53'] == "OPEN" else "FAIL"
    
    udp_ok = data['version'] not in ["TIMEOUT", "UNREACHABLE", "DISABLED"] or data['recursion'] not in ["TIMEOUT", "UNREACHABLE", "DISABLED"]
    p53u_clr = OK if udp_ok else FAIL
    udp_lat = data['recursion_lat'] if data['recursion'] not in ["TIMEOUT", "DISABLED"] else data['version_lat']
    p53u_str = f"OK ({udp_lat:.0f}ms)" if udp_ok else "TIMEOUT"
    
    dot_clr = OK if data.get('dot') == "YES" else (FAIL if data.get('dot') == "NO" else WARN)
    dot_str = f"OK ({data.get('dot_lat', 0):.0f}ms)" if data.get('dot') == "YES" else data.get('dot', '--')
    
    doh_clr = OK if data.get('doh') == "YES" else (FAIL if data.get('doh') == "NO" else WARN)
    doh_str = f"OK ({data.get('doh_lat', 0):.0f}ms)" if data.get('doh') == "YES" else data.get('doh', '--')
    
    edns_clr = OK if data.get('edns0') == "OK" else FAIL
    edns_str = f"OK ({data.get('edns0_lat', 0):.0f}ms)" if data.get('edns0') == "OK" else data.get('edns0', '--')
    
    dsec_clr = OK if data.get('dnssec') == "OK" else FAIL
    dsec_str = f"OK ({data.get('dnssec_lat', 0):.0f}ms)" if data.get('dnssec') == "OK" else data.get('dnssec', '--')
    
    openres = data.get('open_resolver', 'SAFE')
    
    if openres == "OPEN":
        openres_clr = FAIL
    elif openres == "TIMEOUT":
        openres_clr = WARN
    else:
        openres_clr = OK
        
    openres_str = f"{openres} ({data.get('open_resolver_lat', 0):.0f}ms)" if openres in ["OPEN", "REFUSED", "SERVFAIL", "NOERROR"] else openres
    
    alive_str = f"{OK}ALIVE{RESET}" if not data['is_dead'] else f"{FAIL}DEAD{RESET}"
    
    group_str = data.get('groups', '')
    if len(group_str) > 11:
        group_str = group_str[:8] + "..."
        
    print(f"  {srv:15} | {INFO}{group_str:11}{RESET} | {ping_clr}{ping_str:16}{RESET} | {p53u_clr}{p53u_str:11}{RESET} | {p53t_clr}{p53t_str:11}{RESET} | {dsec_clr}{dsec_str:11}{RESET} | {edns_clr}{edns_str:11}{RESET} | {dot_clr}{dot_str:11}{RESET} | {doh_clr}{doh_str:11}{RESET} | {openres_clr}{openres_str:9}{RESET} | {alive_str}")

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
    else:
        serial_str = f"{FAIL}{serial:12}{RESET}"
        
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

    print(f"  {domain:25} -> {srv:15} | {INFO}{group_str:11}{RESET} | {serial_str:18} | {lat_str} | {aa_str} | {axfr_clr}{axfr_str:18}{RESET}")

def print_warning(msg):
    print(f"  {WARN}{msg}{RESET}")

def print_phase_footer(name, metrics, duration: float = 0.0):
    print(f"  {BOLD}--- Phase {name} Summary ---{RESET}")
    for k, v in metrics.items():
        print(f"  {k:20}: {v}")
    if duration > 0.0:
        print(f"  {'Execution Time':20}: {duration:.2f}s")
    print("-" * 40)

def format_result(group, target, server, rtype, status, latency, is_consistent):
    if status == "NOERROR" or status == "NXDOMAIN":
        status_clr = OK
    elif "TIMEOUT" in status or "UNREACHABLE" in status:
        status_clr = WARN
    else:
        status_clr = FAIL
        
    consistency_str = f" [{WARN}DIV!{RESET}]" if not is_consistent else ""
    return f"  [{INFO}REC{RESET}] {group:10} | {target:25} -> {server:15} | {rtype:5} | {status_clr}{status:12}{RESET} | {latency:4.1f}ms{consistency_str}"

def print_progress(current, total, prefix="", length=30):
    """Prints a carriage-return progress bar."""
    percent = (current / total) * 100
    filled = int(length * current // total)
    bar = "█" * filled + "-" * (length - filled)
    print(f"\r  {INFO}{prefix}{RESET} |{bar}| {percent:3.0f}% ({current}/{total})", end="", flush=True)
    if current == total: print() # New line when done
