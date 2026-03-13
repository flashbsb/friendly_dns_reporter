"""
UI and Terminal Formatting for FriendlyDNSReporter.
"""

# ANSI Palette
RESET = "\033[0m"
OK     = "\033[92m"  # Green
FAIL   = "\033[91m"  # Red
WARN   = "\033[93m"  # Yellow
INFO   = "\033[96m"  # Cyan
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
    if "1" in name:
        print(f"  {'IP Address':15} | {'Ping':4} | {'53-TCP':6} | {'53-UDP':6} | {'443-TCP':7} | {'Recursion':9} | Status")
    elif "2" in name:
        print(f"  {'Domain':25} -> {'Server':15} | {'Serial':10} | AXFR Status")
    elif "3" in name:
        print(f"  {'Group':10} | {'Target':30} -> {'Server':15} | {'Type':5} | {'Status':12}")
    print("-" * 88)

def print_summary_table(total, success, fail, div, sync_issues, reports):
    print("\n" + "=" * 80)
    print(f"{BOLD}FINAL DIAGNOSTIC SUMMARY{RESET}")
    print("=" * 80)
    print(f"  Total Record Queries : {total}")
    print(f"  Successful (OK)      : {OK}{success}{RESET}")
    print(f"  Failures (ERR)       : {(FAIL if fail > 0 else OK)}{fail}{RESET}")
    print(f"  Divergences (DIV)    : {(WARN if div > 0 else OK)}{div}{RESET}")
    print(f"  Sync/Zone Issues     : {(FAIL if sync_issues > 0 else OK)}{sync_issues}{RESET}")
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
    ping_clr = OK if data['ping'] == "OK" else FAIL
    p53t_clr = OK if data['port53'] == "OPEN" else FAIL
    # UDP works if either recursion or version didn't timeout
    udp_ok = data['recursion'] not in ["TIMEOUT", "UNREACHABLE"] or data['version'] not in ["TIMEOUT", "UNREACHABLE"]
    p53u_clr = OK if udp_ok else FAIL
    p443_clr = OK if data['port443'] == "OPEN" else FAIL
    rec_clr = OK if data['recursion'] == "OPEN" else (WARN if data['recursion'] == "TIMEOUT" else FAIL)
    alive_str = f"{OK}ALIVE{RESET}" if not data['is_dead'] else f"{FAIL}DEAD{RESET}"
    
    udp_status = "OK" if udp_ok else "TIMEOU"
    
    print(f"  {srv:15} | {ping_clr}{data['ping']:4}{RESET} | {p53t_clr}{data['port53']:6}{RESET} | {p53u_clr}{udp_status:6}{RESET} | {p443_clr}{data['port443']:7}{RESET} | {rec_clr}{data['recursion']:9}{RESET} | {alive_str}")

def print_zone_detail(srv, domain, serial, axfr_ok, status):
    sync_clr = OK if serial != "?" and status == "NOERROR" else (WARN if status == "UNREACHABLE" else FAIL)
    axfr_clr = FAIL if axfr_ok else OK
    axfr_str = "VULNERABLE!" if axfr_ok else "SAFE"
    print(f"  {domain:25} -> {srv:15} | {sync_clr}{serial:10}{RESET} | {axfr_clr}{axfr_str}{RESET}")

def print_phase_footer(name, metrics):
    print(f"  {BOLD}--- Phase {name} Summary ---{RESET}")
    for k, v in metrics.items():
        print(f"  {k:20}: {v}")
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
