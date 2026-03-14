#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
FRIENDLY DNS REPORTER - PYTHON EDITION
=============================================================================
Version: 2.9.2
Author: flashbsb
Description: 3-Phase Automated DNS diagnostics for Windows and Linux.
=============================================================================
"""

import sys
import os
import subprocess

def _verify_and_install_dependencies():
    """Verify and automatically install required dependencies for Windows and Linux."""
    required_packages = {
        "urllib3": "urllib3",
        "dns": "dnspython",
        "requests": "requests",
        "jinja2": "Jinja2",
        "icmplib": "icmplib"
    }
    
    missing_packages = []
    for module_name, pip_name in required_packages.items():
        try:
            __import__(module_name)
        except ImportError:
            missing_packages.append(pip_name)
            
    if missing_packages:
        print(f"[*] Missing dependencies detected: {', '.join(missing_packages)}")
        print(f"[*] Attempting to install missing dependencies automatically...")
        try:
            # Use sys.executable to ensure pip corresponds to the current python environment
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
            print("[+] Dependencies installed successfully. Resuming execution...\n")
        except subprocess.CalledProcessError as e:
            print(f"[-] Failed to install dependencies automatically. Error: {e}")
            print(f"[-] Please manually run: {sys.executable} -m pip install {' '.join(missing_packages)}")
            sys.exit(1)

_verify_and_install_dependencies()

import argparse
import csv
import concurrent.futures
import threading
import urllib3
import logging
import time
from datetime import datetime

from core.dns_engine import DNSEngine
from core.connectivity import Connectivity
from core.reporting import Reporter
from core.config_loader import Settings
import core.ui as ui

# Silence DoH/DoT HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup Logging
def setup_logging(log_dir):
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, f"friendly_dns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout) # Keep terminal output
        ]
    )
    # Silence third-party logs
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return log_file

def load_datasets(domains_path, groups_path):
    """Load and normalize CSV datasets."""
    def _read_csv(path):
        if not os.path.exists(path): return []
        with open(path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f, delimiter=';')
            reader.fieldnames = [fn.lstrip('#').strip().upper() for fn in reader.fieldnames] if reader.fieldnames else []
            return [{k.lstrip('#').strip().upper(): v for k, v in row.items() if k} for row in reader if any(row.values()) and not any(str(v).startswith('#') for v in row.values())]

    groups = _read_csv(groups_path)
    domains = _read_csv(domains_path)
    return domains, {g['NAME']: g['SERVERS'].split(',') for g in groups if g.get('NAME') and g.get('SERVERS')}

def compare_consistency(queries, settings):
    """Check consistency between multiple query answers based on settings."""
    if not queries: return True
    
    def _get_key(q):
        # Build comparison tuple based on strictness
        ans = q['answers']
        if not settings.strict_order_check:
            ans = sorted(ans)
        
        if not settings.strict_ttl_check:
            # Simple heuristic: remove the first part if it looks like a TTL (digit)
            ans = [" ".join(a.split(" ")[1:]) if a.split(" ")[0].isdigit() else a for a in ans]
            
        return tuple(ans)

    base_key = _get_key(queries[0])
    return all(_get_key(q) == base_key for q in queries[1:])

def run_phase1_infrastructure(servers, srv_groups, conn, dns_engine, settings, lock):
    """Phase 1: Deep Infrastructure Check (Once per server)."""
    phase_start_time = time.time()
    infra_results = {}
    
    def _check_server(srv):
        srv = srv.strip()
        if not srv: return
        
        res = {"server": srv, "is_dead": False, "groups": srv_groups.get(srv, "N/A")}
        
        # 1. Connectivity Probes (Ping)
        ping_res = conn.ping(srv, count=settings.ping_count) if settings.enable_ping else {"is_alive": True}
        res["ping"] = "OK" if ping_res.get("is_alive") else "FAIL"
        res["latency"] = ping_res.get("avg_rtt", 0)
        res["packet_loss"] = ping_res.get("packet_loss", 0.0) # icmplib returns decimal (e.g., 0.33 for 33%)
        res["ping_count"] = settings.ping_count 
        res["ping_latency_warn"] = settings.ping_latency_warn
        res["ping_latency_crit"] = settings.ping_latency_crit
        res["ping_loss_warn"] = settings.ping_loss_warn
        res["ping_loss_crit"] = settings.ping_loss_crit
        
        # Ports (TCP)
        p53_tcp, p53_lat = conn.check_port(srv, 53)
        res["port53"] = "OPEN" if p53_tcp else "CLOSED"
        res["port53_lat"] = p53_lat
        
        p443_tcp, p443_lat = conn.check_port(srv, 443)
        res["port443"] = "OPEN" if p443_tcp else "CLOSED"
        res["port443_lat"] = p443_lat
        
        p853_tcp, p853_lat = conn.check_port(srv, 853)
        res["port853"] = "OPEN" if p853_tcp else "CLOSED"
        res["port853_lat"] = p853_lat
        
        # 2. DNS-Dependent Checks (UDP)
        v, v_lat = dns_engine.query_version(srv) if settings.check_bind_version else ("DISABLED", 0)
        res["version"] = v if v is not None else "TIMEOUT"
        res["version_lat"] = v_lat
        
        r, r_lat = dns_engine.check_recursion(srv) if settings.enable_recursion_check else (False, 0)
        res["recursion"] = "OPEN" if r is True else ("CLOSED" if r is False else "TIMEOUT")
        res["recursion_lat"] = r_lat
        
        # Circuit Breaker Logic: SERVER IS DEAD only if ALL channels fail
        dns_udp_works = res["version"] not in ["TIMEOUT", "UNREACHABLE", "DISABLED"] or \
                        res["recursion"] not in ["TIMEOUT", "UNREACHABLE", "DISABLED"]
        
        if res["ping"] == "FAIL" and not p53_tcp and not dns_udp_works and res["port443"] == "CLOSED":
            res["is_dead"] = True
            res["version"] = "UNREACHABLE"
            res["recursion"] = "UNREACHABLE"
            res["dot"] = "UNREACHABLE"
            res["doh"] = "UNREACHABLE"
            res["dnssec"] = "UNREACHABLE"
            res["edns0"] = "UNREACHABLE"
            res["open_resolver"] = "UNREACHABLE"
        else:
            # Protocols (DoT/DoH)
            dot, dot_lat = dns_engine.check_dot(srv) if settings.enable_dot_check else (False, 0)
            res["dot"] = "YES" if dot is True else ("NO" if dot is False else "TIMEOUT")
            res["dot_lat"] = dot_lat
            
            doh, doh_lat = dns_engine.check_doh(srv) if settings.enable_doh_check else (False, 0)
            res["doh"] = "YES" if doh is True else ("NO" if doh is False else "TIMEOUT")
            res["doh_lat"] = doh_lat
            
            # Advanced Infrastructure Checks
            dnssec, dsec_lat = dns_engine.check_dnssec(srv) if settings.enable_dnssec_check else (False, 0)
            res["dnssec"] = "OK" if dnssec is True else ("FAIL" if dnssec is False else "TIMEOUT")
            res["dnssec_lat"] = dsec_lat
            
            edns0, edns_lat = dns_engine.check_edns0(srv) if settings.enable_edns_check else (False, 0)
            res["edns0"] = "OK" if edns0 is True else ("FAIL" if edns0 is False else "TIMEOUT")
            res["edns0_lat"] = edns_lat
            
            opn_st, opn_lat = dns_engine.check_open_resolver(srv) if settings.enable_recursion_check else ("DISABLED", 0)
            res["open_resolver"] = opn_st
            res["open_resolver_lat"] = opn_lat
        
        res["trace"] = conn.traceroute(srv, max_hops=settings.trace_max_hops) if settings.enable_trace else None
        
        with lock:
            infra_results[srv] = res
            # ui.print_infra_detail(srv, res) # No longer printing-as-we-go
            counters['done'] += 1
            ui.print_progress(counters['done'], total, "Scanning Servers")

    counters = {'done': 0}
    total = len(servers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=settings.max_threads) as executor:
        list(executor.map(_check_server, servers))
        
    # Order results by group then by server IP
    sorted_infra = sorted(infra_results.items(), key=lambda x: (x[1].get('groups', ''), x[0]))
    for srv, res in sorted_infra:
        ui.print_infra_detail(srv, res)
        
    # Phase Summary
    alive = sum(1 for r in infra_results.values() if not r['is_dead'])
    dead = len(infra_results) - alive
    phase_duration = time.time() - phase_start_time
    ui.print_phase_footer("1: Infrastructure", {"Total Servers": len(infra_results), "Status Alive": alive, "Status Dead": dead}, phase_duration)
    
    return infra_results

def run_phase2_zones(domains_raw, dns_groups, dns_engine, settings, infra_cache, lock):
    """Phase 2: Zone Integrity & SOA Synchronization."""
    phase_start_time = time.time()
    zone_results = []
    zones = {}
    for entry in domains_raw:
        domain = entry.get('DOMAIN')
        if not domain: continue
        for group in (entry.get('GROUPS') or '').split(','):
            group = group.strip()
            if group in dns_groups:
                zones.setdefault(domain, set()).update(dns_groups[group])

    def _check_zone(domain, servers):
        results = []
        serials = {}
        for srv in servers:
            infra = infra_cache.get(srv, {})
            if infra.get("is_dead"):
                res = {"domain": domain, "server": srv, "serial": "N/A", "axfr_vulnerable": False, "axfr_detail": "PH1 FAIL", "status": "UNREACHABLE"}
                results.append(res); serials[srv] = "N/A"
                with lock: ui.print_zone_detail(srv, domain, "N/A", False, "UNREACHABLE")
                continue

            soa = dns_engine.query(srv, domain, "SOA")
            serial = soa['answers'][0].split(' ')[2] if soa['status'] == "NOERROR" and soa['answers'] else "?"
            serials[srv] = serial
            axfr_ok, axfr_msg = dns_engine.check_axfr(srv, domain) if settings.enable_axfr_check else (False, "DISABLED")
            
            res = {"domain": domain, "server": srv, "serial": serial, "axfr_vulnerable": axfr_ok, "axfr_detail": axfr_msg, "status": soa['status']}
            results.append(res)
            with lock: ui.print_zone_detail(srv, domain, serial, axfr_ok, soa['status'])
            
        is_synced = len(set(s for s in serials.values() if s != "N/A")) <= 1
        with lock:
            zone_results.extend(results)
            counters['done'] += 1
            ui.print_progress(counters['done'], total, "Checking Zones")

    counters = {'done': 0}
    total = len(zones)
    with concurrent.futures.ThreadPoolExecutor(max_workers=settings.max_threads) as executor:
        futures = [executor.submit(_check_zone, dom, srvs) for dom, srvs in zones.items()]
        concurrent.futures.wait(futures)
        
    # Phase Summary
    vuln = sum(1 for r in zone_results if r['axfr_vulnerable'])
    phase_duration = time.time() - phase_start_time
    ui.print_phase_footer("2: Zone Integrity", {"Total Zones": len(zones), "AXFR Vulnerabilities": vuln}, phase_duration)
        
    return zone_results

def run_phase3_records(tasks, dns_engine, settings, infra_cache, results, lock):
    """Phase 3: Parallel Record Consistency Check."""
    phase_start_time = time.time()
    def _worker(target, group_name, server, record_types):
        # Circuit Breaker
        infra = infra_cache.get(server, {})
        if infra.get("is_dead"):
            local_res = [{
                "domain": target, "group": group_name, "server": server, "type": rtype,
                "status": "UNREACHABLE", "latency": 0, "ping": "FAIL", "port53": "CLOSED",
                "version": "DEAD", "recursion": "DEAD", "dot": "DEAD", "doh": "DEAD",
                "nsid": None, "internally_consistent": "N/A", "answers": "SKIPPED: SERVER DOWN"
            } for rtype in record_types if rtype.strip()]
            with lock:
                results.extend(local_res)
                for r in local_res: print(ui.format_result(group_name, target, server, r['type'], "UNREACHABLE", 0, True))
            return

        local_res = []
        for rtype in record_types:
            rtype = rtype.strip().upper()
            if not rtype: continue
            
            queries = []
            for _ in range(settings.consistency_checks):
                res = dns_engine.query(server, target, rtype, use_edns=settings.enable_edns_check)
                queries.append(res)
                if settings.sleep_time > 0: time.sleep(settings.sleep_time)
                
            is_consistent = compare_consistency(queries, settings)
            main_q = queries[0]
            
            entry = {
                "domain": target, "group": group_name, "server": server, "type": rtype,
                "status": main_q['status'], "latency": main_q['latency'],
                "ping": infra.get("ping", "N/A"), "port53": infra.get("port53", "N/A"),
                "version": infra.get("version", "N/A"), "recursion": infra.get("recursion", "N/A"),
                "dot": infra.get("dot", "N/A"), "doh": infra.get("doh", "N/A"),
                "nsid": main_q.get("nsid"), "internally_consistent": "YES" if is_consistent else "DIV!",
                "answers": ", ".join(main_q['answers'])
            }
            local_res.append(entry)
            with lock:
                print(ui.format_result(group_name, target, server, rtype, main_q['status'], main_q['latency'], is_consistent))
        
        with lock:
            results.extend(local_res)
            counters['done'] += 1
            ui.print_progress(counters['done'], total, "Record Consistency")

    counters = {'done': 0}
    total = len(tasks)
    with concurrent.futures.ThreadPoolExecutor(max_workers=settings.max_threads) as executor:
        futures = [executor.submit(_worker, *t) for t in tasks]
        concurrent.futures.wait(futures)
    
    # Phase Summary
    succ = sum(1 for r in results if r['status'] == "NOERROR")
    fail = len(results) - succ
    phase_duration = time.time() - phase_start_time
    ui.print_phase_footer("3: Record Consistency", {"Total Queries": len(results), "Success": succ, "Failures": fail}, phase_duration)

def main():
    script_start_time = time.time()
    settings = Settings()
    
    parser = argparse.ArgumentParser(description="FriendlyDNSReporter - Professional Suite (v2.9.2)")
    parser.add_argument("-n", "--domains", default=os.path.join("config", "domains.csv"), help="Domains CSV")
    parser.add_argument("-g", "--groups", default=os.path.join("config", "groups.csv"), help="Groups CSV")
    parser.add_argument("-o", "--output", default=settings.log_dir, help="Output DIR")
    args = parser.parse_args()
    
    ui.print_banner("v2.9.2")
    ui.print_header(settings.max_threads, settings.consistency_checks, os.path.basename(args.domains))
    
    domains_raw, dns_groups = load_datasets(args.domains, args.groups)
    if not domains_raw or not dns_groups:
        print(f"[{ui.FAIL}ERROR{ui.RESET}] Datasets missing/empty.")
        sys.exit(1)

    dns_engine = DNSEngine(timeout=settings.timeout, tries=settings.dig_tries)
    conn = Connectivity(timeout=settings.timeout)
    lock = threading.Lock()
    
    # Identify which groups are actually used in domains.csv
    active_groups = set()
    for entry in domains_raw:
        for group in (entry.get('GROUPS') or '').split(','):
            active_groups.add(group.strip())
            
    # Collect only servers from active groups and create a reverse mapping
    all_servers = set()
    srv_to_groups = {}
    for group, srvs in dns_groups.items():
        if group in active_groups:
            all_servers.update(srvs)
            for s in srvs:
                if s not in srv_to_groups: srv_to_groups[s] = []
                srv_to_groups[s].append(group)
    
    # Format groups as strings
    for s in srv_to_groups:
        srv_to_groups[s] = ", ".join(srv_to_groups[s])
            
    if not all_servers:
        print(f"[{ui.FAIL}ERROR{ui.RESET}] No active servers found for the specified domains.")
        sys.exit(1)
    
    infra_cache = {}
    if settings.enable_phase_server:
        ui.print_phase("1: Server Infrastructure")
        infra_cache = run_phase1_infrastructure(all_servers, srv_to_groups, conn, dns_engine, settings, lock)
    
    zone_results = []
    if settings.enable_phase_zone:
        ui.print_phase("2: Zone Integrity")
        zone_results = run_phase2_zones(domains_raw, dns_groups, dns_engine, settings, infra_cache, lock)
    
    results = []
    if settings.enable_phase_record:
        ui.print_phase("3: Record Consistency")
        tasks = []
        for entry in domains_raw:
            domain = entry.get('DOMAIN')
            if not domain: continue
            targets = [domain] + [f"{h.strip()}.{domain}" for h in (entry.get('EXTRA') or '').split(',') if h.strip()]
            for target in targets:
                for group in (entry.get('GROUPS') or '').split(','):
                    group = group.strip()
                    for server in dns_groups.get(group, []):
                        tasks.append((target, group, server, (entry.get('RECORDS') or '').split(',')))
        run_phase3_records(tasks, dns_engine, settings, infra_cache, results, lock)

    # Reporting & Summary
    reporter = Reporter(args.output)
    report_data = {"summary": {"total": len(results), "timestamp": datetime.now().isoformat()}, "infrastructure": infra_cache, "zones": zone_results, "results": results}
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M')
    
    paths = {}
    if settings.enable_json_report: paths["JSON"] = reporter.export_json(report_data, f"report_{timestamp}.json")
    if settings.enable_csv_report: paths["CSV"] = reporter.export_csv(results, f"report_{timestamp}.csv", list(results[0].keys()) if results else [])
    if settings.enable_html_report: paths["HTML"] = reporter.generate_html(report_data, f"dashboard_{timestamp}.html")
    
    total, success = len(results), sum(1 for r in results if r['status'] == "NOERROR")
    div = sum(1 for r in results if r['internally_consistent'] == "DIV!")
    sync_issues = sum(1 for z in zone_results if z['serial'] == "?" or z['status'] == "UNREACHABLE")
    script_duration = time.time() - script_start_time
    ui.print_summary_table(total, success, total-success, div, sync_issues, paths, script_duration)

if __name__ == "__main__":
    main()
