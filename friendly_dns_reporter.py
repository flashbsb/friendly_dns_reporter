#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
FRIENDLY DNS REPORTER - PYTHON EDITION
=============================================================================
Version: 5.1.0
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
import core.validators as validators
from core.config_loader import Settings
import core.ui as ui

# Silence DoH/DoT HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup Logging
def setup_logging(log_dir, use_timestamp=True):
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    if use_timestamp:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(log_dir, f"friendly_dns_{ts}.log")
    else:
        log_file = os.path.join(log_dir, "friendly_dns.log")
    
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
    """Load and normalize CSV datasets with robust auto-detection."""
    def _read_csv(path):
        if not os.path.exists(path): return []
        try:
            with open(path, 'r', encoding='utf-8-sig') as f:
                content = f.read()
                if not content: return []
                # Detect delimiter: comma, semicolon or tab
                delim = ';'
                for d in [';', ',', '\t']:
                    if d in content.split('\n')[0]:
                        delim = d
                        break
                
                f.seek(0)
                reader = csv.DictReader(f, delimiter=delim)
                # Normalize field names: strip, uppercase, and remove BOM/hash
                reader.fieldnames = [fn.lstrip('#').strip().upper() for fn in reader.fieldnames] if reader.fieldnames else []
                
                rows = []
                for row in reader:
                    if not any(row.values()) or any(str(v).startswith('#') for v in row.values()):
                        continue
                    # Strip all values
                    clean_row = {k.strip().upper(): str(v).strip() for k, v in row.items() if k}
                    rows.append(clean_row)
                return rows
        except Exception as e:
            print(f"Error reading {path}: {e}")
            return []

    groups_raw = _read_csv(groups_path)
    domains_raw = _read_csv(domains_path)
    
    # Process groups into a rich metadata dict
    dns_groups = {}
    for g in groups_raw:
        name = g.get('NAME')
        if name:
            name = name.strip().upper() # Normalize
            servers = g.get('SERVERS')
            if servers:
                dns_groups[name] = {
                    "servers": [s.strip() for s in servers.split(',')],
                    "type": g.get('TYPE', 'recursive').lower()
                }
            
    return domains_raw, dns_groups

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
        res["packet_loss"] = ping_res.get("packet_loss", 0.0)
        res["ping_count"] = settings.ping_count 
        res["ping_latency_warn"] = settings.ping_latency_warn
        res["ping_latency_crit"] = settings.ping_latency_crit
        res["ping_loss_warn"] = settings.ping_loss_warn
        res["ping_loss_crit"] = settings.ping_loss_crit
        
        # 2. Deep Service Probes (Port vs. Service)
        
        # UDP 53 (Pre-calculated via Version/Recursion)
        res["port53u"] = "OPEN" # UDP always assumed open if we try it, but we'll validate service below
        
        # TCP 53
        p53t_open, p53t_lat = conn.check_port(srv, 53)
        res["port53t"] = "OPEN" if p53t_open else "CLOSED"
        res["port53t_serv"] = "N/A"
        if p53t_open:
            st, lat = dns_engine.check_tcp(srv)
            res["port53t_serv"] = st
            if st == "OK": p53t_lat = lat
        res["port53t_lat"] = p53t_lat

        # 3. DNS-Dependent Checks (UDP)
        v, v_lat = dns_engine.query_version(srv) if settings.check_bind_version else ("DISABLED", 0)
        res["version"] = v if v is not None else "TIMEOUT"
        res["version_lat"] = v_lat
        
        r, r_lat = dns_engine.check_recursion(srv) if settings.enable_recursion_check else (False, 0)
        res["recursion"] = "OPEN" if r is True else ("CLOSED" if r is False else "TIMEOUT")
        res["recursion_lat"] = r_lat
        
        # Service Validation for UDP 53
        udp_serv_ok = res["version"] not in ["TIMEOUT", "UNREACHABLE", "DISABLED"] or \
                      res["recursion"] not in ["TIMEOUT", "UNREACHABLE", "DISABLED"]
        res["port53u_serv"] = "OK" if udp_serv_ok else ("TIMEOUT" if (res["version"] == "TIMEOUT" or res["recursion"] == "TIMEOUT") else "FAIL")
        
        # Circuit Breaker Logic: SERVER IS DEAD only if PORT and SERVICE fail across the board
        is_alive = (res["ping"] == "OK") or udp_serv_ok or (res["port53t_serv"] == "OK")
        
        if not is_alive:
            res["is_dead"] = True
            for field in ["version", "recursion", "dot", "doh", "dnssec", "edns0", "open_resolver"]:
                 res[field] = "UNREACHABLE"
            res["port53t_serv"] = "FAIL"
            res["port853_serv"] = "FAIL"
            res["port443_serv"] = "FAIL"
        else:
            # Protocols (DoT/DoH)
            p853_open, p853_slat = conn.check_port(srv, 853)
            res["port853"] = "OPEN" if p853_open else "CLOSED"
            res["port853_serv"] = "FAIL"
            if p853_open:
                dot_st, dot_lat = dns_engine.check_dot(srv) if settings.enable_dot_check else ("DISABLED", 0)
                res["dot"] = dot_st
                res["dot_lat"] = dot_lat
                res["port853_serv"] = dot_st
            else:
                res["dot"] = "NO"
                res["dot_lat"] = 0

            p443_open, p443_slat = conn.check_port(srv, 443)
            res["port443"] = "OPEN" if p443_open else "CLOSED"
            res["port443_serv"] = "FAIL"
            if p443_open:
                doh_st, doh_lat = dns_engine.check_doh(srv) if settings.enable_doh_check else ("DISABLED", 0)
                res["doh"] = doh_st
                res["doh_lat"] = doh_lat
                res["port443_serv"] = doh_st
            else:
                res["doh"] = "NO"
                res["doh_lat"] = 0
            
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
        
        # Traceroute removed as requested (unused in UI)
        
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
    ui.print_phase_header("1: Server Infrastructure")
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
    zones = {} # domain -> list of (server, group_name)
    for entry in domains_raw:
        domain = entry.get('DOMAIN')
        if not domain: continue
        for group in (entry.get('GROUPS') or '').split(','):
            group = group.strip().upper()
            if group in dns_groups:
                if domain not in zones: zones[domain] = []
                for s in dns_groups[group]["servers"]:
                    zones[domain].append((s.strip(), group))

    def _check_zone(domain, srv_group_tuples):
        local_results = []
        serials = {}
        timers_list = []
        dnssec_status = []
        web_risks = {}
        mname_target = None

        for srv, group_name in srv_group_tuples:
            srv = srv.strip()
            infra = infra_cache.get(srv, {})
            
            # Determine recursion based on specific group type for THIS server
            is_recursive = dns_groups.get(group_name, {}).get("type") == "recursive"
            
            if infra.get("is_dead"):
                res = {
                    "domain": domain, "server": srv, "group": group_name, 
                    "serial": "N/A", "axfr_vulnerable": False, "axfr_detail": "PH1 FAIL", 
                    "status": "UNREACHABLE", "is_dead": True
                }
                local_results.append(res); serials[srv] = "N/A"
                continue

            try:
                # Harmonized recursion logic matching Phase 3
                soa = dns_engine.query(srv, domain, "SOA", rd=is_recursive)
                
                # Smart Fallback: if preferred RD fails, try the alternative
                if soa['status'] not in ["NOERROR", "NXDOMAIN"]:
                    soa_fallback = dns_engine.query(srv, domain, "SOA", rd=not is_recursive)
                    if soa_fallback['status'] == "NOERROR" or (soa_fallback['status'] == "NXDOMAIN" and soa['status'] != "NXDOMAIN"):
                        soa = soa_fallback

                # Robust extraction: check answers + authority
                records = soa['answers'] + soa.get('authority', [])
                soa_rec = next((r for r in records if " SOA " in f" {r} " or len(r.split()) >= 7), None)
                if not soa_rec and records: soa_rec = records[0] # Fallback
                
                parts = soa_rec.split() if soa_rec else []
                serial = "?"
                mname = "N/A"
                rname = "N/A"
                timer_parts = []
                
                if parts:
                    if "SOA" in parts:
                        idx = parts.index("SOA")
                        if len(parts) > idx + 3:
                            mname = parts[idx+1]
                            rname = parts[idx+2]
                            serial = parts[idx+3]
                        if len(parts) > idx + 7:
                            timer_parts = parts[idx+4:idx+8]
                    elif len(parts) >= 7:
                        mname = parts[0]
                        rname = parts[1]
                        serial = parts[2]
                        timer_parts = parts[3:7]
                
                # SOA Timers (Refresh, Retry, Expire, MinTTL)
                if len(timer_parts) >= 4 and settings.enable_soa_timer_audit:
                    try:
                        t_ref, t_ret, t_exp, t_min = int(timer_parts[0]), int(timer_parts[1]), int(timer_parts[2]), int(timer_parts[3])
                        timers_list.append((t_ref, t_ret, t_exp, t_min))
                    except: pass
                
                aa = soa.get('aa', False)
                latency = soa.get('latency', 0)
                
                # DNSSEC Check
                is_signed = dns_engine.check_zone_dnssec(srv, domain) if settings.enable_zone_dnssec_check else False
                dnssec_status.append(is_signed)
                
                # Web Risk Check
                risks = [] # Web Risk check removed (silent feature)
                web_risks[srv] = risks

                # NS Check (Check answers and authority for referrals)
                ns_q = dns_engine.query(srv, domain, "NS", rd=is_recursive)
                
                ns_records = ns_q['answers'] + ns_q.get('authority', [])
                ns_list = []
                for nr in ns_records:
                    p = nr.split()
                    if "NS" in p:
                        ns_list.append(p[p.index("NS")+1].lower().rstrip('.'))
                    elif len(p) == 1:
                        ns_list.append(p[0].lower().rstrip('.'))
                ns_list = sorted(list(set(ns_list)))
                
                serials[srv] = serial
                if mname != "N/A": mname_target = mname
                
                axfr_ok, axfr_msg = dns_engine.check_axfr(srv, domain) if settings.enable_axfr_check else (False, "DISABLED")
                
                res = {
                    "domain": domain, "server": srv, "group": group_name,
                    "serial": serial, "mname": mname, "rname": rname,
                    "axfr_vulnerable": axfr_ok, "axfr_detail": axfr_msg, "status": soa['status'],
                    "aa": aa, "latency": latency, "ns_list": ns_list,
                    "soa_latency_warn": settings.soa_latency_warn,
                    "soa_latency_crit": settings.soa_latency_crit,
                    "axfr_allowed_groups": settings.axfr_allowed_groups,
                    "web_risks": risks,
                    "dnssec": is_signed,
                    "is_dead": False
                }
                local_results.append(res)
            except Exception as e:
                # Critical: Include group in error result so UI doesn't show UNCATEGORIZED
                local_results.append({
                    "domain": domain, "server": srv, "group": group_name,
                    "serial": "?", "status": f"ERROR: {str(e)}", "axfr_vulnerable": False
                })

        is_synced = len(set(s for s in serials.values() if s != "N/A")) <= 1
        ns_lists = [r['ns_list'] for r in local_results if r.get('status') == "NOERROR" and 'ns_list' in r]
        ns_consistent = len(set(tuple(l) for l in ns_lists)) <= 1 if ns_lists else True
        
        # ZONE AUDIT LOGIC
        audit = {
            "dnssec": any(dnssec_status),
            "timers_ok": True, "timers_issues": [],
            "mname_reachable": None, "glue_ok": True,
            "web_risk": any(r for r in web_risks.values())
        }
        
        if timers_list and settings.enable_soa_timer_audit:
            # Check consistency of timers across servers
            if len(set(timers_list)) > 1:
                audit["timers_ok"] = False
                audit["timers_issues"].append("Inconsistent timers across servers")
            
            # RFC 1912 Analysis (use first set if consistent)
            ref, ret, exp, mn = timers_list[0]
            rfc_ok, rfc_issues = dns_engine.analyze_soa_timers(ref, ret, exp, mn)
            if not rfc_ok:
                audit["timers_ok"] = False
                audit["timers_issues"].extend(rfc_issues)

        if mname_target:
            # Check if MNAME matches any server we just tested
            for r in local_results:
                srv_val = str(r.get('server', '')).lower()
                mn_val = str(r.get('mname', '')).lower()
                clean_target = mname_target.lower().rstrip('.')
                if clean_target in srv_val or clean_target in mn_val:
                     if r.get('status') == "NOERROR":
                         audit["mname_reachable"] = f"{r['server']} (UP)"
                         break
            if not audit["mname_reachable"]:
                audit["mname_reachable"] = f"{mname_target} (UNKNOWN)"

        for r in local_results:
            r["zone_audit"] = audit
            r["zone_is_synced"] = is_synced
            r["ns_consistent"] = ns_consistent

        with lock:
            zone_results.extend(local_results)
            counters['done'] += 1
            ui.print_progress(counters['done'], total, "Checking Zones")

    counters = {'done': 0}
    total = len(zones)
    # ui.print_phase_header("2: Zone Integrity") # Header moved down after progress
    with concurrent.futures.ThreadPoolExecutor(max_workers=settings.max_threads) as executor:
        futures = [executor.submit(_check_zone, dom, srvs) for dom, srvs in zones.items()]
        concurrent.futures.wait(futures)
        
    # Final sorted print
    ui.print_phase_header("2: Zone Integrity")
    last_domain = None
    sorted_zones = sorted(zone_results, key=lambda x: (x['domain'], x['server']))
    for i, res in enumerate(sorted_zones):
        # Check for NS inconsistency and Zone Sync per domain (printed once)
        if res['domain'] != last_domain:
            if last_domain is not None:
                # Print audit block for the PREVIOUS domain
                prev_res = sorted_zones[i-1]
                ui.print_zone_audit_block(last_domain, prev_res.get('zone_audit', {}))

            last_domain = res['domain']
            
        ui.print_zone_detail(res['server'], res['domain'], res)
    
    # Print audit block for the LAST domain
    if sorted_zones:
        last_res = sorted_zones[-1]
        ui.print_zone_audit_block(last_res['domain'], last_res.get('zone_audit', {}))
        
    # Phase Summary
    vuln = sum(1 for r in zone_results if r['axfr_vulnerable'])
    lame = sum(1 for r in zone_results if not r.get('aa', True) and r.get('status') == "NOERROR")
    inconsistent_ns = sum(1 for r in zone_results if r.get('ns_list') and len(set(tuple(r2.get('ns_list', [])) for r2 in zone_results if r2['domain'] == r['domain'])) > 1)
    
    phase_duration = time.time() - phase_start_time
    ui.print_phase_footer("2: Zones", {
        "Domains Tested": len(zones),
        "Lame Delegations": lame,
        "NS Inconsistencies": inconsistent_ns // 2 if inconsistent_ns > 0 else 0 # Rough estimate
    }, phase_duration)
        
    return zone_results

def run_phase3_records(tasks, dns_engine, dns_groups, settings, infra_cache, results, lock):
    """Phase 3: Parallel Record Consistency Check."""
    phase_start_time = time.time()
    counters = {'done': 0}
    total = len(tasks)
    
    def _worker(target, group_name, server, record_types):
        try:
            # Circuit Breaker
            infra = infra_cache.get(server, {})
            if infra.get("is_dead"):
                local_res = [{
                    "domain": target, "group": group_name, "server": server, "type": rtype,
                    "status": "UNREACHABLE", "latency": 0, "ping": "FAIL", "port53": "CLOSED",
                    "version": "DEAD", "recursion": "DEAD", "dot": "DEAD", "doh": "DEAD",
                    "nsid": None, "internally_consistent": "N/A", "answers": "SKIPPED: SERVER DOWN",
                    "is_consistent": True
                } for rtype in record_types if rtype.strip()]
                with lock:
                    results.extend(local_res)
                    counters['done'] += 1
                    ui.print_progress(counters['done'], total, "Record Consistency")
                return

            local_res = []
            # Determine recursion based on group type
            is_recursive = dns_groups.get(group_name, {}).get("type") == "recursive"
            
            for rtype in record_types:
                rtype = rtype.strip().upper()
                if not rtype: continue
                
                queries = []
                for _ in range(settings.consistency_checks):
                    res = dns_engine.query(server, target, rtype, rd=is_recursive, use_edns=settings.enable_edns_check)
                    queries.append(res)
                    if settings.sleep_time > 0: time.sleep(settings.sleep_time)
                    
                is_consistent = compare_consistency(queries, settings)
                main_q = queries[0]
                
                # SEMANTIC AUDIT
                findings = []
                
                # 1. TTL Analysis
                ttl_ok, ttl_msg = validators.analyze_ttl(main_q.get('ttl', 0))
                if not ttl_ok: findings.append(ttl_msg)
                
                # 2. Record Specific Syntax/Chain checks
                spf_list = [a for a in main_q['answers'] if rtype == "TXT" and "v=spf1" in a]
                dmarc_list = [a for a in main_q['answers'] if rtype == "TXT" and "v=DMARC1" in a]
                
                if spf_list:
                    _, spf_issues = validators.validate_spf(spf_list)
                    findings.extend(spf_issues)
                    
                if dmarc_list:
                    _, dmarc_issues = validators.validate_dmarc(dmarc_list)
                    findings.extend(dmarc_issues)

                for ans in main_q['answers']:
                    # Dangling DNS (CNAME / MX)
                    if rtype in ["CNAME", "MX"]:
                        # Extract target (MX has priority first)
                        target_host = ans.split(' ')[1] if rtype == "MX" else ans.rstrip('.')
                        chain_ok, chain_msg = dns_engine.resolve_chain(server, target_host, rtype)
                        if not chain_ok:
                            findings.append(f"Dangling {rtype} target: {target_host} ({chain_msg})")
                        else:
                            # MX Target Port 25 Check
                            if rtype == "MX":
                                 if not dns_engine.check_port_25(target_host):
                                     findings.append(f"MX Target {target_host} UNREACHABLE on Port 25 (SMTP)")

                entry = {
                    "domain": target, "group": group_name, "server": server, "type": rtype,
                    "status": main_q['status'], "latency": main_q['latency'],
                    "ping": infra.get("ping", "N/A"), "port53": infra.get("port53u", "N/A"),
                    "version": infra.get("version", "N/A"), "recursion": infra.get("recursion", "N/A"),
                    "dot": infra.get("dot", "N/A"), "doh": infra.get("doh", "N/A"),
                    "nsid": main_q.get("nsid"), "internally_consistent": "YES" if is_consistent else "DIV!",
                    "answers": ", ".join(main_q['answers']),
                    "is_consistent": is_consistent,
                    "findings": findings
                }
                local_res.append(entry)
            
            with lock:
                results.extend(local_res)
                counters['done'] += 1
                ui.print_progress(counters['done'], total, "Record Consistency")
        except Exception as e:
            with lock:
                # Add a partial/error result instead of nothing
                results.append({"domain": target, "group": group_name, "server": server, "type": "ERROR", "status": str(e), "latency": 0, "is_consistent": False})
                counters['done'] += 1
                ui.print_progress(counters['done'], total, "Record Consistency")

    counters = {'done': 0}
    total = len(tasks)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=settings.max_threads) as executor:
        futures = [executor.submit(_worker, *t) for t in tasks]
        concurrent.futures.wait(futures)

    # Post-collection sorting and printing
    ui.print_phase_header("3: Record Consistency")
    
    # Sort results
    sorted_results = sorted(results, key=lambda x: (x['domain'], x['group'], x['server']))
    
    last_zone_srv = None # (domain, server) pair
    
    for r in sorted_results:
        print(ui.format_result(
            r['domain'], r['group'], r['server'], r['type'], r['status'], r['latency'], r['is_consistent'],
            warn_ms=settings.rec_latency_warn, crit_ms=settings.rec_latency_crit
        ))
        
        # Print semantic findings
        if r.get('findings'):
            ui.print_record_findings(r['findings'])
            
        # Optional: Wildcard detection per (domain, server)
        # We only do it once per (zone, server) to avoid spam
        current_zone_srv = (r['domain'], r['server'])
        if current_zone_srv != last_zone_srv and r['status'] == "NOERROR":
            has_wc, wc_ans = dns_engine.detect_wildcard(r['server'], r['domain'])
            if has_wc:
                ui.print_record_findings([f"Wildcard detection triggered! Zone resolves any sub-subdomain to: {wc_ans}"])
            last_zone_srv = current_zone_srv
    
    # Phase Summary
    succ = sum(1 for r in results if r['status'] == "NOERROR")
    fail = len(results) - succ
    phase_duration = time.time() - phase_start_time
    ui.print_phase_footer("3: Record Consistency", {"Total Queries": len(results), "Success": succ, "Failures": fail}, phase_duration)

def main():
    script_start_time = time.time()
    settings = Settings()
    log_file = setup_logging(settings.log_dir, use_timestamp=settings.enable_report_timestamps)
    
    parser = argparse.ArgumentParser(description="FriendlyDNSReporter - Professional Suite (v5.1.0)")
    parser.add_argument("-n", "--domains", default=os.path.join("config", "domains.csv"), help="Domains CSV")
    parser.add_argument("-g", "--groups", default=os.path.join("config", "groups.csv"), help="Groups CSV")
    parser.add_argument("-o", "--output", default=settings.log_dir, help="Output DIR")
    parser.add_argument("-p", "--phases", help="Select phases to run (e.g. 1,3 or 2)")
    args = parser.parse_args()
    
    # Process phase selection
    run_p1 = settings.enable_phase_server
    run_p2 = settings.enable_phase_zone
    run_p3 = settings.enable_phase_record
    
    if args.phases:
        selected = [p.strip() for p in args.phases.split(',')]
        run_p1 = "1" in selected
        run_p2 = "2" in selected
        run_p3 = "3" in selected

    ui.print_banner("v5.1.0")
    ui.print_header(settings.max_threads, settings.consistency_checks, os.path.basename(args.domains))
    
    domains_raw, dns_groups = load_datasets(args.domains, args.groups)
    if not domains_raw or not dns_groups:
        print(f"[{ui.FAIL}ERROR{ui.RESET}] Datasets missing/empty.")
        sys.exit(1)

    dns_engine = DNSEngine(timeout=settings.dns_timeout, tries=settings.dns_retries)
    conn = Connectivity(timeout=settings.timeout)
    lock = threading.Lock()
    
    # Identify which groups are actually used in domains.csv
    active_groups = set()
    for entry in domains_raw:
        for group in (entry.get('GROUPS') or '').split(','):
            active_groups.add(group.strip().upper())
            
    # Collect servers and create a reverse mapping
    all_servers = set()
    srv_to_groups = {}
    for group, g_meta in dns_groups.items():
        # Only process if it's an active group OR if filtering is disabled
        if not settings.only_test_active_groups or group in active_groups:
            all_servers.update(g_meta["servers"])
            for s in g_meta["servers"]:
                if s not in srv_to_groups: srv_to_groups[s] = []
                srv_to_groups[s].append(group)
    
    # Format groups as strings
    for s in srv_to_groups:
        srv_to_groups[s] = ", ".join(srv_to_groups[s])
            
    if not all_servers:
        print(f"[{ui.FAIL}ERROR{ui.RESET}] No active servers found for the specified domains.")
        sys.exit(1)
    
    infra_cache = {}
    if run_p1:
        ui.print_phase("1: Server Infrastructure")
        infra_cache = run_phase1_infrastructure(all_servers, srv_to_groups, conn, dns_engine, settings, lock)
    
    zone_results = []
    if run_p2:
        ui.print_phase("2: Zone Integrity")
        zone_results = run_phase2_zones(domains_raw, dns_groups, dns_engine, settings, infra_cache, lock)
    
    results = []
    if run_p3:
        ui.print_phase("3: Record Consistency")
        tasks = []
        for entry in domains_raw:
            domain = entry.get('DOMAIN')
            if not domain: continue
            targets = [domain] + [f"{h.strip()}.{domain}" for h in (entry.get('EXTRA') or '').split(',') if h.strip()]
            for target in targets:
                for group in (entry.get('GROUPS') or '').split(','):
                    group = group.strip().upper()
                    for server in dns_groups.get(group, {}).get("servers", []):
                        tasks.append((target, group, server, (entry.get('RECORDS') or '').split(',')))
        run_phase3_records(tasks, dns_engine, dns_groups, settings, infra_cache, results, lock)

    # Reporting & Summary
    reporter = Reporter(args.output)
    report_data = {"summary": {"total": len(results), "timestamp": datetime.now().isoformat()}, "infrastructure": infra_cache, "zones": zone_results, "results": results}
    
    suffix = f"_{datetime.now().strftime('%Y%m%d_%H%M')}" if settings.enable_report_timestamps else ""
    
    paths = {}
    if settings.enable_json_report: paths["JSON"] = reporter.export_json(report_data, f"report{suffix}.json")
    if settings.enable_csv_report: paths["CSV"] = reporter.export_csv(results, f"report{suffix}.csv", list(results[0].keys()) if results else [])
    if settings.enable_html_report: paths["HTML"] = reporter.generate_html(report_data, f"dashboard{suffix}.html")
    
    # Filter out empty paths (fixes request to not show 'Reports Generated' header if none created)
    paths = {k: v for k, v in paths.items() if v}
    
    total, success = len(results), sum(1 for r in results if r['status'] == "NOERROR")
    div = sum(1 for r in results if r['internally_consistent'] == "DIV!")
    sync_issues = sum(1 for z in zone_results if z['serial'] == "?" or z['status'] == "UNREACHABLE")
    script_duration = time.time() - script_start_time
    ui.print_summary_table(total, success, total-success, div, sync_issues, paths, script_duration)

if __name__ == "__main__":
    main()
