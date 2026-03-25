#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
FRIENDLY DNS REPORTER
=============================================================================
Author: flashbsb
Description: 3-Phase Automated DNS diagnostics for Windows and Linux.
=============================================================================
"""

import sys
import os
import subprocess

BOOTSTRAP_LOGS = []

def _bootstrap_note(message):
    BOOTSTRAP_LOGS.append(message)

def _get_missing_dependencies():
    """Return the list of missing pip packages required by the script."""
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
    return missing_packages

def _handle_missing_dependencies(missing_packages, auto_install=False):
    """Prompt or instruct the user about missing dependencies."""
    if not missing_packages:
        return

    install_cmd = f"{sys.executable} -m pip install {' '.join(missing_packages)}"
    _bootstrap_note(f"Missing dependencies detected: {', '.join(missing_packages)}")
    print("[*] Missing dependencies detected:")
    for pkg in missing_packages:
        print(f"    - {pkg}")

    if auto_install:
        _bootstrap_note("Automatic dependency installation explicitly enabled by --install-missing-deps.")
        print("[*] Automatic dependency installation explicitly enabled by --install-missing-deps.")
        should_install = True
    elif sys.stdin is None or not sys.stdin.isatty():
        _bootstrap_note("Non-interactive session detected. Automatic installation disabled by default.")
        print("[-] Non-interactive session detected. Automatic installation is disabled by default.")
        print(f"[-] Install them manually with:\n    {install_cmd}")
        sys.exit(1)
    else:
        reply = input("[?] Attempt automatic installation now? [y/N]: ").strip().lower()
        should_install = reply in ("y", "yes")

    if not should_install:
        _bootstrap_note("Dependency installation canceled by user.")
        print("[-] Dependency installation canceled by user.")
        print(f"[-] Install them manually with:\n    {install_cmd}")
        sys.exit(1)

    print("[*] Attempting to install missing dependencies automatically...")
    _bootstrap_note("Attempting automatic installation of missing dependencies.")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
        _bootstrap_note("Missing dependencies installed successfully.")
        print("[+] Dependencies installed successfully. Resuming execution...\n")
    except subprocess.CalledProcessError as e:
        _bootstrap_note(f"Automatic dependency installation failed: {e}")
        print(f"[-] Failed to install dependencies automatically. Error: {e}")
        print(f"[-] Please manually run:\n    {install_cmd}")
        sys.exit(1)

import argparse
import csv
import concurrent.futures
import ipaddress
import threading
import logging
import time
from datetime import datetime

from core.config_loader import Settings
from core.version import VERSION

def _log_bootstrap_messages(enabled):
    if enabled and BOOTSTRAP_LOGS:
        for entry in BOOTSTRAP_LOGS:
            logging.info(f"[BOOTSTRAP] {entry}")

def _truncate_for_log(value, limit=240):
    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= limit else text[:limit - 3] + "..."

def _latency_or_none(value):
    if value is None:
        return None
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None

def _status_latency(status, latency, success_statuses=None):
    success_statuses = success_statuses or {"OK", "OPEN", "NOERROR", "NXDOMAIN", "REFUSED", "NO_RECURSION", "SERVFAIL", "HIDDEN"}
    return _latency_or_none(latency) if status in success_statuses else None

def _collect_available_latencies(*values):
    return [float(v) for v in values if isinstance(v, (int, float)) and v > 0]

def _format_probe_basis(latencies):
    if not latencies:
        return "N/A"
    avg = sum(latencies) / len(latencies)
    return f"{avg:.1f}ms across {len(latencies)} measured probe(s)"

def _latency_log(value):
    return f"{value:.1f}ms" if value is not None else "N/A"

def _probe_failure_reason(status, latency=None):
    text = str(status or "").upper()
    if latency is None and text in {"OK", "OPEN", "NOERROR", "NXDOMAIN", "REFUSED", "NO_RECURSION", "SERVFAIL", "HIDDEN"}:
        return "no_timing"
    if "TIMEOUT" in text:
        return "timeout"
    if "UNREACHABLE" in text:
        return "unreachable"
    if text in {"CLOSED", "NO"}:
        return "closed"
    if text in {"DISABLED", "N/A"}:
        return "not_evaluated"
    if text.startswith("ERROR"):
        return "error"
    if text in {"FAIL", "FALSE"}:
        return "probe_failed"
    if text in {"OK", "OPEN", "NOERROR", "NXDOMAIN", "REFUSED", "NO_RECURSION", "SERVFAIL", "HIDDEN"}:
        return "none"
    return text.lower() if text else "unknown"

def _set_probe_observability(res, name, status, latency, source="direct"):
    res[f"{name}_timing_source"] = source
    res[f"{name}_failure_reason"] = _probe_failure_reason(status, latency)

def _store_probe_evidence(res, name, meta):
    meta = meta or {}
    res[f"{name}_protocol"] = meta.get("protocol")
    res[f"{name}_rcode"] = meta.get("rcode")
    res[f"{name}_flags"] = meta.get("flags")
    res[f"{name}_query_size"] = meta.get("query_size")
    res[f"{name}_response_size"] = meta.get("response_size")
    res[f"{name}_authority_count"] = meta.get("authority_count")
    res[f"{name}_answer_count"] = meta.get("answer_count")
    if "aa" in meta:
        res[f"{name}_aa"] = meta.get("aa")
    if "tc" in meta:
        res[f"{name}_tc"] = meta.get("tc")
    if "http_status" in meta:
        res[f"{name}_http_status"] = meta.get("http_status")
    if "ra" in meta:
        res[f"{name}_ra"] = meta.get("ra")

def _run_repeated_probe(probe_fn, repeats, success_statuses=None):
    success_statuses = set(success_statuses or {"OK"})
    attempts = []
    status_counts = {}
    last_seen = {}
    meta_choice = {}

    for idx in range(max(1, int(repeats or 1))):
        res = probe_fn() # Returns DNSResponse
        attempts.append(res)
        status_counts[res.status] = status_counts.get(res.status, 0) + 1
        last_seen[res.status] = idx
        if res.meta and not meta_choice:
            meta_choice = res.meta
        if res.meta and res.status in success_statuses:
            meta_choice = res.meta

    representative_status = max(status_counts, key=lambda s: (status_counts[s], last_seen[s])) if status_counts else "N/A"
    successful_latencies = [a.latency for a in attempts if a.status in success_statuses and a.latency is not None]
    first_latency = successful_latencies[0] if successful_latencies else None
    min_latency = min(successful_latencies) if successful_latencies else None
    max_latency = max(successful_latencies) if successful_latencies else None
    avg_latency = round(sum(successful_latencies) / len(successful_latencies), 2) if successful_latencies else None
    jitter = round(max_latency - min_latency, 2) if len(successful_latencies) >= 2 else None

    return {
        "status": representative_status,
        "latency": avg_latency,
        "first": first_latency,
        "min": min_latency,
        "max": max_latency,
        "jitter": jitter,
        "sample_count": len(attempts),
        "measured_count": len(successful_latencies),
        "status_consistent": len(status_counts) <= 1,
        "status_samples": [a.status for a in attempts],
        "meta": meta_choice,
    }

def _store_probe_repeat_summary(res, name, summary):
    res[f"{name}_sample_count"] = summary.get("sample_count", 0)
    res[f"{name}_measured_count"] = summary.get("measured_count", 0)
    res[f"{name}_latency_first"] = summary.get("first")
    res[f"{name}_latency_min"] = summary.get("min")
    res[f"{name}_latency_avg"] = summary.get("latency")
    res[f"{name}_latency_max"] = summary.get("max")
    res[f"{name}_latency_jitter"] = summary.get("jitter")
    res[f"{name}_status_consistent"] = summary.get("status_consistent")
    res[f"{name}_status_samples"] = summary.get("status_samples", [])

def _store_query_evidence(res, name, query_result):
    if not query_result: return
    res[f"{name}_protocol"] = query_result.protocol
    res[f"{name}_rcode"] = query_result.status
    res[f"{name}_flags"] = query_result.flags
    res[f"{name}_query_size"] = query_result.query_size
    res[f"{name}_response_size"] = query_result.response_size
    res[f"{name}_authority_count"] = query_result.authority_count
    res[f"{name}_answer_count"] = query_result.answer_count
    res[f"{name}_aa"] = query_result.aa
    res[f"{name}_tc"] = query_result.tc

def _run_repeated_query(query_fn, repeats, success_statuses=None):
    success_statuses = set(success_statuses or {"NOERROR"})
    attempts = []
    status_counts = {}
    last_seen = {}
    representative_query = None

    for idx in range(max(1, int(repeats or 1))):
        query_result = query_fn() # Returns DNSResponse
        attempts.append(query_result)
        status = query_result.status
        status_counts[status] = status_counts.get(status, 0) + 1
        last_seen[status] = idx
        if not representative_query:
            representative_query = query_result
        if status in success_statuses:
            representative_query = query_result

    representative_status = max(status_counts, key=lambda s: (status_counts[s], last_seen[s])) if status_counts else "N/A"
    successful_latencies = [q.latency for q in attempts if q.status in success_statuses and q.latency is not None]
    first_latency = successful_latencies[0] if successful_latencies else None
    min_latency = min(successful_latencies) if successful_latencies else None
    max_latency = max(successful_latencies) if successful_latencies else None
    avg_latency = round(sum(successful_latencies) / len(successful_latencies), 2) if successful_latencies else None
    jitter = round(max_latency - min_latency, 2) if len(successful_latencies) >= 2 else None

    return representative_query, {
        "status": representative_status,
        "latency": avg_latency,
        "first": first_latency,
        "min": min_latency,
        "max": max_latency,
        "jitter": jitter,
        "sample_count": len(attempts),
        "measured_count": len(successful_latencies),
        "status_consistent": len(status_counts) <= 1,
        "status_samples": [q.status for q in attempts],
    }

def _query_log_payload(query_result, include_full_response=False):
    payload = {
        "status": query_result.status,
        "latency_ms": round(query_result.latency or 0, 2),
        "flags": query_result.flags,
        "aa": query_result.aa,
        "tc": query_result.tc,
        "rd": query_result.rd,
        "ra": query_result.ra,
        "ad": query_result.ad,
        "cd": query_result.cd,
        "ttl": query_result.ttl,
        "answers": query_result.answers,
        "authority": query_result.authority,
        "additional": query_result.additional,
        "nsid": query_result.nsid,
        "query_size": query_result.query_size,
        "response_size": query_result.response_size
    }
    if include_full_response:
        payload["full_response"] = _truncate_for_log(query_result.full_response, 1200)
    return payload

# Setup Logging
def setup_logging(settings):
    if not settings.enable_execution_log:
        # If disabled, we still return a dummy string but don't configure logging
        return None

    log_dir = settings.log_dir
    use_timestamp = settings.enable_report_timestamps

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
            logging.FileHandler(log_file, encoding='utf-8')
            # StreamHandler(sys.stdout) removed to avoid double output with standard print()
        ]
    )
    # Silence third-party logs
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    
    logging.info("=============================================================================")
    logging.info(f"FRIENDLY DNS REPORTER STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logging.info("=============================================================================")
    
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
    if not queries:
        return True

    def _normalize_answer(answer):
        parts = answer.split()
        normalized = []
        for part in parts:
            token = part.rstrip(".")
            try:
                ip_obj = ipaddress.ip_address(token)
                normalized.append(str(ip_obj) if not settings.strict_ip_check else token)
                continue
            except ValueError:
                pass
            normalized.append(part)
        return " ".join(normalized)
    
    def _get_key(q):
        # Build comparison tuple based on strictness
        ans = [_normalize_answer(a) for a in q.get('answers', [])]
        if not settings.strict_order_check:
            ans = sorted(ans)
        
        ttl = q.get("ttl", 0) if settings.strict_ttl_check else None
        return tuple(ans), ttl

    base_key = _get_key(queries[0])
    return all(_get_key(q) == base_key for q in queries[1:])

def is_open_resolver_safe(status):
    return status in {"REFUSED", "NO_RECURSION", "CLOSED"}

def classify_open_resolver(status):
    if status == "OPEN":
        return {
            "classification": "PUBLIC",
            "resolver_exposed": True,
            "resolver_restricted": False,
            "confidence": "HIGH"
        }
    if is_open_resolver_safe(status):
        return {
            "classification": "RESTRICTED",
            "resolver_exposed": False,
            "resolver_restricted": True,
            "confidence": "HIGH"
        }
    if status == "SERVFAIL":
        return {
            "classification": "UNKNOWN",
            "resolver_exposed": None,
            "resolver_restricted": None,
            "confidence": "LOW"
        }
    if status in {"DISABLED", "UNREACHABLE"}:
        return {
            "classification": "NOT_EVALUATED",
            "resolver_exposed": None,
            "resolver_restricted": None,
            "confidence": "NONE"
        }
    return {
        "classification": "UNKNOWN",
        "resolver_exposed": None,
        "resolver_restricted": None,
        "confidence": "LOW"
    }

def derive_server_profile(group_types):
    normalized = {g.lower() for g in group_types if g}
    if not normalized:
        return "unknown"
    if normalized == {"recursive"}:
        return "recursive"
    if normalized == {"authoritative"}:
        return "authoritative"
    return "mixed"

def score_label(value):
    if value is None:
        return "N/A"
    return int(value)

def start_phase_watchdog(label, counters, total, active_items, lock, log_enabled=True):
    """
    Spawns a background thread to track progress and report stall/idle status.
    Uses settings for dynamic intervals.
    """
    settings = Settings()
    interval = settings.watchdog_interval
    stop_event = threading.Event()
    state = {"status": "", "last_done": -1, "last_change": time.time(), "last_idle_bucket": -1}

    def _watch():
        while not stop_event.is_set():
            time.sleep(1)
            with lock:
                done = counters.get('done', 0)
                active_snapshot = list(active_items.keys())
            
            now = time.time()
            if done != state["last_done"]:
                state["last_done"] = done
                state["last_change"] = now
                state["status"] = ""
                state["last_idle_bucket"] = -1
                continue
            
            if done < total:
                idle_for = now - state["last_change"]
                state["status"] = ui.format_progress_status(active_snapshot, idle_for)
                
                idle_bucket = int(idle_for // interval)
                if log_enabled and idle_bucket > state["last_idle_bucket"]:
                    state["last_idle_bucket"] = idle_bucket
                    logging.warning(
                        "[%s] No task completion for %.1fs (%s/%s). Active: %s",
                        label,
                        idle_for,
                        done,
                        total,
                        ", ".join(active_snapshot[:5]) if active_snapshot else "none",
                    )
    
    watcher = threading.Thread(target=_watch, daemon=True)
    watcher.start()
    return stop_event, watcher, state

def run_phase1_infrastructure(servers, srv_groups, srv_profiles, conn, dns_engine, settings, lock):
    """Phase 1: Deep Infrastructure Check (Once per server)."""
    ui.print_phase("1: Server Infrastructure", "Testing reachability, DNS service responsiveness, encryption, and exposure.")
    phase_start_time = time.time()
    infra_results = {}
    active_items = {}
    
    def _check_server(srv):
        srv = srv.strip()
        if not srv: return
        with lock:
            active_items[srv] = "server"
        
        res = {
            "server": srv,
            "is_dead": False,
            "groups": srv_groups.get(srv, "N/A"),
            "server_profile": srv_profiles.get(srv, "unknown"),
            "web_risks": [],
            "dnssec_mode": "DATA_SERVING",
            "qname_min_confidence": "NONE"
        }
        
        # 1. Connectivity Probes (Ping)
        ping_res = conn.ping(srv, count=settings.ping_count) if settings.enable_ping else {"is_alive": True}
        res["ping"] = "OK" if ping_res.get("is_alive") else "FAIL"
        res["latency"] = _latency_or_none(ping_res.get("avg_rtt"))
        res["latency_min"] = _latency_or_none(ping_res.get("min_rtt"))
        res["latency_max"] = _latency_or_none(ping_res.get("max_rtt"))
        res["packet_loss"] = ping_res.get("packet_loss", 0.0)
        res["ping_count"] = settings.ping_count 
        res["ping_latency_warn"] = settings.ping_latency_warn
        res["ping_latency_crit"] = settings.ping_latency_crit
        res["ping_loss_warn"] = settings.ping_loss_warn
        res["ping_loss_crit"] = settings.ping_loss_crit
        
        # 2. Deep Service Probes (Port vs. Service)
        critical_probe_repeats = settings.phase1_probe_repeats

        # UDP 53 (direct DNS responsiveness probe)
        res["port53u"] = "OPEN"
        udp_summary = _run_repeated_probe(lambda: dns_engine.check_udp(srv), critical_probe_repeats, {"OK"})
        res["udp53_status_raw"] = udp_summary["status"]
        res["udp53_probe_lat"] = udp_summary["latency"]
        _store_probe_repeat_summary(res, "udp53_probe", udp_summary)
        _store_probe_evidence(res, "udp53_probe", udp_summary.get("meta"))

        # TCP 53
        p53t_open, p53t_lat = conn.check_port(srv, 53)
        res["port53t"] = "OPEN" if p53t_open else "CLOSED"
        res["port53t_serv"] = "N/A"
        res["port53t_conn_lat"] = _latency_or_none(p53t_lat)
        res["port53t_probe_lat"] = None
        _set_probe_observability(res, "tcp53_connect", res["port53t"], res["port53t_conn_lat"])
        if p53t_open:
            tcp_summary = _run_repeated_probe(lambda: dns_engine.check_tcp(srv), critical_probe_repeats, {"OK"})
            res["port53t_serv"] = tcp_summary["status"]
            res["port53t_probe_lat"] = tcp_summary["latency"]
            _store_probe_repeat_summary(res, "tcp53_probe", tcp_summary)
            _store_probe_evidence(res, "tcp53_probe", tcp_summary.get("meta"))
        else:
            _store_probe_repeat_summary(res, "tcp53_probe", {"sample_count": 0, "measured_count": 0, "first": None, "min": None, "latency": None, "max": None, "jitter": None, "status_consistent": None, "status_samples": []})
        _set_probe_observability(res, "tcp53_probe", res["port53t_serv"], res["port53t_probe_lat"])
        res["port53t_lat"] = res["port53t_probe_lat"] or res["port53t_conn_lat"]

        if settings.sleep_time > 0: time.sleep(settings.sleep_time)

        # 3. DNS-Dependent Checks (UDP)
        v_res = dns_engine.query_version(srv) if settings.check_bind_version else None
        if v_res:
            res["version"] = v_res.status if v_res.status != "NOERROR" else (v_res.answers[0] if v_res.answers else "OK")
            res["version_lat"] = _status_latency(res["version"], v_res.latency)
            _set_probe_observability(res, "version", res["version"], res["version_lat"])
            _store_query_evidence(res, "version", v_res)
        else:
            res["version"] = "DISABLED"
            res["version_lat"] = None

        r_res = dns_engine.check_recursion(srv) if settings.enable_recursion_check else None
        if r_res:
             # Logic for recursion: if it's a recursive server, we expect RA or NOERROR answers
            is_rec = r_res.ra or r_res.status == "NOERROR"
            res["recursion"] = "OPEN" if is_rec else "CLOSED"
            res["recursion_lat"] = r_res.latency
            _set_probe_observability(res, "recursion", res["recursion"], res["recursion_lat"])
            _store_query_evidence(res, "recursion", r_res)
        else:
            res["recursion"] = "DISABLED"
            res["recursion_lat"] = None
        
        # Service Validation
        udp_aux_ok = res["version"] not in ["TIMEOUT", "UNREACHABLE", "DISABLED"] or \
                     res["recursion"] not in ["TIMEOUT", "UNREACHABLE", "DISABLED"]
        udp_serv_ok = res["udp53_status_raw"] == "OK" or udp_aux_ok
        udp_timeout_seen = any(status == "TIMEOUT" for status in [res.get("udp53_status_raw"), res.get("version"), res.get("recursion")])
        res["port53u_serv"] = "OK" if udp_serv_ok else ("TIMEOUT" if udp_timeout_seen else "FAIL")
        _set_probe_observability(res, "udp53_probe", res["port53u_serv"], res["udp53_probe_lat"], source="direct")
        
        is_alive = (res["ping"] == "OK") or udp_serv_ok or (res["port53t_serv"] == "OK")
        
        if not is_alive:
            res["is_dead"] = True
            logging.info(f"[PHASE 1] SERVER {srv} IS DEAD (Ping Fail and Services Down)")
            for field in ["version", "recursion", "dot", "doh", "dnssec", "edns0", "open_resolver"]:
                 res[field] = "UNREACHABLE"
            res["port53t_serv"] = "FAIL"
            res["port853_serv"] = "FAIL"
            res["port443_serv"] = "FAIL"
            for field in [
                "version_lat", "recursion_lat", "port53t_probe_lat", "dot_lat", "doh_lat",
                "dnssec_lat", "edns0_lat", "open_resolver_lat", "port853_conn_lat", "port443_conn_lat",
                "ecs_lat", "qname_min_lat", "cookies_lat", "web_risk_lat", "probe_latency_avg"
            ]:
                res[field] = None
            res["web_risk_timings"] = {}
            res["web_risk_status"] = {80: "CLOSED", 443: "CLOSED"}
            for probe_name, probe_status, probe_latency, source in [
                ("udp53_probe", res.get("port53u_serv"), res.get("udp53_probe_lat"), "derived"),
                ("tcp53_connect", res.get("port53t"), res.get("port53t_conn_lat"), "direct"),
                ("tcp53_probe", res.get("port53t_serv"), res.get("port53t_probe_lat"), "direct"),
                ("version", res.get("version"), res.get("version_lat"), "direct"),
                ("recursion", res.get("recursion"), res.get("recursion_lat"), "direct"),
                ("dot_connect", res.get("port853", "CLOSED"), res.get("port853_conn_lat"), "direct"),
                ("dot_probe", res.get("dot"), res.get("dot_lat"), "direct"),
                ("doh_connect", res.get("port443", "CLOSED"), res.get("port443_conn_lat"), "direct"),
                ("doh_probe", res.get("doh"), res.get("doh_lat"), "direct"),
                ("dnssec", res.get("dnssec"), res.get("dnssec_lat"), "direct"),
                ("edns0", res.get("edns0"), res.get("edns0_lat"), "direct"),
                ("open_resolver", res.get("open_resolver"), res.get("open_resolver_lat"), "direct"),
                ("ecs", res.get("ecs"), res.get("ecs_lat"), "direct"),
                ("qname_min", res.get("qname_min"), res.get("qname_min_lat"), "not_applicable"),
                ("cookies", res.get("cookies"), res.get("cookies_lat"), "direct"),
                ("web_risk", "CLOSED", res.get("web_risk_lat"), "multi_port"),
            ]:
                _set_probe_observability(res, probe_name, probe_status, probe_latency, source)
        else:
            ping_display = f"{res['latency']:.1f}ms" if res.get("latency") is not None else "N/A"
            logging.info(f"[PHASE 1] Server {srv} is ALIVE. Latency: {ping_display}, Loss: {res['packet_loss']}%")
            
            # Protocols (DoT/DoH)
            p853_open, p853_slat = conn.check_port(srv, 853)
            res["port853"] = "OPEN" if p853_open else "CLOSED"
            res["port853_conn_lat"] = _latency_or_none(p853_slat)
            _set_probe_observability(res, "dot_connect", res["port853"], res["port853_conn_lat"])
            if p853_open:
                dot_summary = _run_repeated_probe(lambda: dns_engine.check_dot(srv), critical_probe_repeats, {"OK"}) if settings.enable_dot_check else {"status": "DISABLED", "latency": None, "meta": {}}
                res["dot"] = dot_summary["status"]
                res["dot_lat"] = dot_summary["latency"]
                _store_probe_repeat_summary(res, "dot_probe", dot_summary)
                _store_probe_evidence(res, "dot_probe", dot_summary.get("meta"))
            else:
                res["dot"] = "NO"
                res["dot_lat"] = None
            _set_probe_observability(res, "dot_probe", res["dot"], res["dot_lat"])

            p443_open, p443_slat = conn.check_port(srv, 443)
            res["port443"] = "OPEN" if p443_open else "CLOSED"
            res["port443_conn_lat"] = _latency_or_none(p443_slat)
            _set_probe_observability(res, "doh_connect", res["port443"], res["port443_conn_lat"])
            if p443_open:
                doh_summary = _run_repeated_probe(lambda: dns_engine.check_doh(srv), critical_probe_repeats, {"OK"}) if settings.enable_doh_check else {"status": "DISABLED", "latency": None, "meta": {}}
                res["doh"] = doh_summary["status"]
                res["doh_lat"] = doh_summary["latency"]
                _store_probe_repeat_summary(res, "doh_probe", doh_summary)
                _store_probe_evidence(res, "doh_probe", doh_summary.get("meta"))
            else:
                res["doh"] = "NO"
                res["doh_lat"] = None
            _set_probe_observability(res, "doh_probe", res["doh"], res["doh_lat"])
            
            # Advanced Infrastructure Checks
            ds_res = dns_engine.check_dnssec(srv) if settings.enable_dnssec_check else None
            if ds_res:
                res["dnssec"] = "OK" if ds_res.status == "NOERROR" else "FAIL"
                res["dnssec_lat"] = ds_res.latency
                _set_probe_observability(res, "dnssec", res["dnssec"], res["dnssec_lat"])
                _store_query_evidence(res, "dnssec", ds_res)
            else:
                res["dnssec"] = "DISABLED"

            edns_res = dns_engine.check_edns0(srv) if settings.enable_edns_check else None
            if edns_res:
                res["edns0"] = "OK" if edns_res.status == "NOERROR" else "FAIL"
                res["edns0_lat"] = edns_res.latency
                _set_probe_observability(res, "edns0", res["edns0"], res["edns0_lat"])
                _store_query_evidence(res, "edns0", edns_res)
            else:
                res["edns0"] = "DISABLED"
            
            open_summary = _run_repeated_probe(lambda: dns_engine.check_open_resolver(srv), critical_probe_repeats, {"OPEN", "REFUSED", "NO_RECURSION", "SERVFAIL"}) if settings.enable_recursion_check else {"status": "DISABLED"}
            res["open_resolver"] = open_summary["status"]
            res["open_resolver_lat"] = open_summary.get("latency")
            res.update(classify_open_resolver(res["open_resolver"]))
            _set_probe_observability(res, "open_resolver", res["open_resolver"], res["open_resolver_lat"])
            _store_probe_repeat_summary(res, "open_resolver", open_summary)
            _store_probe_evidence(res, "open_resolver", open_summary.get("meta"))
            
            # Privacy & Advanced Protocol Checks
            ecs_res = dns_engine.check_ecs_support(srv) if settings.enable_ecs_check else None
            if ecs_res:
                res["ecs"] = ecs_res.status == "NOERROR" # Simplified logic
                res["ecs_lat"] = ecs_res.latency
                _set_probe_observability(res, "ecs", "OK" if res["ecs"] else "NO", res["ecs_lat"])
            else:
                res["ecs"] = None
                res["ecs_lat"] = None

            if settings.enable_qname_min_check and res["server_profile"] in {"recursive", "mixed"}:
                qm_res = dns_engine.check_qname_minimization(srv, rd=True)
                res["qname_min"] = qm_res.status == "NOERROR"
                res["qname_min_lat"] = qm_res.latency
                res["qname_min_confidence"] = "LOW"
            else:
                res["qname_min"] = None
                res["qname_min_lat"] = None
                res["qname_min_confidence"] = "NONE"
            _set_probe_observability(res, "qname_min", res["qname_min"], res["qname_min_lat"])

            cook_res = dns_engine.check_dns_cookies(srv) if settings.enable_dns_cookies_check else None
            if cook_res:
                res["cookies"] = cook_res.status == "NOERROR"
                res["cookies_lat"] = cook_res.latency
                _set_probe_observability(res, "cookies", "OK" if res["cookies"] else "NO", res["cookies_lat"])
            else:
                 res["cookies"] = None
                 res["cookies_lat"] = None

            if settings.enable_web_risk_check:
                wr_risks, wr_timings = dns_engine.check_web_risk(srv)
                res["web_risks"] = wr_risks
                res["web_risk_timings"] = wr_timings
                # Calculate a rough latency for web risk check if needed, though it's multi-port
                valid_web_times = [t for t in wr_timings.values() if t is not None]
                res["web_risk_lat"] = max(valid_web_times) if valid_web_times else None
            else:
                res["web_risks"] = []
                res["web_risk_lat"] = None
            _set_probe_observability(res, "web_risk", "OPEN" if res["web_risks"] else "CLOSED", res["web_risk_lat"])

        with lock:
            infra_results[srv] = res
            active_items.pop(srv, None)
            counters['done'] += 1
            ui.print_progress(counters['done'], total, "Scanning Servers", status_suffix=watchdog_state["status"])

    counters = {'done': 0}
    total = len(servers)
    stop_event, watcher, watchdog_state = start_phase_watchdog("Scanning Servers", counters, total, active_items, lock, log_enabled=settings.enable_execution_log)
    with concurrent.futures.ThreadPoolExecutor(max_workers=settings.max_threads) as executor:
        list(executor.map(_check_server, servers))
    stop_event.set()
    watcher.join(timeout=settings.watchdog_join_timeout)
        
    # Calculate individual scores
    for srv in infra_results:
        infra_results[srv]['infrastructure_score'] = calculate_server_score(infra_results[srv], settings)

    # Phase 1 summary counters are needed by the terminal snapshot and analytics.
    alive = sum(1 for r in infra_results.values() if not r['is_dead'])
    dead = len(infra_results) - alive

    ui.print_phase_snapshot(
        "Phase 1 Snapshot",
        [
            ("Servers", len(infra_results)),
            ("Alive", alive),
            ("Dead", dead),
            ("Public recursion", sum(1 for r in infra_results.values() if r.get("resolver_exposed") is True)),
            ("Encrypted DNS", sum(1 for r in infra_results.values() if r.get("dot") == "OK" or r.get("doh") == "OK"))
        ],
        interpretation="Use this block to understand coverage before reading the detailed rows."
    )

    # Order results by group then by server IP
    sorted_infra = sorted(infra_results.items(), key=lambda x: (x[1].get('groups', ''), x[0]))
    ui.print_phase_header("1: Server Infrastructure")
    for srv, res in sorted_infra:
        if settings.enable_execution_log:
            logging.info(
                "[PHASE 1] INFRA DETAIL: Server=%s, Score=%s, Ping=%s, UDP=%s, TCP=%s, DoT=%s, DoH=%s, Resolver=%s, Risks=%s",
                srv,
                res.get('infrastructure_score', 0),
                res.get('ping'),
                res.get('port53u_serv'),
                res.get('port53t_serv'),
                res.get('dot'),
                res.get('doh'),
                res.get('classification'),
                res.get('web_risks', []),
            )
        ui.print_infra_detail(srv, res)
        
    # Phase Summary
    # Phase 1 Analytics
    insights = {}
    if alive > 0:
        # Aggregated Health Index
        avg_health = sum(r.get('infrastructure_score', 0) for r in infra_results.values() if not r['is_dead']) / alive
        insights["Infrastructure Health"] = f"{avg_health:.1f}% (Global Index)"
        
        # Protocol Adoption
        dot_ok = sum(1 for r in infra_results.values() if r.get('dot') == "OK")
        doh_ok = sum(1 for r in infra_results.values() if r.get('doh') == "OK")
        sec_ok = sum(1 for r in infra_results.values() if r.get('dnssec') == "OK")
        cook_ok = sum(1 for r in infra_results.values() if r.get('cookies') is True)
        
        adoption = ((dot_ok + doh_ok + sec_ok + cook_ok) / (alive * 4)) * 100
        insights["Protocol Adoption"] = f"{adoption:.1f}% (Modern Stack)"
        
        # Network Health vs SLAs using all measured transport/service timings, not just ping.
        all_probe_latencies = []
        for row in infra_results.values():
            if row.get("is_dead"):
                continue
            all_probe_latencies.extend(_collect_available_latencies(
                row.get("latency"),
                row.get("udp53_probe_lat"),
                row.get("version_lat"),
                row.get("recursion_lat"),
                row.get("port53t_conn_lat"),
                row.get("port53t_probe_lat"),
                row.get("port853_conn_lat"),
                row.get("dot_lat"),
                row.get("port443_conn_lat"),
                row.get("doh_lat"),
                row.get("dnssec_lat"),
                row.get("edns0_lat"),
                row.get("open_resolver_lat"),
                row.get("ecs_lat"),
                row.get("qname_min_lat"),
                row.get("cookies_lat"),
                row.get("web_risk_lat"),
            ))
        if all_probe_latencies:
            avg_probe_lat = sum(all_probe_latencies) / len(all_probe_latencies)
            sla_health = max(0, 100 - (avg_probe_lat / settings.ping_latency_warn * 50))
            insights["Network Health"] = f"{sla_health:.1f}% ({_format_probe_basis(all_probe_latencies)})"
        else:
            insights["Network Health"] = "N/A (no successful latency probes)"
        repeated_probe_names = ["udp53_probe", "tcp53_probe", "dot_probe", "doh_probe", "open_resolver"]
        stability_flags = []
        jitter_values = []
        for row in infra_results.values():
            if row.get("is_dead"):
                continue
            for probe_name in repeated_probe_names:
                sample_count = row.get(f"{probe_name}_sample_count", 0) or 0
                status_consistent = row.get(f"{probe_name}_status_consistent")
                if sample_count >= 2 and status_consistent is not None:
                    stability_flags.append(1 if status_consistent else 0)
                jitter = row.get(f"{probe_name}_latency_jitter")
                if jitter is not None:
                    jitter_values.append(jitter)
        if stability_flags:
            stability_pct = (sum(stability_flags) / len(stability_flags)) * 100
            insights["Transport Stability"] = f"{stability_pct:.1f}% ({sum(stability_flags)}/{len(stability_flags)} stable repeated probes)"
        else:
            insights["Transport Stability"] = "N/A (no repeated probe samples)"
        if jitter_values:
            insights["Probe Jitter"] = f"{(sum(jitter_values) / len(jitter_values)):.1f}ms average across {len(jitter_values)} repeated probes"
        else:
            insights["Probe Jitter"] = "N/A (insufficient repeated latency samples)"
        avg_probe_coverage = sum(r.get("probe_coverage_ratio", 0.0) for r in infra_results.values() if not r.get("is_dead")) / alive
        insights["Probe Coverage"] = f"{avg_probe_coverage:.1f}% ({sum(r.get('measured_probe_count', 0) for r in infra_results.values() if not r.get('is_dead'))} measured probes)"

        transport_scores = []
        control_plane_scores = []
        exposure_scores = []
        observability_scores = []

        for row in infra_results.values():
            if row.get("is_dead"):
                continue

            transport_checks = []
            udp_ok = row.get("port53u_serv") == "OK"
            tcp_ok = row.get("port53t_serv") == "OK"
            transport_checks.append(1 if udp_ok == tcp_ok else 0)

            if row.get("port853") == "CLOSED":
                transport_checks.append(1 if row.get("dot") == "NO" else 0)
            else:
                transport_checks.append(1 if row.get("dot") in {"OK", "FAIL", "TIMEOUT", "DISABLED"} else 0)

            if row.get("port443") == "CLOSED":
                transport_checks.append(1 if row.get("doh") == "NO" else 0)
            else:
                transport_checks.append(1 if row.get("doh") in {"OK", "FAIL", "TIMEOUT", "DISABLED"} else 0)

            transport_scores.append((sum(transport_checks) / len(transport_checks)) * 100 if transport_checks else 0)

            control_checks = [
                1 if row.get("dnssec") == "OK" else 0,
                1 if row.get("edns0") == "OK" else 0,
                1 if row.get("cookies") is True else 0,
            ]
            if row.get("server_profile") in {"recursive", "mixed"}:
                control_checks.append(1 if row.get("qname_min") is True else 0)
                control_checks.append(1 if row.get("ecs") is False else 0)
            control_plane_scores.append((sum(control_checks) / len(control_checks)) * 100 if control_checks else 0)

            exposure_checks = [
                1 if row.get("resolver_exposed") is not True else 0,
                1 if not row.get("web_risks") else 0,
            ]
            exposure_scores.append((sum(exposure_checks) / len(exposure_checks)) * 100 if exposure_checks else 0)

            repeatability_checks = []
            for probe_name in ["udp53_probe", "tcp53_probe", "dot_probe", "doh_probe", "open_resolver"]:
                stable = row.get(f"{probe_name}_status_consistent")
                sample_count = row.get(f"{probe_name}_sample_count", 0) or 0
                if sample_count >= 2 and stable is not None:
                    repeatability_checks.append(1 if stable else 0)
            repeatability_score = ((sum(repeatability_checks) / len(repeatability_checks)) * 100) if repeatability_checks else None
            coverage_score = row.get("probe_coverage_ratio", 0.0) or 0.0
            if repeatability_score is None:
                observability_scores.append(coverage_score)
            else:
                observability_scores.append((coverage_score + repeatability_score) / 2)

        if transport_scores:
            insights["Transport Consistency"] = f"{(sum(transport_scores) / len(transport_scores)):.1f}% (UDP/TCP/Encrypted alignment)"
        else:
            insights["Transport Consistency"] = "N/A (no alive servers)"

        if control_plane_scores:
            insights["Control Plane Health"] = f"{(sum(control_plane_scores) / len(control_plane_scores)):.1f}% (DNSSEC, EDNS, cookies, privacy controls)"
        else:
            insights["Control Plane Health"] = "N/A (no alive servers)"

        if exposure_scores:
            insights["Exposure Posture"] = f"{(sum(exposure_scores) / len(exposure_scores)):.1f}% (resolver restriction and web exposure)"
        else:
            insights["Exposure Posture"] = "N/A (no alive servers)"

        if observability_scores:
            insights["Observability Quality"] = f"{(sum(observability_scores) / len(observability_scores)):.1f}% (coverage plus repeated probe stability)"
        else:
            insights["Observability Quality"] = "N/A (no alive servers)"

    phase_duration = time.time() - phase_start_time
    insights["Execution Time"] = f"{phase_duration:.2f}s"
    insights["Total Servers"] = len(infra_results)
    insights["Status Alive"] = alive
    insights["Status Dead"] = dead

    if settings.enable_ui_legends:
        ui.print_legend_phase1_table()

    ui.print_phase_footer("1: Infrastructure", 
                         {"Total Servers": len(infra_results), "Status Alive": alive, "Status Dead": dead}, 
                         phase_duration, 
                         insights)
    
    if settings.enable_execution_log and insights:
        logging.info(f"[PHASE 1] ANALYTICS: {insights}")

    if settings.enable_ui_legends:
        ui.print_legend_phase1_analytics()

    return infra_results, insights

def run_phase2_zones(domains_raw, dns_groups, dns_engine, settings, infra_cache, lock):
    """Phase 2: Zone Integrity & SOA Synchronization."""
    ui.print_phase("2: Zone Integrity", "Checking SOA visibility, authority, synchronization, transfer exposure, and policy signals.")
    phase_start_time = time.time()
    zone_results = []
    active_items = {}
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
        with lock:
            active_items[domain] = "zone"
        local_results = []
        serials = {}
        timers_list = []
        dnssec_status = []
        web_risks = {}
        mname_target = None

        for srv, group_name in srv_group_tuples:
            srv = srv.strip()
            infra = infra_cache.get(srv)
            if not infra:
                # ADAPTIVE FALLBACK: If Phase 1 was skipped, derive what we can from groups.csv
                group_meta = dns_groups.get(group_name, {})
                infra = {
                    "server": srv,
                    "is_dead": False,
                    "server_profile": group_meta.get("type", "recursive"),
                    "web_risks": [],
                    "recursion": "OPEN" if group_meta.get("type") == "recursive" else "CLOSED",
                    "dnssec": "OK" # Assume OK for probe purposes
                }

            phase2_repeats = settings.phase2_probe_repeats
            # Determine recursion based on specific group type for THIS server
            is_recursive = dns_groups.get(group_name, {}).get("type") == "recursive"
            
            if infra.get("is_dead"):
                res = {
                    "domain": domain, "server": srv, "group": group_name, 
                    "serial": "N/A", "axfr_vulnerable": False, "axfr_detail": "PH1 FAIL", 
                    "status": "UNREACHABLE", "is_dead": True,
                    "caa_records": [], "web_risks": infra.get("web_risks", []), "dnssec": None,
                    "latency": None, "ns_list": [], "check_scope": "SKIPPED", "mname": "N/A", "rname": "N/A",
                    "soa_latency": None, "soa_fallback_latency": None, "ns_latency": None,
                    "axfr_latency": None, "caa_latency": None, "zone_dnssec_latency": None,
                    "scope_confidence": "NONE", "used_fallback": False,
                }
                local_results.append(res); serials[srv] = "N/A"
                continue

            try:
                # Harmonized recursion logic matching Phase 3
                soa, soa_repeat = _run_repeated_query(lambda: dns_engine.query(srv, domain, "SOA", rd=is_recursive), phase2_repeats, {"NOERROR", "NXDOMAIN"})
                soa_repeat["status"] = soa.status
                soa_repeat["latency"] = _status_latency(soa.status, soa_repeat.get("latency"), {"NOERROR", "NXDOMAIN"})
                
                # Smart Fallback: if preferred RD fails, try the alternative
                soa_fallback_latency = None
                used_fallback = False
                if soa.status not in ["NOERROR", "NXDOMAIN"]:
                    soa_fallback = dns_engine.query(srv, domain, "SOA", rd=not is_recursive)
                    if soa_fallback.status == "NOERROR" or (soa_fallback.status == "NXDOMAIN" and soa.status != "NXDOMAIN"):
                        soa_fallback_latency = soa_fallback.latency
                        soa = soa_fallback
                        used_fallback = True

                # Robust extraction: check answers + authority
                records = soa.answers + soa.authority
                # Look specifically for the SOA record line
                soa_rec = None
                for r in records:
                    p = r.split()
                    if "SOA" in p:
                        soa_rec = r
                        break
                if not soa_rec and records:
                    # Fallback for some non-standard string representations
                    soa_rec = next((r for r in records if len(r.split()) >= 7), records[0])
                
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
                
                aa = soa.aa
                latency = soa.latency
                
                # Reuse server-level web exposure from phase 1 when available.
                risks = infra.get("web_risks", [])
                web_risks[srv] = risks

                if soa.status != "NOERROR":
                    row = {
                        "domain": domain,
                        "server": srv,
                        "group": group_name,
                        "serial": serial,
                        "mname": mname,
                        "rname": rname,
                        "axfr_vulnerable": False,
                        "axfr_detail": f"SKIPPED ({soa.status})",
                        "status": soa.status,
                        "aa": aa,
                        "latency": latency,
                        "soa_latency": latency,
                        "soa_fallback_latency": soa_fallback_latency,
                        "ns_latency": None,
                        "axfr_latency": None,
                        "caa_latency": None,
                        "zone_dnssec_latency": None,
                        "ns_list": [],
                        "soa_latency_warn": settings.soa_latency_warn,
                        "soa_latency_crit": settings.soa_latency_crit,
                        "axfr_allowed_groups": settings.axfr_allowed_groups,
                        "web_risks": risks,
                        "dnssec": None,
                        "caa_records": [],
                        "is_dead": False,
                        "check_scope": "SOA_ONLY",
                        "scope_confidence": "LOW",
                        "used_fallback": used_fallback,
                    }
                    _store_query_evidence(row, "soa", soa)
                    _store_probe_repeat_summary(row, "soa", soa_repeat)
                    local_results.append(row)
                    serials[srv] = serial
                    continue

                # DNSSEC Check
                ds_res = dns_engine.check_zone_dnssec(srv, domain) if settings.enable_zone_dnssec_check else None
                is_signed = False
                zone_dnssec_latency = None
                if ds_res:
                    is_signed = ds_res.status == "NOERROR"
                    zone_dnssec_latency = ds_res.latency
                    dnssec_status.append(is_signed)

                # NS Check (Check answers and authority for referrals)
                ns_q, ns_repeat = _run_repeated_query(lambda: dns_engine.query(srv, domain, "NS", rd=is_recursive), phase2_repeats, {"NOERROR", "NXDOMAIN"})
                ns_repeat["status"] = ns_q.status
                ns_latency = _status_latency(ns_q.status, ns_repeat.get('latency'))
                
                ns_records = ns_q.answers + ns_q.authority
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
                
                axfr_ok, axfr_msg, axfr_latency = dns_engine.check_axfr(srv, domain) if settings.enable_axfr_check else (False, "DISABLED", None)
                logging.info(f"[PHASE 2] Zone {domain} on {srv}: SOA Serial: {serial}, AXFR: {axfr_ok} ({axfr_msg})")
                
                caa_res = dns_engine.validate_caa(srv, domain, rd=is_recursive) if settings.enable_caa_check else None
                caa_recs = []
                caa_latency = None
                if caa_res:
                    caa_recs = caa_res.answers
                    caa_latency = caa_res.latency
                logging.info(f"[PHASE 2] Zone {domain} on {srv}: CAA Records: {len(caa_recs)}")
                
                res = {
                    "domain": domain, "server": srv, "group": group_name,
                    "serial": serial, "mname": mname, "rname": rname,
                    "axfr_vulnerable": axfr_ok, "axfr_detail": axfr_msg, "status": soa.status,
                    "aa": aa, "latency": latency, "ns_list": ns_list,
                    "soa_latency": latency, "soa_fallback_latency": soa_fallback_latency,
                    "ns_latency": ns_latency, "axfr_latency": axfr_latency,
                    "caa_latency": caa_latency, "zone_dnssec_latency": zone_dnssec_latency,
                    "soa_latency_warn": settings.soa_latency_warn,
                    "soa_latency_crit": settings.soa_latency_crit,
                    "axfr_allowed_groups": settings.axfr_allowed_groups,
                    "web_risks": risks,
                    "dnssec": is_signed,
                    "caa_records": caa_recs,
                    "is_dead": False,
                    "check_scope": "FULL",
                    "scope_confidence": "MEDIUM" if used_fallback else "HIGH",
                    "used_fallback": used_fallback,
                }
                _store_query_evidence(res, "soa", soa)
                _store_probe_repeat_summary(res, "soa", soa_repeat)
                _store_query_evidence(res, "ns", ns_q)
                _store_probe_repeat_summary(res, "ns", ns_repeat)
                if caa_res: _store_query_evidence(res, "caa", caa_res)
                if ds_res: _store_query_evidence(res, "zone_dnssec", ds_res)
                local_results.append(res)
            except Exception as e:
                logging.exception(f"[PHASE 2] Error checking zone {domain} on {srv}")
                local_results.append({
                    "domain": domain, "server": srv, "group": group_name,
                    "serial": "?", "status": f"ERROR: {str(e)}", "axfr_vulnerable": False,
                    "axfr_detail": "ERROR", "caa_records": [], "web_risks": infra.get("web_risks", []),
                    "dnssec": None, "latency": None, "ns_list": [], "check_scope": "ERROR",
                    "soa_latency": None, "soa_fallback_latency": None, "ns_latency": None,
                    "axfr_latency": None, "caa_latency": None, "zone_dnssec_latency": None,
                    "mname": "N/A", "rname": "N/A", "scope_confidence": "NONE", "used_fallback": False
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
            if len(set(timers_list)) > 1:
                audit["timers_ok"] = False
                audit["timers_issues"].append("Inconsistent timers across servers")
            
            ref, ret, exp, mn = timers_list[0]
            rfc_ok, rfc_issues = dns_engine.analyze_soa_timers(ref, ret, exp, mn)
            if not rfc_ok:
                audit["timers_ok"] = False
                audit["timers_issues"].extend(rfc_issues)

        if mname_target:
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
            active_items.pop(domain, None)
            counters['done'] += 1
            ui.print_progress(counters['done'], total, "Checking Zones", status_suffix=watchdog_state["status"])

    counters = {'done': 0}
    total = len(zones)
    stop_event, watcher, watchdog_state = start_phase_watchdog("Checking Zones", counters, total, active_items, lock, log_enabled=settings.enable_execution_log)
    with concurrent.futures.ThreadPoolExecutor(max_workers=settings.max_threads) as executor:
        futures = [executor.submit(_check_zone, dom, srvs) for dom, srvs in zones.items()]
        concurrent.futures.wait(futures)
    stop_event.set()
    watcher.join(timeout=settings.watchdog_join_timeout)
        
    # Calculate individual scores
    for r in zone_results:
        r['zone_score'] = calculate_zone_score(r, settings)

    # Final sorted print
    ui.print_phase_snapshot(
        "Phase 2 Snapshot",
        [
            ("Domains", len(zones)),
            ("Zone checks", len(zone_results)),
            ("SOA-only", sum(1 for r in zone_results if r.get("check_scope") == "SOA_ONLY")),
            ("AXFR exposed", sum(1 for r in zone_results if r.get("axfr_vulnerable"))),
            ("Desynced domains", len({r["domain"] for r in zone_results if r.get("zone_is_synced") is False}))
        ],
        interpretation="Focus first on desynchronized domains and any unexpected AXFR exposure."
    )
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
            
        if settings.enable_execution_log:
            logging.info(
                "[PHASE 2] ZONE DETAIL: Domain=%s, Server=%s, Score=%s, Status=%s, Scope=%s, Synced=%s, NS-Consistent=%s",
                res['domain'],
                res['server'],
                res.get('zone_score', 0),
                res.get('status'),
                res.get('check_scope'),
                res.get('zone_is_synced'),
                res.get('ns_consistent'),
            )
        ui.print_zone_detail(res['server'], res['domain'], res)
    
    # Print audit block for the LAST domain
    if sorted_zones:
        last_res = sorted_zones[-1]
        ui.print_zone_audit_block(last_res['domain'], last_res.get('zone_audit', {}))
        
    # Phase Summary
    vuln = sum(1 for r in zone_results if r['axfr_vulnerable'])
    lame = sum(1 for r in zone_results if not r.get('aa', True) and r.get('status') == "NOERROR")
    inconsistent_ns = sum(1 for r in zone_results if r.get('ns_list') and len(set(tuple(r2.get('ns_list', [])) for r2 in zone_results if r2['domain'] == r['domain'])) > 1)
    
    # Phase 2 Analytics
    total_checks = len(zone_results)
    synced_domains = set()
    for domain in zones:
        domain_rows = [r for r in zone_results if r['domain'] == domain]
        successful_rows = [r for r in domain_rows if r.get('status') == "NOERROR"]
        if successful_rows and all(r.get('zone_is_synced') for r in successful_rows):
            synced_domains.add(domain)
    
    insights = {}
    if total_checks > 0:
        # Aggregated Health Index
        avg_compliance = sum(r.get('zone_score', 0) for r in zone_results) / total_checks
        insights["Zone Compliance"] = f"{avg_compliance:.1f}% (Global Index)"
        
        sync_health = (len(synced_domains) / len(zones)) * 100 if zones else 0
        insights["Sync Health"] = f"{sync_health:.1f}% (Zones fully synchronized)"
        
        ca_adoption = sum(1 for r in zone_results if len(r.get('caa_records', [])) > 0)
        insights["CAA Adoption"] = f"{(ca_adoption / total_checks) * 100:.1f}% (SSL Policy)"
        zone_probe_latencies = []
        for row in zone_results:
            zone_probe_latencies.extend(_collect_available_latencies(
                row.get("soa_latency"),
                row.get("soa_fallback_latency"),
                row.get("ns_latency"),
                row.get("axfr_latency"),
                row.get("caa_latency"),
                row.get("zone_dnssec_latency"),
            ))
        if zone_probe_latencies:
            avg_zone_latency = sum(zone_probe_latencies) / len(zone_probe_latencies)
            insights["Zone Response Health"] = f"{max(0, 100 - (avg_zone_latency / settings.soa_latency_warn * 50)):.1f}% ({_format_probe_basis(zone_probe_latencies)})"
        else:
            insights["Zone Response Health"] = "N/A (no successful zone probe timings)"

        authority_scores = []
        transfer_scores = []
        hygiene_scores = []
        repeatability_scores = []
        fallback_count = 0
        confidence_scores = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}

        for row in zone_results:
            if row.get("used_fallback"):
                fallback_count += 1
            confidence = row.get("scope_confidence", "NONE")
            confidence_scores[confidence] = confidence_scores.get(confidence, 0) + 1

            authority_checks = []
            if row.get("status") == "NOERROR":
                authority_checks.append(1 if row.get("aa") else 0)
                authority_checks.append(1 if row.get("zone_is_synced") else 0)
                ns_consistent = row.get("ns_consistent")
                if ns_consistent is not None:
                    authority_checks.append(1 if ns_consistent else 0)
                authority_checks.append(1 if row.get("mname") not in {"N/A", "?"} else 0)
            if authority_checks:
                authority_scores.append((sum(authority_checks) / len(authority_checks)) * 100)

            transfer_checks = []
            allowed_groups = row.get("axfr_allowed_groups", [])
            current_group = str(row.get("group", "")).upper()
            expected_transfer = any(g in current_group for g in allowed_groups) if allowed_groups else False
            if row.get("axfr_vulnerable"):
                transfer_checks.append(100 if expected_transfer else 0)
            else:
                detail = str(row.get("axfr_detail", "")).upper()
                if "REFUSED" in detail or "REJECTED" in detail:
                    transfer_checks.append(100 if not expected_transfer else 60)
                elif "TIMEOUT" in detail:
                    transfer_checks.append(40)
                elif "DISABLED" in detail:
                    transfer_checks.append(50)
                else:
                    transfer_checks.append(35)
            transfer_scores.extend(transfer_checks)

            hygiene_checks = []
            if row.get("dnssec") is not None:
                hygiene_checks.append(1 if row.get("dnssec") else 0)
            hygiene_checks.append(1 if len(row.get("caa_records", [])) > 0 else 0)
            audit = row.get("zone_audit", {})
            hygiene_checks.append(1 if audit.get("timers_ok") else 0)
            mname_reachable = str(audit.get("mname_reachable", ""))
            hygiene_checks.append(1 if "(UP)" in mname_reachable else 0)
            hygiene_checks.append(1 if not row.get("web_risks") else 0)
            if hygiene_checks:
                hygiene_scores.append((sum(hygiene_checks) / len(hygiene_checks)) * 100)

            for probe_name in ["soa", "ns"]:
                sample_count = row.get(f"{probe_name}_sample_count", 0) or 0
                stable = row.get(f"{probe_name}_status_consistent")
                if sample_count >= 2 and stable is not None:
                    repeatability_scores.append(100 if stable else 0)

        if authority_scores:
            insights["Authority Integrity"] = f"{(sum(authority_scores) / len(authority_scores)):.1f}% (AA, sync, NS, MNAME integrity)"
        else:
            insights["Authority Integrity"] = "N/A (insufficient authoritative observations)"
        if transfer_scores:
            insights["Transfer Exposure Posture"] = f"{(sum(transfer_scores) / len(transfer_scores)):.1f}% (AXFR behavior versus expectation)"
        else:
            insights["Transfer Exposure Posture"] = "N/A (no AXFR observations)"
        if hygiene_scores:
            insights["Zone Hygiene"] = f"{(sum(hygiene_scores) / len(hygiene_scores)):.1f}% (DNSSEC, CAA, timers, MNAME, web exposure)"
        else:
            insights["Zone Hygiene"] = "N/A (no hygiene observations)"
        insights["Fallback Dependency"] = f"{(fallback_count / total_checks) * 100:.1f}% ({fallback_count}/{total_checks} rows used fallback)" if total_checks else "N/A"
        insights["Scope Confidence"] = (
            f"H:{confidence_scores.get('HIGH', 0)} M:{confidence_scores.get('MEDIUM', 0)} "
            f"L:{confidence_scores.get('LOW', 0)} N:{confidence_scores.get('NONE', 0)}"
        )
        if repeatability_scores:
            insights["Zone Stability"] = f"{(sum(repeatability_scores) / len(repeatability_scores)):.1f}% (SOA/NS repeated status stability)"
        else:
            insights["Zone Stability"] = "N/A (no repeated SOA/NS samples)"

    phase_duration = time.time() - phase_start_time
    if settings.enable_ui_legends:
        ui.print_legend_phase2_table()

    ui.print_phase_footer("2: Zones", {
        "Domains Tested": len(zones),
        "Lame Delegations": lame,
        "NS Inconsistencies": inconsistent_ns // 2 if inconsistent_ns > 0 else 0
    }, phase_duration, insights)

    if settings.enable_execution_log and insights:
        logging.info(f"[PHASE 2] ANALYTICS: {insights}")

    if settings.enable_ui_legends:
        ui.print_legend_phase2_analytics()

    return zone_results, insights

def run_phase3_records(tasks, dns_engine, dns_groups, settings, infra_cache, results, lock):
    """Phase 3: Parallel Record Consistency Check."""
    ui.print_phase("3: Record Consistency", "Repeating record lookups to detect divergence, dangling targets, and policy anomalies.")
    phase_start_time = time.time()
    counters = {'done': 0}
    total = len(tasks)
    active_items = {}
    
    def _worker(target, group_name, server, record_types):
        task_label = f"{target}@{server}"
        with lock:
            active_items[task_label] = group_name
        try:
            # Circuit Breaker
            infra = infra_cache.get(server)
            if not infra:
                # ADAPTIVE FALLBACK: Handle missing infra cache if Phase 1 was skipped
                group_meta = dns_groups.get(group_name, {})
                infra = {
                    "server": server,
                    "is_dead": False,
                    "server_profile": group_meta.get("type", "recursive"),
                    "recursion": "OPEN" if group_meta.get("type") == "recursive" else "CLOSED"
                }

            if infra.get("is_dead"):
                local_res = [{
                    "domain": target, "group": group_name, "server": server, "type": rtype,
                    "status": "UNREACHABLE", "latency": None, "ping": "FAIL", "port53": "CLOSED",
                    "version": "DEAD", "recursion": "DEAD", "dot": "DEAD", "doh": "DEAD",
                    "nsid": None, "internally_consistent": "N/A", "answers": "SKIPPED: SERVER DOWN",
                    "is_consistent": True,
                    "latency_first": None, "latency_avg": None, "latency_min": None, "latency_max": None,
                    "chain_latency": None, "mx_port25_latency": None, "wildcard_latency": None
                } for rtype in record_types if rtype.strip()]
                with lock:
                    results.extend(local_res)
                    active_items.pop(task_label, None)
                    counters['done'] += 1
                    ui.print_progress(counters['done'], total, "Record Consistency", status_suffix=watchdog_state["status"])
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
                query_latencies = [q.latency for q in queries if q.latency is not None]
                chain_latencies = []
                mx_port25_latencies = []
                
                # SEMANTIC AUDIT
                findings = []
                
                # 0. Protocol Flags (TC - Truncated)
                if main_q.tc:
                    findings.append("Truncated response (TC bit set) - Suggests Large Packets/MTU issues")
                
                # 1. TTL Analysis (Using first answer's TTL as representative)
                if main_q.ttl > 0:
                     _, ttl_msg = validators.analyze_ttl(main_q.ttl, 
                                                       min_val=settings.ttl_min_threshold, 
                                                       max_val=settings.ttl_max_threshold)
                     if ttl_msg != "OK":
                         findings.append(ttl_msg)

                # 2. Record Specific Syntax/Chain checks
                spf_list = [a for a in main_q.answers if rtype == "TXT" and "v=spf1" in a]
                dmarc_list = [a for a in main_q.answers if rtype == "TXT" and "v=DMARC1" in a]
                
                if spf_list:
                    _, spf_issues = validators.validate_spf(spf_list, lookup_limit=settings.spf_lookup_limit)
                    findings.extend(spf_issues)
                    
                if dmarc_list:
                    _, dmarc_issues = validators.validate_dmarc(dmarc_list)
                    findings.extend(dmarc_issues)

                for ans in main_q.answers:
                    # Dangling DNS (CNAME / MX)
                    if rtype in ["CNAME", "MX"]:
                        # Extract target (MX has priority first)
                        parts = ans.split()
                        target_host = parts[1] if rtype == "MX" and len(parts) > 1 else ans.rstrip('.')
                        chain_ok, chain_msg, chain_latency = dns_engine.resolve_chain(server, target_host, rtype, rd=is_recursive)
                        if chain_latency is not None:
                            chain_latencies.append(chain_latency)
                        if not chain_ok:
                            findings.append(f"Dangling {rtype} target: {target_host} ({chain_msg})")
                        else:
                            # MX Target Port 25 Check
                            if rtype == "MX":
                                 mx_ok, mx_port25_latency = dns_engine.check_port_25(target_host, port=settings.smtp_port)
                                 if mx_port25_latency is not None:
                                     mx_port25_latencies.append(mx_port25_latency)
                                 if not mx_ok:
                                     findings.append(f"MX Target {target_host} UNREACHABLE on Port 25 (SMTP)")

                entry = {
                    "domain": target, "group": group_name, "server": server, "type": rtype,
                    "status": main_q.status, "latency": _status_latency(main_q.status, main_q.latency),
                    "latency_first": _status_latency(main_q.status, main_q.latency),
                    "latency_avg": round(sum(query_latencies) / len(query_latencies), 2) if query_latencies else None,
                    "latency_min": round(min(query_latencies), 2) if query_latencies else None,
                    "latency_max": round(max(query_latencies), 2) if query_latencies else None,
                    "ping": infra.get("ping", "N/A"), "port53": infra.get("port53u", "N/A"),
                    "version": infra.get("version", "N/A"), "recursion": infra.get("recursion", "N/A"),
                    "dot": infra.get("dot", "N/A"), "doh": infra.get("doh", "N/A"),
                    "nsid": main_q.nsid, "internally_consistent": "YES" if is_consistent else "DIV!",
                    "answers": ", ".join(main_q.answers),
                    "is_consistent": is_consistent,
                    "findings": findings,
                    "chain_latency": round(sum(chain_latencies) / len(chain_latencies), 2) if chain_latencies else None,
                    "mx_port25_latency": round(sum(mx_port25_latencies) / len(mx_port25_latencies), 2) if mx_port25_latencies else None,
                    "wildcard_detected": False,
                    "wildcard_answers": [],
                    "wildcard_scope": "ZONE",
                    "wildcard_latency": None
                }
                _store_query_evidence(entry, "main", main_q)
                local_res.append(entry)
            
            with lock:
                results.extend(local_res)
                active_items.pop(task_label, None)
                counters['done'] += 1
                ui.print_progress(counters['done'], total, "Record Consistency", status_suffix=watchdog_state["status"])
        except Exception as e:
            logging.exception(f"[PHASE 3] Execution error for {target} @ {server}")
            with lock:
                results.append({"domain": target, "group": group_name, "server": server, "type": "ERROR", "status": str(e), "latency": None, "is_consistent": False})
                active_items.pop(task_label, None)
                counters['done'] += 1
                ui.print_progress(counters['done'], total, "Record Consistency", status_suffix=watchdog_state["status"])

    counters = {'done': 0}
    total = len(tasks)
    
    stop_event, watcher, watchdog_state = start_phase_watchdog("Record Consistency", counters, total, active_items, lock, log_enabled=settings.enable_execution_log)
    with concurrent.futures.ThreadPoolExecutor(max_workers=settings.max_threads) as executor:
        futures = [executor.submit(_worker, *t) for t in tasks]
        concurrent.futures.wait(futures)
    stop_event.set()
    watcher.join(timeout=0.1)

    # Post-collection sorting and printing
    ui.print_phase_snapshot(
        "Phase 3 Snapshot",
        [
            ("Queries", len(results)),
            ("Successful", sum(1 for r in results if r['status'] == "NOERROR")),
            ("Divergent", sum(1 for r in results if r.get("internally_consistent") == "DIV!")),
            ("Findings", sum(1 for r in results if r.get("findings")))
        ],
        interpretation="Treat divergence as context-sensitive; repeated findings across the same domain/server deserve priority."
    )
    ui.print_phase_header("3: Record Consistency")
    
    # Sort results
    sorted_results = sorted(results, key=lambda x: (x['domain'], x['group'], x['server']))
    
    wildcard_cache = {}
    for r in sorted_results:
        current_zone_srv = (r['domain'], r['server'])
        if current_zone_srv in wildcard_cache:
            continue
        if r['status'] == "NOERROR":
            is_recursive = dns_groups.get(r['group'], {}).get("type") == "recursive"
            wildcard_cache[current_zone_srv] = dns_engine.detect_wildcard(r['server'], r['domain'], rd=is_recursive)
        else:
            wildcard_cache[current_zone_srv] = (False, [], None)

    reported_wildcards = set()
    for r in sorted_results:
        current_zone_srv = (r['domain'], r['server'])
        has_wc, wc_ans, wc_latency = wildcard_cache.get(current_zone_srv, (False, [], None))
        r["wildcard_detected"] = has_wc
        r["wildcard_answers"] = wc_ans or []
        r["wildcard_latency"] = wc_latency

        print(ui.format_result(
            r['domain'], r['group'], r['server'], r['type'], r['status'], r['latency'], r['is_consistent'],
            warn_ms=settings.rec_latency_warn, crit_ms=settings.rec_latency_crit
        ))
        ui.print_record_context(r)
        
        # Print semantic findings
        if r.get('findings'):
            ui.print_record_findings(r['findings'])
            
        if has_wc and current_zone_srv not in reported_wildcards:
            reported_wildcards.add(current_zone_srv)
            ui.print_record_findings([f"Zone-level wildcard detected: random subdomains resolved to {wc_ans}"])
    
    # Phase 3 Analytics
    succ = sum(1 for r in results if r['status'] == "NOERROR")
    fail = len(results) - succ
    
    insights = {}
    if len(results) > 0:
        stable = sum(1 for r in results if r.get('is_consistent') is True)
        insights["Stability Index"] = f"{(stable / len(results)) * 100:.1f}% (No DIV!)"
        
        findings_total = sum(len(r.get('findings', [])) for r in results)
        insights["Finding Density"] = f"{findings_total / len(results):.2f} issues/query"
        measured_record_latencies = [r.get("latency_avg") for r in results if r.get("latency_avg") is not None]
        if measured_record_latencies:
            avg_record_latency = sum(measured_record_latencies) / len(measured_record_latencies)
            insights["Record Response Health"] = f"{max(0, 100 - (avg_record_latency / settings.rec_latency_warn * 50)):.1f}% ({avg_record_latency:.1f}ms avg)"
        jitter_values = [
            (r.get("latency_max") - r.get("latency_min"))
            for r in results
            if r.get("latency_max") is not None and r.get("latency_min") is not None
        ]
        if jitter_values:
            insights["Jitter Index"] = f"{(sum(jitter_values) / len(jitter_values)):.1f}ms avg spread"

    phase_duration = time.time() - phase_start_time
    if settings.enable_ui_legends:
        ui.print_legend_phase3_table()

    ui.print_phase_footer("3: Record Consistency", {"Total Queries": len(results), "Success": succ, "Failures": fail}, phase_duration, insights)

    if settings.enable_execution_log and insights:
        logging.info(f"[PHASE 3] ANALYTICS: {insights}")

    if settings.enable_ui_legends:
        ui.print_legend_phase3_analytics()

    return results, insights

def calculate_server_score_breakdown(res, settings):
    """Return profile-aware total/security/privacy scoring for a server."""
    if res.get('is_dead'):
        return {"total": 0, "security": 0, "privacy": 0, "privacy_applicable": False}

    profile = res.get("server_profile", "unknown")
    security_raw = 0
    privacy_raw = 0
    privacy_applicable = profile in {"recursive", "mixed"}

    if res.get('dnssec') == "OK":
        security_raw += settings.weight_dnssec
    if res.get('cookies') is True:
        security_raw += settings.weight_cookies
    if res.get('edns0') == "OK":
        security_raw += settings.weight_edns0
    if res.get('resolver_restricted') is True:
        security_raw += settings.weight_restricted
    if not res.get('web_risks'):
        security_raw += settings.weight_web_safe

    if profile == "authoritative":
        if res.get('port53u_serv') == "OK":
            security_raw += settings.weight_port53_u
        if res.get('port53t_serv') == "OK":
            security_raw += settings.weight_port53_t
        security_score = min(security_raw, 100)
        total_score = security_score
    else:
        if res.get('dot') == "OK":
            privacy_raw += settings.weight_dot
        if res.get('doh') == "OK":
            privacy_raw += settings.weight_doh
        if res.get('qname_min') is True:
            privacy_raw += settings.weight_qname_min
        if res.get('ecs') is False:
            privacy_raw += settings.weight_ecs_masking
        
        # Security score for recursives is normalized against 80 (since port53_u/t aren't added)
        security_score = int((security_raw / 80) * 100)
        privacy_score = min(privacy_raw, 100)
        total_score = int((security_score + privacy_score) / 2)

    return {
        "total": min(total_score, 100),
        "security": min(security_score, 100),
        "privacy": min(privacy_score if privacy_applicable else 0, 100),
        "privacy_applicable": privacy_applicable
    }

def calculate_server_score(res, settings):
    """Calculate a 0-100 score for a single server infrastructure."""
    return calculate_server_score_breakdown(res, settings)["total"]

def calculate_zone_score(res, settings):
    """Calculate a 0-100 score for a single zone-on-server result."""
    if res.get('status') != "NOERROR": return 0
    
    s = 0
    # Sync & Identity
    if res.get('zone_is_synced'): s += settings.weight_zone_sync
    if res.get('aa'): s += settings.weight_zone_aa
    
    # Security Policies
    if not res.get('axfr_vulnerable'): s += settings.weight_zone_no_axfr
    if len(res.get('caa_records', [])) > 0: s += settings.weight_zone_caa
    
    audit = res.get('zone_audit', {})
    if audit.get('dnssec'): s += settings.weight_zone_dnssec
    
    return s

def calculate_scores(infra_results, zone_results, settings):
    """Calculate aggregated Security and Privacy scores for global summary."""
    if not infra_results:
        return None, None
    
    total_sec = 0
    total_priv = 0
    sec_count = 0
    priv_count = 0
    
    for srv, res in infra_results.items():
        breakdown = calculate_server_score_breakdown(res, settings)

        security_score = breakdown["security"]
        vuln_axfr = any(z['axfr_vulnerable'] for z in zone_results if z['server'] == srv)
        if not vuln_axfr:
            security_score = min(security_score + 10, 100)
        has_caa = any(len(z.get('caa_records', [])) > 0 for z in zone_results if z['server'] == srv)
        if has_caa:
            security_score = min(security_score + 5, 100)

        total_sec += security_score
        sec_count += 1

        if breakdown["privacy_applicable"]:
            total_priv += breakdown["privacy"]
            priv_count += 1
        
    sec_avg = int(total_sec / sec_count) if sec_count else None
    priv_avg = int(total_priv / priv_count) if priv_count else None
    return sec_avg, priv_avg

def build_terminal_takeaways(infra_results, zone_results, results, security_available, privacy_available):
    takeaways = []
    public_resolvers = sum(1 for r in infra_results.values() if r.get("resolver_exposed") is True)
    if public_resolvers:
        takeaways.append(f"{public_resolvers} server(s) showed public recursion exposure.")

    desynced_domains = len({z["domain"] for z in zone_results if z.get("zone_is_synced") is False})
    if desynced_domains:
        takeaways.append(f"{desynced_domains} domain(s) showed SOA desynchronization across tested servers.")

    finding_count = sum(1 for r in results if r.get("findings"))
    if finding_count:
        takeaways.append(f"{finding_count} record result(s) contained semantic findings worth review.")

    wildcard_pairs = len({(r["domain"], r["server"]) for r in results if r.get("wildcard_detected")})
    if wildcard_pairs:
        takeaways.append(f"{wildcard_pairs} zone/server pair(s) showed wildcard behavior.")

    if not privacy_available and security_available:
        takeaways.append("Privacy score was not applicable because no recursive-profile servers were fully evaluated.")

    if not takeaways:
        takeaways.append("No immediate high-priority issue was surfaced in this execution.")
    return takeaways

def main():
    script_start_time = time.time()
    settings = Settings()
    log_file = setup_logging(settings)
    
    if settings.enable_execution_log:
        logging.info(f"Configuration loaded from {settings.path}")
        logging.info(f"Max Threads: {settings.max_threads}, Consistency Checks: {settings.consistency_checks}")

    parser = argparse.ArgumentParser(
        description=f"FriendlyDNSReporter - Professional Suite (v{VERSION})\n"
                    "WARNING: Use at your own risk. If your DNS explodes, don't blame us.\n"
                    "Based on factual data, but subject to divine network intervention and creative firewalls.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-n", "--domains", default=settings.file_domains, help=f"Domains CSV (default: {settings.file_domains})")
    parser.add_argument("-g", "--groups", default=settings.file_groups, help=f"Groups CSV (default: {settings.file_groups})")
    parser.add_argument("-o", "--output", default=settings.log_dir, help="Output DIR")
    parser.add_argument("-p", "--phases", help="Select phases to run (e.g. 1,3 or 2)")
    parser.add_argument("--install-missing-deps", action="store_true", help="Allow automatic installation of missing Python dependencies")
    args = parser.parse_args()

    missing_packages = _get_missing_dependencies()
    _handle_missing_dependencies(missing_packages, auto_install=args.install_missing_deps)
    _log_bootstrap_messages(settings.enable_execution_log)

    global urllib3, DNSEngine, Connectivity, Reporter, validators, ui
    import urllib3
    from core.dns_engine import DNSEngine
    from core.connectivity import Connectivity
    from core.reporting import Reporter
    import core.validators as validators
    import core.ui as ui

    # Silence DoH/DoT HTTPS warnings only after dependency checks and imports succeed.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Process phase selection
    run_p1 = settings.enable_phase_server
    run_p2 = settings.enable_phase_zone
    run_p3 = settings.enable_phase_record
    
    if args.phases:
        selected = [p.strip() for p in args.phases.split(',')]
        run_p1 = "1" in selected
        run_p2 = "2" in selected
        run_p3 = "3" in selected

    ui.print_banner(VERSION)
    ui.print_disclaimer()
    ui.print_header(settings.max_threads, settings.consistency_checks, os.path.basename(args.domains))
    
    domains_raw, dns_groups = load_datasets(args.domains, args.groups)
    if not domains_raw or not dns_groups:
        err_msg = "Datasets missing or empty. Execution aborted."
        print(f"[{ui.FAIL}ERROR{ui.RESET}] {err_msg}")
        if settings.enable_execution_log: logging.error(err_msg)
        sys.exit(1)

    if settings.enable_execution_log:
        logging.info(f"Datasets loaded: {len(domains_raw)} domains, {len(dns_groups)} groups defined.")

    dns_engine = DNSEngine(timeout=settings.dns_timeout, tries=settings.dns_retries)
    conn = Connectivity(timeout=settings.timeout, ping_timeout=settings.ping_timeout)
    lock = threading.Lock()
    
    # Identify which groups are actually used in domains.csv
    active_groups = set()
    for d in domains_raw:
        if d.get('GROUPS'):
            active_groups.update([g.strip().upper() for g in d['GROUPS'].split(',')])
    
    # Collect servers and create a reverse mapping
    all_servers = set()
    srv_to_groups = {}
    srv_to_types = {}
    for group, g_meta in dns_groups.items():
        if settings.only_test_active_groups and group not in active_groups:
            continue
        if group in active_groups or not settings.only_test_active_groups:
            all_servers.update(g_meta["servers"])
            for s in g_meta["servers"]:
                if s not in srv_to_groups: srv_to_groups[s] = []
                srv_to_groups[s].append(group)
                if s not in srv_to_types:
                    srv_to_types[s] = set()
                srv_to_types[s].add(g_meta.get("type", "recursive"))
    
    # Format groups as strings
    for s in srv_to_groups:
        srv_to_groups[s] = ", ".join(srv_to_groups[s])
    srv_profiles = {s: derive_server_profile(types) for s, types in srv_to_types.items()}

    infra_cache = {}
    
    # Run Phase 1: Infrastructure
    p1_insights = {}
    if run_p1:
        infra_cache, p1_insights = run_phase1_infrastructure(all_servers, srv_to_groups, srv_profiles, conn, dns_engine, settings, lock)

    # Run Phase 2: Zones
    zone_results = []
    p2_insights = {}
    if run_p2:
        zone_results, p2_insights = run_phase2_zones(domains_raw, dns_groups, dns_engine, settings, infra_cache, lock)

    # Run Phase 3: Records
    results = []
    p3_insights = {}
    if run_p3:
        tasks = []
        for entry in domains_raw:
            groups = (entry.get('GROUPS') or '').split(',')
            target = entry.get('DOMAIN')
            if target:
                for group in groups:
                    group = group.strip().upper()
                    if group in dns_groups:
                        for server in dns_groups[group]["servers"]:
                            tasks.append((target, group, server, (entry.get('RECORDS') or '').split(',')))
        results, p3_insights = run_phase3_records(tasks, dns_engine, dns_groups, settings, infra_cache, results, lock)

    # Final Analytics Calculation
    sec_score, priv_score = calculate_scores(infra_cache, zone_results, settings)
    security_available = sec_score is not None
    privacy_available = priv_score is not None
    scores_available = security_available and privacy_available
    avg_score = ((sec_score + priv_score) / 2) if scores_available else (sec_score if security_available else None)
    grade = (
        ui.format_grade(avg_score)
        .replace("\033[92m", "")
        .replace("\033[91m", "")
        .replace("\033[93m", "")
        .replace("\033[0m", "")
        if avg_score is not None else "N/A"
    )
    final_summary = {
        "total_queries": len(results),
        "success_queries": sum(1 for r in results if r.get('status') == "NOERROR"),
        "divergences": sum(1 for r in results if r.get('internally_consistent') == "DIV!"),
        "zone_sync_issues": len({
            z["domain"] for z in zone_results
            if z.get("status") != "NOERROR" or z.get("zone_is_synced") is False
        }),
        "security_score": score_label(sec_score),
        "privacy_score": score_label(priv_score),
        "security_score_available": security_available,
        "privacy_score_available": privacy_available,
        "scores_available": scores_available,
        "global_grade": grade,
        "execution_time_s": round(time.time() - script_start_time, 2),
        "timestamp": datetime.now().isoformat()
    }

    # Reporting & Summary
    import platform
    reporter = Reporter(args.output)
    
    report_data = {
        "metadata": {
            "version": VERSION,
            "timestamp": final_summary["timestamp"],
            "arguments": vars(args),
            "system_info": {
                "os": platform.system(),
                "os_release": platform.release(),
                "python_version": sys.version.split()[0]
            },
            "config": {
                "max_threads": settings.max_threads,
                "consistency_checks": settings.consistency_checks,
                "output_directory": args.output
            }
        },
        "summary": final_summary, 
        "analytics": {
            "phase1_infrastructure": p1_insights,
            "phase2_zones": p2_insights,
            "phase3_records": p3_insights
        },
        "detailed_results": {
            "infrastructure": infra_cache, 
            "zones": zone_results, 
            "records": results
        }
    }
    
    suffix = f"_{datetime.now().strftime('%Y%m%d_%H%M')}" if settings.enable_report_timestamps else ""
    
    paths = {}
    # Ensure JSON is generated if HTML is enabled (as HTML now depends on it)
    if settings.enable_json_report or settings.enable_html_report:
        paths["JSON"] = reporter.export_json(report_data, f"report{suffix}.json")

    if settings.enable_text_report:
        paths["TXT"] = reporter.export_text(report_data, f"report{suffix}.txt")
    
    if settings.enable_csv_report:
        # 1. Details Phase 1 (Infrastructure)
        infra_list = []
        for srv, data in infra_cache.items():
            row = {"server": srv}
            row.update(data)
            infra_list.append(row)
        if infra_list:
            paths["CSV_INFRA"] = reporter.export_csv(infra_list, f"details_phase1_infrastructure{suffix}.csv", list(infra_list[0].keys()))
            
        # 2. Details Phase 2 (Zones)
        if zone_results:
            # Flatten zone_audit if exists
            zone_csv_data = []
            for z in zone_results:
                row = z.copy()
                audit = row.pop('zone_audit', {})
                for k, v in audit.items(): row[f"audit_{k}"] = v
                zone_csv_data.append(row)
            paths["CSV_ZONES"] = reporter.export_csv(zone_csv_data, f"details_phase2_zones{suffix}.csv", list(zone_csv_data[0].keys()))

        # 3. Details Phase 3 (Records)
        if results:
            paths["CSV_RECORDS"] = reporter.export_csv(results, f"details_phase3_records{suffix}.csv", list(results[0].keys()))

        # 4-7. Summaries
        if p1_insights: paths["CSV_SUM_P1"] = reporter.export_csv([p1_insights], f"summary_phase1{suffix}.csv", list(p1_insights.keys()))
        if p2_insights: paths["CSV_SUM_P2"] = reporter.export_csv([p2_insights], f"summary_phase2{suffix}.csv", list(p2_insights.keys()))
        if p3_insights: paths["CSV_SUM_P3"] = reporter.export_csv([p3_insights], f"summary_phase3{suffix}.csv", list(p3_insights.keys()))
        paths["CSV_SUM_FINAL"] = reporter.export_csv([final_summary], f"summary_final{suffix}.csv", list(final_summary.keys()))

    if settings.enable_html_report: 
        # Scan for existing JSON reports in the same directory for history visualization
        json_path = paths.get("JSON")
        history_files = []
        if json_path:
            json_dir = os.path.dirname(json_path)
            if os.path.exists(json_dir):
                history_files = [f for f in os.listdir(json_dir) if f.lower().endswith(".json")]
        
        html_context = {
            "dataset_name": os.path.basename(args.domains),
            "report_file": os.path.basename(json_path) if json_path else f"report{suffix}.json",
            "history_files": history_files
        }
        paths["HTML"] = reporter.generate_html(html_context, f"dashboard{suffix}.html")
    
    # Filter out empty paths
    paths = {k: v for k, v in paths.items() if v}
    if settings.enable_execution_log:
        for label, path in paths.items():
            logging.info(f"Report Generated [{label}]: {path}")
    
    total = len(results)
    success = sum(1 for r in results if r['status'] == "NOERROR")
    div = sum(1 for r in results if r.get('internally_consistent') == "DIV!")
    sync_issues = len({
        z["domain"] for z in zone_results
        if z.get("status") != "NOERROR" or z.get("zone_is_synced") is False
    })
    script_duration = time.time() - script_start_time
    
    sec_score, priv_score = calculate_scores(infra_cache, zone_results, settings)
    security_available = sec_score is not None
    privacy_available = priv_score is not None
    scores_available = security_available and privacy_available
    avg_score = ((sec_score + priv_score) / 2) if scores_available else (sec_score if security_available else None)
    grade = (
        ui.format_grade(avg_score)
        .replace("\033[92m", "")
        .replace("\033[91m", "")
        .replace("\033[93m", "")
        .replace("\033[0m", "")
        if avg_score is not None else "N/A"
    )
    
    takeaways = build_terminal_takeaways(infra_cache, zone_results, results, security_available, privacy_available)

    if settings.enable_execution_log:
        score_display = f"{avg_score:.1f}%" if scores_available else "N/A"
        logging.info(f"FINAL SUMMARY: Total={total}, Success={success}, Divergences={div}, ZoneIssues={sync_issues}")
        logging.info(f"FORENSIC SCORES: Security={score_label(sec_score)}, Privacy={score_label(priv_score)}, Grade={grade} ({score_display})")
        logging.info(f"Execution Time: {script_duration:.2f}s")
        logging.info("=============================================================================")
        logging.info("FRIENDLY DNS REPORTER FINISHED")
        logging.info("=============================================================================")


    ui.print_summary_table(
        total,
        success,
        total-success,
        div,
        sync_issues,
        paths,
        script_duration,
        sec_score if sec_score is not None else 0,
        priv_score if priv_score is not None else 0,
        settings.enable_ui_legends,
        scores_available=scores_available,
        security_available=security_available,
        privacy_available=privacy_available,
        show_security=settings.enable_security_score,
        show_privacy=settings.enable_privacy_score,
        takeaways=takeaways
    )

if __name__ == "__main__":
    main()
