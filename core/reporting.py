import json
import csv
from jinja2 import Environment, FileSystemLoader
import os
import re

class Reporter:
    def __init__(self, output_dir="logs"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def export_json(self, data, filename):
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        
        # Update index
        if not filename.startswith("reports_index"):
            self.update_index(filename)
            
        return path

    def update_index(self, new_report):
        index_path = os.path.join(self.output_dir, "reports_index.json")
        index = {"reports": []}
        
        if os.path.exists(index_path):
            try:
                with open(index_path, 'r', encoding='utf-8') as f:
                    index = json.load(f)
            except:
                pass
        
        if new_report not in index["reports"]:
            index["reports"].append(new_report)
            # Keep latest reports first for the dashboard selector default.
            index["reports"].sort(reverse=True)
            
            with open(index_path, 'w', encoding='utf-8') as f:
                json.dump(index, f, indent=4)

    def export_csv(self, data, filename, fieldnames):
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=';')
            writer.writeheader()
            writer.writerows(data)
        return path

    def export_text(self, report_data, filename):
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self._build_text_report(report_data))
        return path

    def generate_html(self, context, filename, template_name="dashboard.html"):
        path = os.path.join(self.output_dir, filename)
        
        # Setup Jinja2 environment to load from core/templates
        base_dir = os.path.dirname(os.path.dirname(__file__))
        template_dir = os.path.join(base_dir, 'core', 'templates')
        
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template(template_name)
        
        html_content = template.render(context)
            
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return path

    def _build_text_report(self, report_data):
        summary = report_data.get("summary", {})
        metadata = report_data.get("metadata", {})
        analytics = report_data.get("analytics", {})
        snapshots = report_data.get("snapshots", {})
        details = report_data.get("detailed_results", {})
        infra = details.get("infrastructure", {})
        zones = details.get("zones", [])
        records = details.get("records", [])

        def clean(value):
            text = re.sub(r"\x1b\[[0-9;]*m", "", str(value))
            return text

        def add_section(title, rows=None):
            lines.append(f"\n[ {title.upper()} ]")
            lines.append("=" * 80)
            if rows:
                lines.extend(rows)
            else:
                lines.append("No data available.")

        def fmt_bool(value):
            if value is True: return "YES"
            if value is False: return "NO"
            return "N/E"

        def fmt_latency(value):
            if value is None or value == "": return "N/A"
            return f"{clean(value)}ms"

        def fmt_amplification(q, r):
            if q and r:
                ratio = r / q
                return f"{ratio:.1f}x"
            return "N/A"

        def fmt_probe_evidence(item, probe_name, label=None):
            label = label or probe_name
            protocol = item.get(f"{probe_name}_protocol")
            rcode = item.get(f"{probe_name}_rcode")
            flags = item.get(f"{probe_name}_flags") or []
            q_size = item.get(f"{probe_name}_query_size")
            r_size = item.get(f"{probe_name}_response_size")
            aa = item.get(f"{probe_name}_aa")
            ra = item.get(f"{probe_name}_ra")
            ad = item.get(f"{probe_name}_ad")
            
            details = []
            if protocol: details.append(f"proto={clean(protocol)}")
            if rcode: details.append(f"rcode={clean(rcode)}")
            if flags: details.append(f"flags={clean(','.join(map(str, flags[:4])))}")
            if q_size is not None and r_size is not None:
                details.append(f"amp={fmt_amplification(q_size, r_size)}({q_size}B->{r_size}B)")
            if aa is not None: details.append(f"aa={'Y' if aa else 'N'}")
            if ra is not None: details.append(f"ra={'Y' if ra else 'N'}")
            if ad is not None: details.append(f"ad={'Y' if ad else 'N'}")
            
            if not details: return f"{label}=N/A"
            return f"{label}=" + ",".join(details)

        def fmt_probe_repeat(item, probe_name, label=None):
            label = label or probe_name
            sample_count = item.get(f"{probe_name}_sample_count", 0) or 0
            if sample_count <= 0: return f"{label}=N/E"
            avg_lat = fmt_latency(item.get(f"{probe_name}_latency_avg"))
            min_lat = fmt_latency(item.get(f"{probe_name}_latency_min"))
            max_lat = fmt_latency(item.get(f"{probe_name}_latency_max"))
            jitter = fmt_latency(item.get(f"{probe_name}_latency_jitter"))
            stable = item.get(f"{probe_name}_status_consistent")
            stable_str = "stable" if stable is True else ("flap" if stable is False else "n/e")
            return f"{label}={sample_count}x {stable_str} [{min_lat}/{avg_lat}/{max_lat}] j={jitter}"

        def fmt_insights(ins_dict):
            if not ins_dict: return []
            return [f"  [i] {k:25}: {clean(v)}" for k, v in ins_dict.items()]

        def fmt_snapshot(snap_list):
            if not snap_list: return ""
            return " | ".join([f"{k}: {v}" for k, v in snap_list])

        lines = [
            "FRIENDLY DNS REPORTER",
            "=" * 80,
            f"V: {clean(metadata.get('version', 'N/A'))} | TS: {clean(summary.get('timestamp', 'N/A'))}",
            f"OS: {clean(metadata.get('system_info', {}).get('os', 'N/A'))} | PY: {clean(metadata.get('system_info', {}).get('python_version', 'N/A'))}",
            "=" * 80
        ]

        # Executive Snapshot
        snapshot_rows = [
            f"├─ Grade: {clean(summary.get('global_grade', 'N/A'))}",
            f"├─ Security: {clean(summary.get('security_score', 'N/A'))}",
            f"├─ Privacy: {clean(summary.get('privacy_score', 'N/A'))}",
            f"├─ Response Health: {clean(summary.get('success_queries', 0))}/{clean(summary.get('total_queries', 0))} OK",
            f"└─ Risk Signals: {clean(summary.get('zone_sync_issues', 0))} Desync, {clean(summary.get('divergences', 0))} Div!",
        ]
        
        takeaways = analytics.get("takeaways", [])
        if takeaways:
            snapshot_rows.append("\n[ EXECUTIVE TAKEAWAYS ]")
            snapshot_rows.append("-" * 30)
            for t in takeaways:
                snapshot_rows.append(f" {clean(t)}")
        
        breakdown = analytics.get("score_breakdown", [])
        if breakdown:
            snapshot_rows.append("\n[ SCORING BREAKDOWN ]")
            snapshot_rows.append("-" * 30)
            for item in breakdown:
                snapshot_rows.append(f" {clean(item)}")

        add_section("Executive Snapshot", snapshot_rows)

        # Phase 1: Infrastructure
        infra_rows = []
        if snapshots.get("phase1"):
            infra_rows.append(f"SNAPSHOT: {fmt_snapshot(snapshots['phase1'])}")
            infra_rows.append("-" * 40)
        
        if analytics.get("phase1_infrastructure"):
            infra_rows.extend(fmt_insights(analytics["phase1_infrastructure"]))
            infra_rows.append("-" * 40)

        for srv, item in sorted(infra.items()):
            alive = "ALIVE" if not item.get('is_dead') else "DEAD"
            infra_rows.append(f"▶ Server: {srv} [{clean(item.get('groups', 'N/A'))}] ({alive})")
            infra_rows.append(f"  ├─ Profile: {clean(item.get('server_profile', 'unknown'))}")
            infra_rows.append(f"  ├─ Network: Ping={fmt_latency(item.get('latency'))} | UDP53={fmt_latency(item.get('udp53_probe_lat'))} | TCP53={fmt_latency(item.get('port53t_probe_lat'))}")
            infra_rows.append(f"  ├─ Security: Score={clean(item.get('infrastructure_score', 'N/A'))} | Res={clean(item.get('classification', 'N/A'))} | DoT={clean(item.get('dot', 'N/A'))} | DoH={clean(item.get('doh', 'N/A'))}")
            infra_rows.append(f"  ├─ Evidence: {fmt_probe_evidence(item, 'dnssec', 'DNSSEC')}")
            infra_rows.append(f"  └─ Repeat: {fmt_probe_repeat(item, 'udp53_probe', 'UDP53')}")
        add_section("Phase 1: Infrastructure", infra_rows)

        # Phase 2: Zones
        zone_rows = []
        if snapshots.get("phase2"):
            zone_rows.append(f"SNAPSHOT: {fmt_snapshot(snapshots['phase2'])}")
            zone_rows.append("-" * 40)
        
        if analytics.get("phase2_zones"):
            zone_rows.extend(fmt_insights(analytics["phase2_zones"]))
            zone_rows.append("-" * 40)

        for item in sorted(zones, key=lambda z: (z.get("domain", ""), z.get("server", ""))):
            audit = item.get("zone_audit", {})
            synced = "SYNC" if item.get('zone_is_synced') else "DESYNC"
            zone_rows.append(f"▶ Zone: {clean(item.get('domain'))} @ {clean(item.get('server'))} ({synced})")
            zone_rows.append(f"  ├─ SOA: {clean(item.get('status'))} | Serial={clean(item.get('serial'))} | Lat={fmt_latency(item.get('latency'))}")
            
            # SOA Timers Table
            timers = item.get("soa_timers", {})
            if timers:
                t_row = f"  ├─ Timers: Ref={timers.get('refresh')} Ret={timers.get('retry')} Exp={timers.get('expire')} Min={timers.get('min_ttl')}"
                if audit.get("timers_ok") is False:
                    t_row += " [!] POLICY RISK"
                zone_rows.append(t_row)
            
            zone_rows.append(f"  ├─ Policy: AA={fmt_bool(item.get('aa'))} | AXFR={clean(item.get('axfr_detail'))} | DNSSEC={fmt_bool(item.get('dnssec'))} | CAA={len(item.get('caa_records', []))}")
            zone_rows.append(f"  └─ Evidence: {fmt_probe_evidence(item, 'soa', 'SOA')} | {fmt_probe_evidence(item, 'ns', 'NS')}")
        add_section("Phase 2: Zones", zone_rows)

        # Phase 3: Records
        record_rows = []
        if snapshots.get("phase3"):
            record_rows.append(f"SNAPSHOT: {fmt_snapshot(snapshots['phase3'])}")
            record_rows.append("-" * 40)
        
        if analytics.get("phase3_records"):
            record_rows.extend(fmt_insights(analytics["phase3_records"]))
            record_rows.append("-" * 40)

        for item in sorted(records, key=lambda r: (r.get("domain", ""), r.get("server", ""), r.get("type", ""))):
            consistent = "OK" if item.get('is_consistent') else "DIV!"
            record_rows.append(f"▶ Record: {clean(item.get('domain'))} [{clean(item.get('type'))}] @ {clean(item.get('server'))} ({consistent})")
            record_rows.append(f"  ├─ Result: {clean(item.get('status'))} | LatAvg={fmt_latency(item.get('latency_avg'))} | Answers: {clean(item.get('answers', ''))}")
            
            # Detailed evidence
            amp = fmt_amplification(item.get('query_size'), item.get('response_size'))
            ad_flag = "AD+" if item.get('ad') else "AD-"
            record_rows.append(f"  ├─ Telemetry: {ad_flag} | Amp={amp} | Q={item.get('query_size')}B R={item.get('response_size')}B")
            
            if item.get("findings"):
                for finding in item["findings"]:
                    record_rows.append(f"  ├─ [!] {clean(finding)}")
            
            if item.get("wildcard_detected"):
                record_rows.append(f"  └─ [!] Wildcard Resolved: {clean(' | '.join(item.get('wildcard_answers', [])))}")
            else:
                record_rows.append(f"  └─ Verification: ChainLat={fmt_latency(item.get('chain_latency'))} | Jitter={fmt_latency(item.get('latency_jitter'))}")
        add_section("Phase 3: Records", record_rows)

        return "\n".join(lines) + "\n"
