import json
import csv
from jinja2 import Environment, FileSystemLoader
import os
import re


def _serialize_value(value):
    """Convert lists/dicts to CSV-safe strings; pass scalars through."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, (list, tuple)):
        return " | ".join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return value


def _prepare_csv_row(row):
    """Return a copy of a dict with all values serialized for CSV."""
    return {k: _serialize_value(v) for k, v in row.items()}

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
            for row in data:
                writer.writerow(_prepare_csv_row(row))
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

        def fmt_val(value):
            """Format any value for text output: list→pipe-separated, dict→JSON, bool/None→readable."""
            if value is None: return "N/A"
            if isinstance(value, bool): return str(value)
            if isinstance(value, (list, tuple)):
                return " | ".join(str(clean(v)) for v in value) if value else "[]"
            if isinstance(value, dict):
                return json.dumps(value, ensure_ascii=False)
            return str(clean(value))

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
            authority_count = item.get(f"{probe_name}_authority_count")
            answer_count = item.get(f"{probe_name}_answer_count")
            aa = item.get(f"{probe_name}_aa")
            tc = item.get(f"{probe_name}_tc")
            http_status = item.get(f"{probe_name}_http_status")
            ra = item.get(f"{probe_name}_ra")

            details_list = []
            if protocol: details_list.append(f"proto={clean(protocol)}")
            if rcode: details_list.append(f"rcode={clean(rcode)}")
            if flags: details_list.append(f"flags={clean(','.join(map(str, flags[:4])))}")
            if q_size is not None: details_list.append(f"q={q_size}B")
            if r_size is not None: details_list.append(f"r={r_size}B")
            if authority_count is not None: details_list.append(f"auth={authority_count}")
            if answer_count is not None: details_list.append(f"answers={answer_count}")
            if aa is not None: details_list.append(f"aa={'Y' if aa else 'N'}")
            if tc is not None: details_list.append(f"tc={'Y' if tc else 'N'}")
            if http_status is not None: details_list.append(f"http={http_status}")
            if ra is not None: details_list.append(f"ra={'Y' if ra else 'N'}")

            if not details_list: return f"{label}=N/A"
            return f"{label}=" + ",".join(details_list)

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
            samples = item.get(f"{probe_name}_status_samples", [])
            return f"{label}={sample_count}x {stable_str} [{min_lat}/{avg_lat}/{max_lat}] j={jitter} samples={fmt_val(samples)}"

        def fmt_insights(ins_dict):
            if not ins_dict: return []
            return [f"  [i] {k:25}: {clean(v)}" for k, v in ins_dict.items()]

        def fmt_snapshot(snap_list):
            if not snap_list: return ""
            return " | ".join([f"{k}: {v}" for k, v in snap_list])

        def fmt_dict_full(d, prefix="  ", exclude_keys=None):
            """Format ALL fields of a dict as indented key=value lines."""
            exclude = set(exclude_keys or [])
            out = []
            for k, v in d.items():
                if k in exclude:
                    continue
                out.append(f"{prefix}{k}: {fmt_val(v)}")
            return out

        lines = [
            "FRIENDLY DNS REPORTER",
            "=" * 80,
            f"V: {clean(metadata.get('version', 'N/A'))} | TS: {clean(summary.get('timestamp', 'N/A'))}",
            f"OS: {clean(metadata.get('system_info', {}).get('os', 'N/A'))} | PY: {clean(metadata.get('system_info', {}).get('python_version', 'N/A'))}",
            "=" * 80
        ]

        # ── Executive Snapshot ──────────────────────────────────────────────
        snapshot_rows = [
            f"├─ Grade: {clean(summary.get('global_grade', 'N/A'))}",
            f"├─ Security: {clean(summary.get('security_score', 'N/A'))}",
            f"├─ Privacy: {clean(summary.get('privacy_score', 'N/A'))}",
            f"├─ Scores Available: {clean(summary.get('scores_available', 'N/A'))}",
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

        # ── Phase 1: Infrastructure (100% coverage) ─────────────────────────
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

            # Connection & Ping
            infra_rows.append(f"  ├─ ping: {fmt_val(item.get('ping'))}")
            infra_rows.append(f"  ├─ latency: {fmt_latency(item.get('latency'))}")
            infra_rows.append(f"  ├─ latency_min: {fmt_latency(item.get('latency_min'))}")
            infra_rows.append(f"  ├─ latency_max: {fmt_latency(item.get('latency_max'))}")
            infra_rows.append(f"  ├─ packet_loss: {fmt_val(item.get('packet_loss'))}")
            infra_rows.append(f"  ├─ ping_count: {fmt_val(item.get('ping_count'))}")
            infra_rows.append(f"  ├─ ping_latency_warn: {fmt_val(item.get('ping_latency_warn'))}")
            infra_rows.append(f"  ├─ ping_latency_crit: {fmt_val(item.get('ping_latency_crit'))}")
            infra_rows.append(f"  ├─ ping_loss_warn: {fmt_val(item.get('ping_loss_warn'))}")
            infra_rows.append(f"  ├─ ping_loss_crit: {fmt_val(item.get('ping_loss_crit'))}")

            # Port & Service status
            infra_rows.append(f"  ├─ port53u: {fmt_val(item.get('port53u'))}")
            infra_rows.append(f"  ├─ port53u_serv: {fmt_val(item.get('port53u_serv'))}")
            infra_rows.append(f"  ├─ udp53_status_raw: {fmt_val(item.get('udp53_status_raw'))}")
            infra_rows.append(f"  ├─ udp53_probe_lat: {fmt_latency(item.get('udp53_probe_lat'))}")
            infra_rows.append(f"  ├─ port53t: {fmt_val(item.get('port53t'))}")
            infra_rows.append(f"  ├─ port53t_serv: {fmt_val(item.get('port53t_serv'))}")
            infra_rows.append(f"  ├─ port53t_conn_lat: {fmt_latency(item.get('port53t_conn_lat'))}")
            infra_rows.append(f"  ├─ port53t_probe_lat: {fmt_latency(item.get('port53t_probe_lat'))}")
            infra_rows.append(f"  ├─ port53t_lat: {fmt_latency(item.get('port53t_lat'))}")

            # Repeated probes
            for pn in ["udp53_probe", "tcp53_probe", "dot_probe", "doh_probe", "open_resolver"]:
                infra_rows.append(f"  ├─ {pn}: {fmt_probe_repeat(item, pn)}")

            # Evidence for each probe
            for pn in ["udp53_probe", "tcp53_probe", "version", "recursion", "dot_probe", "doh_probe",
                        "dnssec", "edns0", "open_resolver", "ecs", "qname_min", "cookies"]:
                infra_rows.append(f"  ├─ evidence_{pn}: {fmt_probe_evidence(item, pn)}")

            # Observability (timing_source + failure_reason per probe)
            obs_probes = ["udp53_probe", "tcp53_connect", "tcp53_probe", "version", "recursion",
                          "dot_connect", "dot_probe", "doh_connect", "doh_probe",
                          "dnssec", "edns0", "open_resolver", "ecs", "qname_min", "cookies", "web_risk"]
            for pn in obs_probes:
                src = item.get(f"{pn}_timing_source")
                reason = item.get(f"{pn}_failure_reason")
                if src is not None or reason is not None:
                    infra_rows.append(f"  ├─ obs_{pn}: source={fmt_val(src)} reason={fmt_val(reason)}")

            # Encrypted DNS
            infra_rows.append(f"  ├─ port853: {fmt_val(item.get('port853'))}")
            infra_rows.append(f"  ├─ port853_conn_lat: {fmt_latency(item.get('port853_conn_lat'))}")
            infra_rows.append(f"  ├─ dot: {fmt_val(item.get('dot'))}")
            infra_rows.append(f"  ├─ dot_lat: {fmt_latency(item.get('dot_lat'))}")
            infra_rows.append(f"  ├─ port443: {fmt_val(item.get('port443'))}")
            infra_rows.append(f"  ├─ port443_conn_lat: {fmt_latency(item.get('port443_conn_lat'))}")
            infra_rows.append(f"  ├─ doh: {fmt_val(item.get('doh'))}")
            infra_rows.append(f"  ├─ doh_lat: {fmt_latency(item.get('doh_lat'))}")

            # Version & Recursion
            infra_rows.append(f"  ├─ version: {fmt_val(item.get('version'))}")
            infra_rows.append(f"  ├─ version_lat: {fmt_latency(item.get('version_lat'))}")
            infra_rows.append(f"  ├─ recursion: {fmt_val(item.get('recursion'))}")
            infra_rows.append(f"  ├─ recursion_lat: {fmt_latency(item.get('recursion_lat'))}")

            # Advanced checks
            infra_rows.append(f"  ├─ dnssec: {fmt_val(item.get('dnssec'))}")
            infra_rows.append(f"  ├─ dnssec_lat: {fmt_latency(item.get('dnssec_lat'))}")
            infra_rows.append(f"  ├─ edns0: {fmt_val(item.get('edns0'))}")
            infra_rows.append(f"  ├─ edns0_lat: {fmt_latency(item.get('edns0_lat'))}")
            infra_rows.append(f"  ├─ open_resolver: {fmt_val(item.get('open_resolver'))}")
            infra_rows.append(f"  ├─ open_resolver_lat: {fmt_latency(item.get('open_resolver_lat'))}")

            # Resolver classification
            infra_rows.append(f"  ├─ classification: {fmt_val(item.get('classification'))}")
            infra_rows.append(f"  ├─ resolver_exposed: {fmt_val(item.get('resolver_exposed'))}")
            infra_rows.append(f"  ├─ resolver_restricted: {fmt_val(item.get('resolver_restricted'))}")
            infra_rows.append(f"  ├─ confidence: {fmt_val(item.get('confidence'))}")

            # Privacy
            infra_rows.append(f"  ├─ ecs: {fmt_val(item.get('ecs'))}")
            infra_rows.append(f"  ├─ ecs_lat: {fmt_latency(item.get('ecs_lat'))}")
            infra_rows.append(f"  ├─ qname_min: {fmt_val(item.get('qname_min'))}")
            infra_rows.append(f"  ├─ qname_min_lat: {fmt_latency(item.get('qname_min_lat'))}")
            infra_rows.append(f"  ├─ qname_min_confidence: {fmt_val(item.get('qname_min_confidence'))}")
            infra_rows.append(f"  ├─ cookies: {fmt_val(item.get('cookies'))}")
            infra_rows.append(f"  ├─ cookies_lat: {fmt_latency(item.get('cookies_lat'))}")

            # Web risk
            infra_rows.append(f"  ├─ web_risks: {fmt_val(item.get('web_risks'))}")
            infra_rows.append(f"  ├─ web_risk_lat: {fmt_latency(item.get('web_risk_lat'))}")
            infra_rows.append(f"  ├─ web_risk_timings: {fmt_val(item.get('web_risk_timings'))}")
            infra_rows.append(f"  ├─ web_risk_status: {fmt_val(item.get('web_risk_status'))}")

            # Meta
            infra_rows.append(f"  ├─ server_profile: {fmt_val(item.get('server_profile'))}")
            infra_rows.append(f"  ├─ dnssec_mode: {fmt_val(item.get('dnssec_mode'))}")
            infra_rows.append(f"  ├─ infrastructure_score: {fmt_val(item.get('infrastructure_score'))}")
            infra_rows.append(f"  └─ is_dead: {fmt_val(item.get('is_dead'))}")

        add_section("Phase 1: Infrastructure", infra_rows)

        # ── Phase 2: Zones (100% coverage) ──────────────────────────────────
        zone_rows = []
        if snapshots.get("phase2"):
            zone_rows.append(f"SNAPSHOT: {fmt_snapshot(snapshots['phase2'])}")
            zone_rows.append("-" * 40)
        if analytics.get("phase2_zones"):
            zone_rows.extend(fmt_insights(analytics["phase2_zones"]))
            zone_rows.append("-" * 40)

        for item in sorted(zones, key=lambda z: (z.get("domain", ""), z.get("server", ""))):
            synced = "SYNC" if item.get('zone_is_synced') else "DESYNC"
            zone_rows.append(f"▶ Zone: {clean(item.get('domain'))} @ {clean(item.get('server'))} [{clean(item.get('group', ''))}] ({synced})")

            # Core
            zone_rows.append(f"  ├─ domain_parent: {fmt_val(item.get('domain_parent'))}")
            zone_rows.append(f"  ├─ status: {fmt_val(item.get('status'))}")
            zone_rows.append(f"  ├─ serial: {fmt_val(item.get('serial'))}")
            zone_rows.append(f"  ├─ mname: {fmt_val(item.get('mname'))}")
            zone_rows.append(f"  ├─ rname: {fmt_val(item.get('rname'))}")
            zone_rows.append(f"  ├─ aa: {fmt_val(item.get('aa'))}")
            zone_rows.append(f"  ├─ latency: {fmt_latency(item.get('latency'))}")
            zone_rows.append(f"  ├─ ping_latency: {fmt_latency(item.get('ping_latency'))}")

            # SOA details
            zone_rows.append(f"  ├─ soa_latency: {fmt_latency(item.get('soa_latency'))}")
            zone_rows.append(f"  ├─ soa_fallback_latency: {fmt_latency(item.get('soa_fallback_latency'))}")
            zone_rows.append(f"  ├─ soa_latency_warn: {fmt_val(item.get('soa_latency_warn'))}")
            zone_rows.append(f"  ├─ soa_latency_crit: {fmt_val(item.get('soa_latency_crit'))}")
            zone_rows.append(f"  ├─ soa_timers: {fmt_val(item.get('soa_timers'))}")
            zone_rows.append(f"  ├─ used_fallback: {fmt_val(item.get('used_fallback'))}")

            # NS
            zone_rows.append(f"  ├─ ns_list: {fmt_val(item.get('ns_list'))}")
            zone_rows.append(f"  ├─ ns_latency: {fmt_latency(item.get('ns_latency'))}")
            zone_rows.append(f"  ├─ ns_consistent: {fmt_val(item.get('ns_consistent'))}")

            # AXFR
            zone_rows.append(f"  ├─ axfr_vulnerable: {fmt_val(item.get('axfr_vulnerable'))}")
            zone_rows.append(f"  ├─ axfr_detail: {fmt_val(item.get('axfr_detail'))}")
            zone_rows.append(f"  ├─ axfr_latency: {fmt_latency(item.get('axfr_latency'))}")
            zone_rows.append(f"  ├─ axfr_allowed_groups: {fmt_val(item.get('axfr_allowed_groups'))}")

            # DNSSEC & CAA
            zone_rows.append(f"  ├─ dnssec: {fmt_val(item.get('dnssec'))}")
            zone_rows.append(f"  ├─ zone_dnssec_latency: {fmt_latency(item.get('zone_dnssec_latency'))}")
            zone_rows.append(f"  ├─ caa_records: {fmt_val(item.get('caa_records'))}")
            zone_rows.append(f"  ├─ caa_latency: {fmt_latency(item.get('caa_latency'))}")

            # Scope & Audit
            zone_rows.append(f"  ├─ check_scope: {fmt_val(item.get('check_scope'))}")
            zone_rows.append(f"  ├─ scope_confidence: {fmt_val(item.get('scope_confidence'))}")
            zone_rows.append(f"  ├─ zone_is_synced: {fmt_val(item.get('zone_is_synced'))}")
            zone_rows.append(f"  ├─ zone_score: {fmt_val(item.get('zone_score'))}")
            zone_rows.append(f"  ├─ is_dead: {fmt_val(item.get('is_dead'))}")
            zone_rows.append(f"  ├─ web_risks: {fmt_val(item.get('web_risks'))}")

            # Zone Audit (dict)
            audit = item.get("zone_audit", {})
            zone_rows.append(f"  ├─ zone_audit.dnssec: {fmt_val(audit.get('dnssec'))}")
            zone_rows.append(f"  ├─ zone_audit.timers_ok: {fmt_val(audit.get('timers_ok'))}")
            zone_rows.append(f"  ├─ zone_audit.timers_issues: {fmt_val(audit.get('timers_issues'))}")
            zone_rows.append(f"  ├─ zone_audit.mname_reachable: {fmt_val(audit.get('mname_reachable'))}")
            zone_rows.append(f"  ├─ zone_audit.glue_ok: {fmt_val(audit.get('glue_ok'))}")
            zone_rows.append(f"  └─ zone_audit.web_risk: {fmt_val(audit.get('web_risk'))}")

            # Evidence
            for pn in ["soa", "ns", "caa", "zone_dnssec"]:
                ev = fmt_probe_evidence(item, pn)
                if ev and "=N/A" not in ev:
                    zone_rows.append(f"  ├─ evidence_{pn}: {ev}")
            for pn in ["soa", "ns"]:
                rp = fmt_probe_repeat(item, pn)
                if rp and "=N/E" not in rp:
                    zone_rows.append(f"  ├─ repeat_{pn}: {rp}")

        add_section("Phase 2: Zones", zone_rows)

        # ── Phase 3: Records (100% coverage) ────────────────────────────────
        record_rows = []
        if snapshots.get("phase3"):
            record_rows.append(f"SNAPSHOT: {fmt_snapshot(snapshots['phase3'])}")
            record_rows.append("-" * 40)
        if analytics.get("phase3_records"):
            record_rows.extend(fmt_insights(analytics["phase3_records"]))
            record_rows.append("-" * 40)

        for item in sorted(records, key=lambda r: (str(r.get("domain", "")), str(r.get("server", "")), str(r.get("type", "")))):
            consistent = "OK" if item.get('is_consistent') else "DIV!"
            record_rows.append(f"▶ Record: {clean(item.get('domain'))} [{clean(item.get('type'))}] @ {clean(item.get('server'))} ({consistent})")

            # Core
            record_rows.append(f"  ├─ domain_parent: {fmt_val(item.get('domain_parent'))}")
            record_rows.append(f"  ├─ group: {fmt_val(item.get('group'))}")
            record_rows.append(f"  ├─ status: {fmt_val(item.get('status'))}")
            record_rows.append(f"  ├─ latency: {fmt_latency(item.get('latency'))}")
            record_rows.append(f"  ├─ latency_first: {fmt_latency(item.get('latency_first'))}")
            record_rows.append(f"  ├─ latency_avg: {fmt_latency(item.get('latency_avg'))}")
            record_rows.append(f"  ├─ latency_min: {fmt_latency(item.get('latency_min'))}")
            record_rows.append(f"  ├─ latency_max: {fmt_latency(item.get('latency_max'))}")
            record_rows.append(f"  ├─ latency_jitter: {fmt_latency(item.get('latency_jitter'))}")

            # Transport context (from Phase 1)
            record_rows.append(f"  ├─ ping: {fmt_val(item.get('ping'))}")
            record_rows.append(f"  ├─ ping_latency: {fmt_latency(item.get('ping_latency'))}")
            record_rows.append(f"  ├─ port53: {fmt_val(item.get('port53'))}")
            record_rows.append(f"  ├─ recursion: {fmt_val(item.get('recursion'))}")
            record_rows.append(f"  ├─ dot: {fmt_val(item.get('dot'))}")
            record_rows.append(f"  ├─ dot_latency: {fmt_latency(item.get('dot_latency'))}")
            record_rows.append(f"  ├─ doh: {fmt_val(item.get('doh'))}")
            record_rows.append(f"  ├─ doh_latency: {fmt_latency(item.get('doh_latency'))}")

            # Response metadata
            record_rows.append(f"  ├─ answers: {fmt_val(item.get('answers'))}")
            record_rows.append(f"  ├─ ad: {fmt_val(item.get('ad'))}")
            record_rows.append(f"  ├─ nsid: {fmt_val(item.get('nsid'))}")
            record_rows.append(f"  ├─ query_size: {fmt_val(item.get('query_size'))}")
            record_rows.append(f"  ├─ response_size: {fmt_val(item.get('response_size'))}")

            # Amplification
            amp = fmt_amplification(item.get('query_size'), item.get('response_size'))
            record_rows.append(f"  ├─ amplification: {amp}")

            # Consistency
            record_rows.append(f"  ├─ internally_consistent: {fmt_val(item.get('internally_consistent'))}")
            record_rows.append(f"  ├─ is_consistent: {fmt_val(item.get('is_consistent'))}")

            # Chain & MX
            record_rows.append(f"  ├─ chain_latency: {fmt_latency(item.get('chain_latency'))}")
            record_rows.append(f"  ├─ chain_depth: {fmt_val(item.get('chain_depth'))}")
            record_rows.append(f"  ├─ mx_port25_latency: {fmt_latency(item.get('mx_port25_latency'))}")

            # Wildcard
            record_rows.append(f"  ├─ wildcard_detected: {fmt_val(item.get('wildcard_detected'))}")
            record_rows.append(f"  ├─ wildcard_answers: {fmt_val(item.get('wildcard_answers'))}")
            record_rows.append(f"  ├─ wildcard_latency: {fmt_latency(item.get('wildcard_latency'))}")

            # Findings
            for finding in item.get("findings", []):
                record_rows.append(f"  ├─ [!] finding: {clean(finding)}")

            # Evidence (main query)
            ev = fmt_probe_evidence(item, "main")
            if ev and "=N/A" not in ev:
                record_rows.append(f"  ├─ evidence_main: {ev}")

        add_section("Phase 3: Records", record_rows)

        return "\n".join(lines) + "\n"
