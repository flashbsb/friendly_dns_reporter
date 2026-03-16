#!/usr/bin/env python3
"""Lightweight report coverage checker for FriendlyDNSReporter JSON outputs."""

from __future__ import annotations

import json
import sys
from pathlib import Path


REQUIRED_INFRA_FIELDS = [
    "server_profile",
    "classification",
    "resolver_exposed",
    "resolver_restricted",
    "latency",
    "latency_min",
    "latency_max",
    "web_risks",
]

REQUIRED_ZONE_FIELDS = [
    "check_scope",
    "mname",
    "rname",
    "caa_records",
    "zone_audit",
]

REQUIRED_ZONE_AUDIT_FIELDS = [
    "dnssec",
    "timers_ok",
    "timers_issues",
    "mname_reachable",
    "web_risk",
]

REQUIRED_RECORD_FIELDS = [
    "answers",
    "findings",
    "wildcard_detected",
    "wildcard_answers",
    "internally_consistent",
]


def check_fields(items, required_fields, label):
    missing = set()
    for item in items:
        for field in required_fields:
            if field not in item:
                missing.add(field)
    if missing:
        print(f"[WARN] {label}: missing fields -> {', '.join(sorted(missing))}")
    else:
        print(f"[ OK ] {label}: all required fields present")


def main():
    if len(sys.argv) != 2:
        print("Usage: python tools/report_coverage_check.py <report.json>")
        raise SystemExit(1)

    report_path = Path(sys.argv[1])
    data = json.loads(report_path.read_text(encoding="utf-8"))
    details = data.get("detailed_results", {})

    infra = list((details.get("infrastructure") or {}).values())
    zones = details.get("zones") or []
    records = details.get("records") or []

    check_fields(infra, REQUIRED_INFRA_FIELDS, "Infrastructure")
    check_fields(zones, REQUIRED_ZONE_FIELDS, "Zones")
    check_fields(records, REQUIRED_RECORD_FIELDS, "Records")

    zone_audits = [z.get("zone_audit", {}) for z in zones if isinstance(z.get("zone_audit"), dict)]
    check_fields(zone_audits, REQUIRED_ZONE_AUDIT_FIELDS, "Zone audit")


if __name__ == "__main__":
    main()
