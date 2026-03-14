import os
import configparser

class Settings:
    """Helper class to load and access settings safely from settings.ini."""
    def __init__(self, config_path="config/settings.ini"):
        self.config = configparser.ConfigParser()
        self.path = config_path
        if os.path.exists(config_path):
            self.config.read(config_path, encoding='utf-8')
        
    def get_int(self, section, key, fallback):
        return self.config.getint(section, key, fallback=fallback)
    
    def get_str(self, section, key, fallback):
        return self.config.get(section, key, fallback=fallback)
    
    def get_bool(self, section, key, fallback):
        return self.config.getboolean(section, key, fallback=fallback)
    
    def get_float(self, section, key, fallback):
        return self.config.getfloat(section, key, fallback=fallback)

    # --- GENERAL ---
    @property
    def max_threads(self):
        return self.get_int("GENERAL", "MAX_THREADS", 10)

    @property
    def timeout(self):
        return self.get_int("GENERAL", "TIMEOUT", 4)

    @property
    def sleep_time(self):
        return self.get_float("GENERAL", "SLEEP", 0.01)

    @property
    def only_test_active_groups(self):
        return self.get_bool("GENERAL", "ONLY_TEST_ACTIVE_GROUPS", True)

    @property
    def enable_ui_legends(self):
        return self.get_bool("GENERAL", "ENABLE_UI_LEGENDS", True)

    # --- REPORTS ---
    @property
    def log_dir(self):
        return self.get_str("REPORTS", "LOG_DIR", "logs")

    @property
    def enable_html_report(self):
        return self.get_bool("REPORTS", "ENABLE_HTML_REPORT", True)

    @property
    def enable_json_report(self):
        return self.get_bool("REPORTS", "ENABLE_JSON_REPORT", True)

    @property
    def enable_csv_report(self):
        return self.get_bool("REPORTS", "ENABLE_CSV_REPORT", True)

    @property
    def enable_report_timestamps(self):
        return self.get_bool("REPORTS", "ENABLE_REPORT_TIMESTAMPS", True)

    @property
    def enable_execution_log(self):
        return self.get_bool("REPORTS", "ENABLE_EXECUTION_LOG", True)

    # --- DNS ENGINE ---
    @property
    def dns_timeout(self):
        return self.get_int("DNS_ENGINE", "DNS_TIMEOUT", 1)

    @property
    def dns_retries(self):
        return self.get_int("DNS_ENGINE", "DNS_RETRIES", 1)

    # --- PHASES ---
    @property
    def enable_phase_server(self):
        return self.get_bool("PHASES", "ENABLE_PHASE_SERVER", True)

    @property
    def enable_phase_zone(self):
        return self.get_bool("PHASES", "ENABLE_PHASE_ZONE", True)

    @property
    def enable_phase_record(self):
        return self.get_bool("PHASES", "ENABLE_PHASE_RECORD", True)

    # --- CONNECTIVITY ---
    @property
    def enable_ping(self):
        return self.get_bool("CONNECTIVITY", "ENABLE_PING", True)

    @property
    def ping_count(self):
        return self.get_int("CONNECTIVITY", "PING_COUNT", 3)

    @property
    def ping_timeout(self):
        return self.get_float("CONNECTIVITY", "PING_TIMEOUT", 2.0)

    @property
    def ping_latency_warn(self):
        return self.get_int("CONNECTIVITY", "PING_LATENCY_WARN", 100)

    @property
    def ping_latency_crit(self):
        return self.get_int("CONNECTIVITY", "PING_LATENCY_CRIT", 250)
        
    @property
    def ping_loss_warn(self):
        return self.get_int("CONNECTIVITY", "PING_LOSS_WARN", 15)
        
    @property
    def ping_loss_crit(self):
        return self.get_int("CONNECTIVITY", "PING_LOSS_CRIT", 50)

    @property
    def soa_latency_warn(self):
        return self.get_int("CONNECTIVITY", "SOA_LATENCY_WARN", 500)

    @property
    def soa_latency_crit(self):
        return self.get_int("CONNECTIVITY", "SOA_LATENCY_CRIT", 1500)


    # --- ADVANCED CHECKS ---
    @property
    def check_bind_version(self):
        return self.get_bool("ADVANCED_CHECKS", "CHECK_BIND_VERSION", True)

    @property
    def enable_recursion_check(self):
        return self.get_bool("ADVANCED_CHECKS", "ENABLE_RECURSION_CHECK", True)

    @property
    def enable_dnssec_check(self):
        return self.get_bool("ADVANCED_CHECKS", "ENABLE_DNSSEC_CHECK", True)

    @property
    def enable_edns_check(self):
        return self.get_bool("ADVANCED_CHECKS", "ENABLE_EDNS_CHECK", True)

    @property
    def enable_dot_check(self):
        return self.get_bool("ADVANCED_CHECKS", "ENABLE_DOT_CHECK", True)

    @property
    def enable_doh_check(self):
        return self.get_bool("ADVANCED_CHECKS", "ENABLE_DOH_CHECK", True)

    # --- ZONE TESTS ---
    @property
    def enable_axfr_check(self):
        return self.get_bool("ZONE_TESTS", "ENABLE_AXFR_CHECK", True)

    @property
    def axfr_allowed_groups(self):
        val = self.get_str("ZONE_TESTS", "AXFR_ALLOWED_GROUPS", "")
        return [g.strip().upper() for g in val.split(',') if g.strip()]

    @property
    def enable_soa_serial_sync(self):
        # We use a simpler serial check in Zone phase
        return True

    @property
    def enable_web_risk_check(self):
        return self.get_bool("ZONE_TESTS", "ENABLE_WEB_RISK_CHECK", True)

    @property
    def enable_soa_timer_audit(self):
        return self.get_bool("ZONE_TESTS", "ENABLE_SOA_TIMER_AUDIT", True)

    @property
    def enable_zone_dnssec_check(self):
        return self.get_bool("ZONE_TESTS", "ENABLE_ZONE_DNSSEC_CHECK", True)

    # --- CONSISTENCY ---
    @property
    def consistency_checks(self):
        return self.get_int("CONSISTENCY", "CONSISTENCY_CHECKS", 5)

    @property
    def strict_ip_check(self):
        return self.get_bool("CONSISTENCY", "STRICT_IP_CHECK", False)

    @property
    def strict_order_check(self):
        return self.get_bool("CONSISTENCY", "STRICT_ORDER_CHECK", False)

    @property
    def strict_ttl_check(self):
        return self.get_bool("CONSISTENCY", "STRICT_TTL_CHECK", False)

    @property
    def rec_latency_warn(self):
        return self.get_int("CONSISTENCY", "REC_LATENCY_WARN", 150)

    @property
    def rec_latency_crit(self):
        return self.get_int("CONSISTENCY", "REC_LATENCY_CRIT", 500)
