import re

def validate_spf(spf_records):
    """Validate SPF record syntax and common pitfalls."""
    issues = []
    if not spf_records:
        return True, []
        
    combined = " ".join(spf_records)
    
    # Check for multiple SPF records
    if len(spf_records) > 1:
        issues.append("Multiple SPF records detected (Invalid SPF)")
        
    if "v=spf1" not in combined:
        issues.append("Missing 'v=spf1' tag")
        
    # Check for +all (Too permissive)
    if "+all" in combined:
        issues.append("SPF contains '+all' (Permissive/Insecure)")
        
    # Check for multiple 'all' mechanisms
    if combined.count("all") > 1:
        issues.append("Multiple 'all' mechanisms detected")
        
    # Look-up limit (More comprehensive check)
    # RFC 7208: limit of 10 DNS lookups for: include, a, mx, ptr, exists, redirect
    lookups = 0
    for mechanism in ["include:", "a", "mx", "ptr", "exists:", "redirect="]:
        # Only count if it's treated as a mechanism (roughly)
        lookups += combined.lower().count(mechanism)
        
    if lookups > 10:
        issues.append(f"High number of DNS lookups ({lookups}), likely exceeds RFC 10-lookup limit")
        
    return len(issues) == 0, issues

def validate_dmarc(dmarc_records):
    """Validate DMARC record syntax."""
    issues = []
    if not dmarc_records:
        return True, []
        
    if len(dmarc_records) > 1:
        issues.append("Multiple DMARC records detected (Invalid)")

    combined = " ".join(dmarc_records)
    
    if "v=DMARC1" not in combined:
        issues.append("Missing 'v=DMARC1' tag")
        
    if "p=" not in combined:
        issues.append("Missing policy tag 'p=' (Required)")
        
    # Check for common policy values
    if "p=none" in combined:
        issues.append("Policy 'p=none' (Monitoring only, no enforcement)")
        
    return len(issues) == 0, issues

def analyze_ttl(ttl):
    """Analyze if TTL follows best practices."""
    # Best practices:
    # Low: < 300s (5m) -> High load
    # High: > 86400s (24h) -> Hard to migrate
    
    if ttl < 60:
        return False, f"TTL extremely low ({ttl}s) - High DNS load"
    if ttl > 172800: # 48h
        return False, f"TTL extremely high ({ttl}s) - Difficult to migrate"
    return True, "OK"
