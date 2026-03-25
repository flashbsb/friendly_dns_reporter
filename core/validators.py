import re

def validate_spf(spf_records, lookup_limit=10):
    """Heuristic SPF validation for common pitfalls."""
    issues = []
    if not spf_records:
        return True, []
        
    combined = " ".join(spf_records)
    
    # Check for multiple SPF records
    if len(spf_records) > 1:
        issues.append("Heuristic SPF warning: multiple SPF records detected (invalid SPF)")
        
    if "v=spf1" not in combined:
        issues.append("Heuristic SPF warning: missing 'v=spf1' tag")
        
    # Check for +all (Too permissive)
    if "+all" in combined:
        issues.append("Heuristic SPF warning: SPF contains '+all' (permissive/insecure)")
        
    # Check for multiple 'all' mechanisms
    all_mechanisms = re.findall(r'(?<![A-Za-z0-9_])[+?~-]?all(?![A-Za-z0-9_])', combined.lower())
    if len(all_mechanisms) > 1:
        issues.append("Heuristic SPF warning: multiple 'all' mechanisms detected")
        
    # Look-up limit (More comprehensive check)
    # RFC 7208: limit of 10 DNS lookups for: include, a, mx, ptr, exists, redirect
    lookups = 0
    normalized = combined.lower()
    lookups += len(re.findall(r'(?<![A-Za-z0-9_])include:', normalized))
    lookups += len(re.findall(r'(?<![A-Za-z0-9_])[+?~-]?a(?=[:/ ]|$)', normalized))
    lookups += len(re.findall(r'(?<![A-Za-z0-9_])[+?~-]?mx(?=[:/ ]|$)', normalized))
    lookups += len(re.findall(r'(?<![A-Za-z0-9_])[+?~-]?ptr(?=[:/ ]|$)', normalized))
    lookups += len(re.findall(r'(?<![A-Za-z0-9_])exists:', normalized))
    lookups += len(re.findall(r'(?<![A-Za-z0-9_])redirect=', normalized))
        
    if lookups > lookup_limit:
        issues.append(f"Heuristic SPF warning: high number of DNS lookups ({lookups}), likely exceeds limit ({lookup_limit})")
        
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

def analyze_ttl(ttl, min_val=60, max_val=172800):
    """Heuristic TTL analysis based on common operational practice."""
    # Best practices:
    # Low: < 300s (5m) -> High load
    # High: > 86400s (24h) -> Hard to migrate
    
    if ttl < min_val:
        return False, f"Heuristic TTL warning: TTL extremely low ({ttl}s) - may increase DNS load"
    if ttl > max_val:
        return False, f"Heuristic TTL warning: TTL extremely high ({ttl}s) - may slow migrations"
    return True, "OK"
