import dns.resolver
import dns.query
import dns.message
import dns.rcode
import dns.exception
import dns.flags
import dns.zone
import dns.edns
import time
import socket

class DNSEngine:
    def __init__(self, timeout=2.0, tries=1):
        self.timeout = timeout
        self.tries = tries

    def query(self, server, domain, record_type="A", rd=True, cd=False, use_edns=False):
        """Perform a DNS query with sophisticated options."""
        last_exception = None
        for attempt in range(self.tries):
            try:
                # Prepare message
                query = dns.message.make_query(domain, record_type)
                
                # Recursion Desired (RD) - default True
                if not rd: query.flags &= ~dns.flags.RD
                
                # Checking Disabled (CD) - default False
                if cd: query.flags |= dns.flags.CD
                
                # EDNS0 Options (+bufsize=1232 +nsid)
                if use_edns:
                    # NSID is Option 3
                    options = [dns.edns.GenericOption(3, b'')] 
                    query.use_edns(edns=0, payload=1232, options=options)

                start_time = time.time()
                response = dns.query.udp(query, server, timeout=self.timeout)
                end_time = time.time()
                
                latency = (end_time - start_time) * 1000 # ms
                status = dns.rcode.to_text(response.rcode())
                
                answers = []
                if response.answer:
                    for rrset in response.answer:
                        for rr in rrset:
                            answers.append(rr.to_text())

                # Also capture authority section (important for SOA/referrals)
                authority = []
                if response.authority:
                    for rrset in response.authority:
                        for rr in rrset:
                            authority.append(rr.to_text())
                
                # Extract NSID if present
                nsid = None
                if response.edns == 0:
                    for opt in response.options:
                        if opt.otype == 3:
                            if hasattr(opt, 'nsid'):
                                nsid = opt.nsid.decode('utf-8', errors='ignore')
                            elif hasattr(opt, 'data'):
                                nsid = opt.data.decode('utf-8', errors='ignore')
                            else:
                                nsid = str(opt)

                # Extract TTL from answer
                ttl = 0
                if response.answer:
                    ttl = response.answer[0].ttl

                return {
                    "status": status,
                    "latency": latency,
                    "flags": dns.flags.to_text(response.flags).split(),
                    "aa": bool(response.flags & dns.flags.AA),
                    "tc": bool(response.flags & dns.flags.TC), # Truncated
                    "answers": sorted(answers),
                    "authority": sorted(authority),
                    "nsid": nsid,
                    "ttl": ttl,
                    "full_response": response.to_text()
                }
            except dns.exception.Timeout as e:
                last_exception = e
                continue # Retry
            except Exception as e:
                return {"status": f"ERROR: {str(e)}", "latency": 0, "answers": [], "authority": []}
        
        return {"status": "TIMEOUT", "latency": self.timeout * 1000, "answers": [], "authority": []}

    def check_axfr(self, server, zone):
        """Check if Zone Transfer (AXFR) is allowed."""
        try:
            # AXFR usually requires TCP
            z = dns.zone.from_xfr(dns.query.xfr(server, zone, timeout=self.timeout))
            return True, f"VULNERABLE: {len(z.nodes)} nodes leaked"
        except Exception as e:
            return False, str(e)

    def check_dnssec(self, server):
        """Check if a server supports DNSSEC validation. Returns (True/False/None, latency)."""
        start = time.time()
        try:
            # We query the root zone (.) to be independent of user domains
            query = dns.message.make_query(".", "DNSKEY", want_dnssec=True)
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    return True, latency
            return False, latency
        except dns.exception.Timeout:
            return None, self.timeout * 1000
        except:
            return False, 0

    def check_open_resolver(self, server):
        """Check if server acts as an open resolver. Returns (StatusString, latency)."""
        start = time.time()
        try:
            # Query a third-party domain without recursion desired
            query = dns.message.make_query("google.com", "A")
            query.flags &= ~dns.flags.RD 
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            
            # If it answers with an A record, it is open
            if response.answer and response.answer[0].rdtype == dns.rdatatype.A:
                return "OPEN", latency
            
            # Map specific response codes
            rcode = response.rcode()
            if rcode == dns.rcode.REFUSED:
                return "REFUSED", latency
            elif rcode == dns.rcode.SERVFAIL:
                return "SERVFAIL", latency
            elif rcode == dns.rcode.NOERROR:
                return "NOERROR", latency
            else:
                return dns.rcode.to_text(rcode), latency
                
        except dns.exception.Timeout:
            return "TIMEOUT", self.timeout * 1000
        except:
            return "ERROR", 0

    def check_edns0(self, server):
        """Check if server supports EDNS0 and large UDP payloads. Returns (True/False/None, latency)."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            # Request a 4096 buffer size
            query.use_edns(edns=0, payload=4096)
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            
            # Check if response retains EDNS0
            if response.edns == 0:
                return True, latency
            return False, latency
        except dns.exception.Timeout:
            return None, self.timeout * 1000
        except:
            return False, 0

    def check_recursion(self, server):
        """Check if recursion is available. Returns (True/False/None, latency)."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            return bool(response.flags & dns.flags.RA), latency
        except dns.exception.Timeout:
            return None, self.timeout * 1000
        except:
            return False, 0

    def query_version(self, server):
        """Query the BIND version. Returns (string/HIDDEN/None, latency)."""
        start = time.time()
        try:
            query = dns.message.make_query("version.bind", "TXT", rdclass=dns.rclass.CH)
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            if response.answer:
                return response.answer[0][0].to_text().strip('"'), latency
            return "HIDDEN", latency
        except dns.exception.Timeout:
            return None, self.timeout * 1000
        except:
            return "HIDDEN", 0

    def check_dot(self, server):
        """Check if server supports DoT. Returns (StatusString, latency)."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            dns.query.tls(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            return "OK", latency
        except dns.exception.Timeout:
            return "TIMEOUT", self.timeout * 1000
        except:
            return "FAIL", 0

    def check_doh(self, server):
        """Check if server supports DoH. Returns (StatusString, latency)."""
        import requests
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            wire_query = query.to_wire()
            url = f"https://{server}/dns-query"
            headers = {"Content-Type": "application/dns-message", "Accept": "application/dns-message"}
            
            response = requests.post(url, data=wire_query, headers=headers, timeout=self.timeout, verify=False)
            latency = (time.time() - start) * 1000
            if response.status_code == 200:
                return "OK", latency
            return "FAIL", 0
        except requests.exceptions.Timeout:
            return "TIMEOUT", self.timeout * 1000
        except:
            return "FAIL", 0

    def check_tcp(self, server):
        """Perform a real DNS query over TCP. Returns (StatusString, latency)."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            dns.query.tcp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            return "OK", latency
        except dns.exception.Timeout:
            return "TIMEOUT", self.timeout * 1000
        except:
            return "FAIL", 0

    def check_zone_dnssec(self, server, domain):
        """Verify if a specific zone is signed (contains DNSKEY and RRSIG)."""
        try:
            query = dns.message.make_query(domain, "DNSKEY", want_dnssec=True)
            response = dns.query.udp(query, server, timeout=self.timeout)
            
            has_dnskey = any(rrset.rdtype == dns.rdatatype.DNSKEY for rrset in response.answer)
            has_rrsig = any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer)
            
            return has_dnskey and has_rrsig
        except:
            return False

    def analyze_soa_timers(self, refresh, retry, expire, minimum):
        """Validate SOA timers against RFC 1912 best practices."""
        # RFC 1912 / Common Best Practices:
        # Refresh: 20 min to 12 hours (1200 - 43200)
        # Retry: 2 min to 2 hours (120 - 7200)
        # Expire: 2 to 4 weeks (1209600 - 2419200)
        # Min TTL: 3 min to 1 day (180 - 86400)
        
        issues = []
        if not (1200 <= refresh <= 43200): issues.append(f"Refresh({refresh}) out of RFC range")
        if not (120 <= retry <= 7200): issues.append(f"Retry({retry}) out of RFC range")
        if retry >= refresh: issues.append("Retry >= Refresh")
        if not (1209600 <= expire <= 2419200): issues.append(f"Expire({expire}) out of RFC range")
        if not (180 <= minimum <= 86400): issues.append(f"MinTTL({minimum}) out of RFC range")
        
        return len(issues) == 0, issues

    def check_web_risk(self, server):
        """Check if ports 80 or 443 are open on the DNS server (Web Exposure Risk)."""
        risks = []
        for port in [80, 443]:
            try:
                with socket.create_connection((server, port), timeout=1.0):
                    risks.append(port)
            except:
                continue
        return risks

    def resolve_chain(self, server, target, rtype):
        """Verify if a CNAME or MX target actually resolves to an IP (Dangling DNS check)."""
        try:
            # Check for both IPv4 and IPv6 resolution
            has_ip = False
            for family in ["A", "AAAA"]:
                res = self.query(server, target, family)
                if res['status'] == "NOERROR" and res['answers']:
                    has_ip = True
                    break
                if res['status'] == "NXDOMAIN":
                    return False, "NXDOMAIN (Dangling!)"
            
            if has_ip:
                return True, "RESOLVES"
            return False, "NO ADDRESS RECORDS FOUND"
        except:
            return False, "ERROR"

    def check_port_25(self, server):
        """Check if SMTP port 25 is open on a target (MX Reachability)."""
        try:
            with socket.create_connection((server, 25), timeout=2.0):
                return True
        except:
            return False

    def detect_wildcard(self, server, domain):
        """Check if zone has a wildcard entry by querying a random sub-subdomain."""
        import random
        import string
        rand_prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        test_domain = f"{rand_prefix}.{domain}"
        try:
            res = self.query(server, test_domain, "A")
            if res['status'] == "NOERROR" and res['answers']:
                return True, res['answers']
            return False, None
        except:
            return False, None
