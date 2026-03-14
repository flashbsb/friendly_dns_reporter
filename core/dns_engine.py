import dns.resolver
import dns.query
import dns.message
import dns.rcode
import dns.exception
import dns.zone
import dns.edns
import time

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

                return {
                    "status": status,
                    "latency": latency,
                    "flags": dns.flags.to_text(response.flags).split(),
                    "aa": bool(response.flags & dns.flags.AA),
                    "answers": sorted(answers),
                    "nsid": nsid,
                    "full_response": response.to_text()
                }
            except dns.exception.Timeout as e:
                last_exception = e
                continue # Retry
            except Exception as e:
                return {"status": f"ERROR: {str(e)}", "latency": 0, "answers": []}
        
        return {"status": "TIMEOUT", "latency": self.timeout * 1000, "answers": []}

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
        """Check if server supports DoT. Returns (True/False/None, latency)."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            dns.query.tls(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            return True, latency
        except dns.exception.Timeout:
            return None, self.timeout * 1000
        except:
            return False, 0

    def check_doh(self, server):
        """Check if server supports DoH. Returns (True/False/None, latency)."""
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
                return True, latency
            return False, 0
        except requests.exceptions.Timeout:
            return None, self.timeout * 1000
        except:
            return False, 0
