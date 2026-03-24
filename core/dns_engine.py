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
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict

@dataclass
class DNSResponse:
    """Standardized DNS response object."""
    status: str
    latency: Optional[float] = None
    answers: List[str] = field(default_factory=list)
    authority: List[str] = field(default_factory=list)
    protocol: str = "udp"
    flags: List[str] = field(default_factory=list)
    aa: bool = False
    tc: bool = False
    nsid: Optional[str] = None
    ttl: int = 0
    query_size: int = 0
    response_size: int = 0
    answer_count: int = 0
    authority_count: int = 0
    meta: Dict[str, Any] = field(default_factory=dict)
    full_response: str = ""

class DNSEngine:
    def __init__(self, timeout=2.0, tries=1, verify_ssl=True):
        self.timeout = timeout
        self.tries = tries
        self.verify_ssl = verify_ssl

    def query(self, server, domain, record_type="A", rd=True, cd=False, use_edns=False) -> DNSResponse:
        """Perform a DNS query with sophisticated options."""
        last_exception = None
        for attempt in range(self.tries):
            try:
                # Prepare message
                query = dns.message.make_query(domain, record_type)
                query_size = len(query.to_wire())
                
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

                return DNSResponse(
                    status=status,
                    latency=latency,
                    protocol="udp",
                    query_size=query_size,
                    response_size=len(response.to_wire()),
                    flags=dns.flags.to_text(response.flags).split(),
                    aa=bool(response.flags & dns.flags.AA),
                    tc=bool(response.flags & dns.flags.TC),
                    answer_count=sum(len(rrset) for rrset in response.answer) if response.answer else 0,
                    authority_count=sum(len(rrset) for rrset in response.authority) if response.authority else 0,
                    answers=answers,
                    authority=authority,
                    nsid=nsid,
                    ttl=ttl,
                    full_response=response.to_text()
                )
            except dns.exception.Timeout as e:
                last_exception = e
                continue # Retry
            except Exception as e:
                return DNSResponse(status=f"ERROR: {str(e)}", protocol="udp")
        
        return DNSResponse(status="TIMEOUT", latency=self.timeout * 1000, protocol="udp")

    def _response_meta(self, response: dns.message.Message, protocol="udp", extra=None) -> Dict[str, Any]:
        if not response:
            return extra or {}
        meta = {
            "protocol": protocol,
            "rcode": dns.rcode.to_text(response.rcode()),
            "flags": dns.flags.to_text(response.flags).split(),
            "response_size": len(response.to_wire()),
            "authority_count": sum(len(rrset) for rrset in response.authority) if response.authority else 0,
            "answer_count": sum(len(rrset) for rrset in response.answer) if response.answer else 0,
            "aa": bool(response.flags & dns.flags.AA),
            "tc": bool(response.flags & dns.flags.TC),
        }
        if extra:
            meta.update(extra)
        return meta

    def _as_response(self, status: str, latency: Optional[float], response: Optional[dns.message.Message] = None, protocol="udp", extra=None) -> DNSResponse:
        """Helper to wrap common probe results into a DNSResponse."""
        if not response:
            return DNSResponse(status=status, latency=latency, protocol=protocol, meta=extra or {})
        
        answers = []
        if response.answer:
            for rrset in response.answer:
                for rr in rrset:
                    answers.append(rr.to_text())
        
        authority = []
        if response.authority:
            for rrset in response.authority:
                for rr in rrset:
                    authority.append(rr.to_text())

        return DNSResponse(
            status=status,
            latency=latency,
            answers=answers,
            authority=authority,
            protocol=protocol,
            flags=dns.flags.to_text(response.flags).split(),
            aa=bool(response.flags & dns.flags.AA),
            tc=bool(response.flags & dns.flags.TC),
            response_size=len(response.to_wire()),
            answer_count=len(answers),
            authority_count=len(authority),
            meta=self._response_meta(response, protocol, extra),
            full_response=response.to_text()
        )

    def check_axfr(self, server, zone) -> DNSResponse:
        """Check if Zone Transfer (AXFR) is allowed."""
        start = time.time()
        try:
            # AXFR usually requires TCP
            z = dns.zone.from_xfr(dns.query.xfr(server, zone, timeout=self.timeout))
            latency = (time.time() - start) * 1000
            return DNSResponse(status="VULNERABLE", latency=latency, protocol="tcp", answer_count=len(z.nodes), meta={"detail": f"{len(z.nodes)} nodes leaked"})
        except dns.exception.Timeout:
            return DNSResponse(status="TIMEOUT", latency=self.timeout * 1000, protocol="tcp")
        except Exception as e:
            return DNSResponse(status="FAIL", protocol="tcp", meta={"error": str(e)})

    def check_dnssec(self, server) -> DNSResponse:
        """Check whether a server returns DNSSEC data. This is not a validation test."""
        start = time.time()
        try:
            # We query the root zone (.) to be independent of user domains
            query = dns.message.make_query(".", "DNSKEY", want_dnssec=True)
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            
            has_dnskey = any(rrset.rdtype == dns.rdatatype.DNSKEY for rrset in response.answer)
            has_rrsig = any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer)
            
            status = "OK" if (has_dnskey and has_rrsig) else "NO_DNSSEC"
            return self._as_response(status, latency, response, extra={"query_type": "DNSKEY", "want_dnssec": True, "query_size": query_size, "has_dnskey": has_dnskey, "has_rrsig": has_rrsig})
        except dns.exception.Timeout:
            return DNSResponse(status="TIMEOUT", latency=self.timeout * 1000)
        except:
            return DNSResponse(status="FAIL")

    def check_open_resolver(self, server) -> DNSResponse:
        """Check if server appears to provide public recursion using third-party recursion."""
        start = time.time()
        try:
            # A public recursion test must request recursion.
            query = dns.message.make_query("google.com", "A")
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000

            rcode = response.rcode()
            recursion_available = bool(response.flags & dns.flags.RA)

            status = dns.rcode.to_text(rcode)
            if recursion_available and rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                status = "OPEN"
            elif rcode == dns.rcode.REFUSED:
                status = "REFUSED"
            elif not recursion_available:
                status = "NO_RECURSION"

            return self._as_response(status, latency, response, extra={"ra": recursion_available, "query_size": query_size})
                
        except dns.exception.Timeout:
            return DNSResponse(status="TIMEOUT", latency=self.timeout * 1000)
        except:
            return DNSResponse(status="ERROR")

    def check_edns0(self, server) -> DNSResponse:
        """Check if server supports EDNS0 and large UDP payloads."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            query.use_edns(edns=0, payload=4096)
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            
            status = "OK" if response.edns == 0 else "FAIL"
            return self._as_response(status, latency, response, extra={"edns": response.edns, "payload": 4096, "query_size": query_size})
        except dns.exception.Timeout:
            return DNSResponse(status="TIMEOUT", latency=self.timeout * 1000)
        except:
            return DNSResponse(status="FAIL")

    def check_recursion(self, server) -> DNSResponse:
        """Check if recursion is available."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            ra = bool(response.flags & dns.flags.RA)
            status = "OK" if ra else "NO_RECURSION"
            return self._as_response(status, latency, response, extra={"ra": ra, "query_size": query_size})
        except dns.exception.Timeout:
            return DNSResponse(status="TIMEOUT", latency=self.timeout * 1000)
        except:
            return DNSResponse(status="FAIL")

    def query_version(self, server) -> DNSResponse:
        """Query the BIND version."""
        start = time.time()
        try:
            query = dns.message.make_query("version.bind", "TXT", rdclass=dns.rclass.CH)
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            if response.answer:
                version = response.answer[0][0].to_text().strip('"')
                return self._as_response("OK", latency, response, extra={"version": version, "query_class": "CH", "query_name": "version.bind", "query_size": query_size})
            return self._as_response("HIDDEN", latency, response, extra={"query_class": "CH", "query_name": "version.bind", "query_size": query_size})
        except dns.exception.Timeout:
            return DNSResponse(status="TIMEOUT", latency=self.timeout * 1000, meta={"query_class": "CH"})
        except:
            return DNSResponse(status="HIDDEN", meta={"query_class": "CH"})

    def check_dot(self, server) -> DNSResponse:
        """Check if server supports DoT."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            query_size = len(query.to_wire())
            response = dns.query.tls(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            return self._as_response("OK", latency, response, protocol="tls", extra={"port": 853, "query_size": query_size})
        except dns.exception.Timeout:
            return DNSResponse(status="TIMEOUT", latency=self.timeout * 1000, protocol="tls", meta={"port": 853})
        except:
            return DNSResponse(status="FAIL", protocol="tls", meta={"port": 853})

    def check_doh(self, server) -> DNSResponse:
        """Check if server supports DoH. SSL verification is configurable (Security 1.1)."""
        import requests
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            wire_query = query.to_wire()
            url = f"https://{server}/dns-query"
            headers = {"Content-Type": "application/dns-message", "Accept": "application/dns-message"}
            
            response = requests.post(url, data=wire_query, headers=headers, timeout=self.timeout, verify=self.verify_ssl)
            latency = (time.time() - start) * 1000
            if response.status_code == 200:
                try:
                    dns_response = dns.message.from_wire(response.content)
                    return self._as_response("OK", latency, dns_response, protocol="https", extra={"port": 443, "http_status": response.status_code, "query_size": len(wire_query)})
                except Exception:
                    return DNSResponse(status="OK", latency=latency, protocol="https", meta={"port": 443, "http_status": response.status_code, "response_size": len(response.content), "query_size": len(wire_query)})
            return DNSResponse(status="FAIL", latency=latency, protocol="https", meta={"port": 443, "http_status": response.status_code, "response_size": len(response.content), "query_size": len(wire_query)})
        except requests.exceptions.Timeout:
            return DNSResponse(status="TIMEOUT", latency=self.timeout * 1000, protocol="https", meta={"port": 443})
        except:
            return DNSResponse(status="FAIL", protocol="https", meta={"port": 443})

    def check_tcp(self, server) -> DNSResponse:
        """Perform a real DNS query over TCP."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            query_size = len(query.to_wire())
            response = dns.query.tcp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            return self._as_response("OK", latency, response, protocol="tcp", extra={"port": 53, "query_size": query_size})
        except dns.exception.Timeout:
            return DNSResponse(status="TIMEOUT", latency=self.timeout * 1000, protocol="tcp", meta={"port": 53})
        except:
            return DNSResponse(status="FAIL", protocol="tcp", meta={"port": 53})

    def check_udp(self, server) -> DNSResponse:
        """Perform a direct DNS query over UDP to measure DNS service responsiveness."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            return self._as_response("OK", latency, response, protocol="udp", extra={"port": 53, "query_size": query_size})
        except dns.exception.Timeout:
            return DNSResponse(status="TIMEOUT", latency=self.timeout * 1000, protocol="udp", meta={"port": 53})
        except:
            return DNSResponse(status="FAIL", protocol="udp", meta={"port": 53})

    def check_zone_dnssec(self, server, domain) -> DNSResponse:
        """Verify if a specific zone is signed (contains DNSKEY and RRSIG)."""
        start = time.time()
        try:
            query = dns.message.make_query(domain, "DNSKEY", want_dnssec=True)
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            
            has_dnskey = any(rrset.rdtype == dns.rdatatype.DNSKEY for rrset in response.answer)
            has_rrsig = any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer)
            
            status = "OK" if (has_dnskey and has_rrsig) else "NO_DNSSEC"
            return self._as_response(status, latency, response, extra={"query_type": "DNSKEY", "want_dnssec": True, "query_size": query_size})
        except dns.exception.Timeout:
            return DNSResponse(status="TIMEOUT", latency=self.timeout * 1000)
        except:
            return DNSResponse(status="FAIL")

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
        timings = {}
        for port in [80, 443]:
            start = time.time()
            try:
                with socket.create_connection((server, port), timeout=1.0):
                    risks.append(port)
                    timings[port] = (time.time() - start) * 1000
            except:
                timings[port] = None
                continue
        return risks, timings

    def resolve_chain(self, server, target, rtype, rd=True):
        """Verify if a CNAME or MX target actually resolves to an IP (Dangling DNS check)."""
        try:
            # Check for both IPv4 and IPv6 resolution
            has_ip = False
            latencies = []
            for family in ["A", "AAAA"]:
                res = self.query(server, target, family, rd=rd)
                if res.get("latency"):
                    latencies.append(res["latency"])
                if res['status'] == "NOERROR" and res['answers']:
                    has_ip = True
                    break
                if res['status'] == "NXDOMAIN":
                    return False, "NXDOMAIN (Dangling!)", (sum(latencies) / len(latencies)) if latencies else None
            
            if has_ip:
                return True, "RESOLVES", (sum(latencies) / len(latencies)) if latencies else None
            return False, "NO ADDRESS RECORDS FOUND", (sum(latencies) / len(latencies)) if latencies else None
        except:
            return False, "ERROR", None

    def check_port_25(self, server):
        """Check if SMTP port 25 is open on a target (MX Reachability)."""
        start = time.time()
        try:
            with socket.create_connection((server, 25), timeout=2.0):
                latency = (time.time() - start) * 1000
                return True, latency
        except:
            return False, None

    def detect_wildcard(self, server, domain, rd=True):
        """Check if zone has a wildcard entry by querying a random sub-subdomain."""
        import random
        import string
        rand_prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        test_domain = f"{rand_prefix}.{domain}"
        try:
            res = self.query(server, test_domain, "A", rd=rd)
            if res['status'] == "NOERROR" and res['answers']:
                return True, res['answers'], res.get("latency")
            return False, None, res.get("latency")
        except:
            return False, None, None

    def check_ecs_support(self, server) -> DNSResponse:
        """Check if server respects/handles EDNS Client Subnet (ECS)."""
        start = time.time()
        try:
            from dns.edns import GenericOption
            ecs_data = b'\x00\x01\x18\x00\x01\x02\x03' 
            options = [GenericOption(8, ecs_data)]
            query = dns.message.make_query("google.com", "A")
            query.use_edns(edns=0, payload=1232, options=options)
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            
            supported = any(opt.otype == 8 for opt in response.options)
            status = "OK" if supported else "NO_ECS"
            return self._as_response(status, latency, response)
        except:
            return DNSResponse(status="FAIL")

    def check_qname_minimization(self, server, rd=True) -> DNSResponse:
        """Heuristic check for QNAME minimization via qnamemintest.internet.nl."""
        try:
            res_txt = self.query(server, "qnamemintest.internet.nl", "TXT", rd=rd)
            for ans in res_txt.answers:
                if "HOORAY" in ans.upper(): 
                    res_txt.status = "OK"
                    return res_txt
            res_txt.status = "NO_QNAME_MIN"
            return res_txt
        except:
            return DNSResponse(status="FAIL")

    def check_dns_cookies(self, server) -> DNSResponse:
        """Check for DNS Cookies (RFC 7873) support."""
        start = time.time()
        try:
            from dns.edns import GenericOption
            import os
            client_cookie = os.urandom(8)
            options = [GenericOption(10, client_cookie)]
            query = dns.message.make_query(".", "SOA")
            query.use_edns(edns=0, payload=1232, options=options)
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            
            supported = any(opt.otype == 10 for opt in response.options)
            status = "OK" if supported else "NO_COOKIE"
            return self._as_response(status, latency, response)
        except:
            return DNSResponse(status="FAIL")

    def validate_caa(self, server, domain, rd=True) -> DNSResponse:
        """Check for CAA records (Certificate Authority Authorization)."""
        try:
            res = self.query(server, domain, "CAA", rd=rd)
            if res.status == "NOERROR" and res.answers:
                res.status = "OK"
                return res
            res.status = "NO_CAA"
            return res
        except:
            return DNSResponse(status="FAIL")
