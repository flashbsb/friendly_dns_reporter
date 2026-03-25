import socket
import subprocess
import platform
import time
import re
from icmplib import ping as icmp_ping

class Connectivity:
    def __init__(self, timeout=2.0, ping_timeout=None):
        self.timeout = timeout
        self.ping_timeout = ping_timeout if ping_timeout is not None else timeout

    def check_port(self, host, port):
        """Check if a TCP port is open. Returns (is_open, latency_ms)."""
        start = time.time()
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                latency = (time.time() - start) * 1000
                return True, latency
        except (socket.timeout, ConnectionRefusedError, socket.error):
            return False, None

    def ping(self, host, count=3):
        """Cross-platform ping using icmplib (best) or system ping (fallback)."""
        try:
            # icmplib provides a clean pythonic way
            result = icmp_ping(host, count=count, timeout=self.ping_timeout)
            return {
                "avg_rtt": result.avg_rtt,
                "min_rtt": result.min_rtt,
                "max_rtt": result.max_rtt,
                "packet_loss": result.packet_loss,
                "is_alive": result.is_alive
            }
        except Exception as e:
            # Fallback to system ping if icmplib fails (e.g. permission issues on linux)
            return self._system_ping(host, count)

    def _system_ping(self, host, count):
        is_windows = platform.system().lower() == 'windows'
        param = '-n' if is_windows else '-c'
        command = ['ping', param, str(count), host]
        
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            
            avg_rtt = None
            min_rtt = None
            max_rtt = None
            packet_loss = 1.0
            
            if is_windows:
                match = re.search(r"Average = (\d+)ms", output)
                if match: avg_rtt = float(match.group(1))
                match_min = re.search(r"Minimum = (\d+)ms", output)
                if match_min: min_rtt = float(match_min.group(1))
                match_max = re.search(r"Maximum = (\d+)ms", output)
                if match_max: max_rtt = float(match_max.group(1))
                
                loss_match = re.search(r"\((\d+)% loss\)", output)
                if loss_match: packet_loss = float(loss_match.group(1)) / 100.0
            else:
                match = re.search(r"rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)", output)
                if match:
                    min_rtt = float(match.group(1))
                    avg_rtt = float(match.group(2))
                    max_rtt = float(match.group(3))
                
                loss_match = re.search(r"(\d+)% packet loss", output)
                if loss_match: packet_loss = float(loss_match.group(1)) / 100.0

            is_alive = packet_loss < 1.0
            return {
                "avg_rtt": avg_rtt,
                "min_rtt": min_rtt,
                "max_rtt": max_rtt,
                "packet_loss": packet_loss,
                "is_alive": is_alive,
                "fallback": True
            }
        except:
            return {"avg_rtt": None, "min_rtt": None, "max_rtt": None, "packet_loss": 1.0, "is_alive": False, "fallback": True}

    def traceroute(self, host, max_hops=30):
        """Simple traceroute implementation (or system call)."""
        # Traceroute is complex to implement purely in Python without raw sockets (permissions)
        # So we'll wrap the system tool
        cmd = ["tracert", "-d", "-h", str(max_hops), host] if platform.system().lower() == 'windows' else ["traceroute", "-n", "-m", str(max_hops), host]
        
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
            return output
        except:
            return "Traceroute failed"
