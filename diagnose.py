import platform
import subprocess
import socket
import time
import re
from datetime import datetime

class NetworkDiagnostics:
    def __init__(self):
        self.os_type = platform.system().lower()

    # ping host and return stats
    def ping(self, host, count=4):
        try:
            if platform.system().lower() == "darwin":  
                command = ["ping", "-c", str(count), "-t", "5", host]
            elif self.os_type == "windows":
                command = ["ping", "-n", str(count), host]
            else:  # Linux
                command = ["ping", "-c", str(count), host]
            
            output = subprocess.check_output(command, universal_newlines=True)
            return self._parse_ping_output(output)
        except subprocess.CalledProcessError:
            return {"status": "failed", "error": "Host unreachable"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
        
     # parse the ping output (for MacOS Darwin, Windows, Unix)
    def _parse_ping_output(self, output):
        result = {
            "status": "success",
            "packets_sent": 0,
            "packets_received": 0,
            "packet_loss": 0,
            "min_rtt": None,
            "avg_rtt": None,
            "max_rtt": None
        }

        # raw output for debugging
        print("Raw ping output:")
        print(output)
        print("---")

        if platform.system().lower() == "darwin": 
            
            packets = re.search(r"(\d+) packets transmitted, (\d+) packets received, ([0-9.]+)% packet loss", output)
            if packets:
                result["packets_sent"] = int(packets.group(1))
                result["packets_received"] = int(packets.group(2))
                result["packet_loss"] = float(packets.group(3))

            times = re.search(r"round-trip min/avg/max/stddev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)", output)
            if times:
                result["min_rtt"] = float(times.group(1))
                result["avg_rtt"] = float(times.group(2))
                result["max_rtt"] = float(times.group(3))

        elif self.os_type == "windows":
            patterns = [
                r"Sent = (\d+), Received = (\d+)",
                r"Packets: Sent = (\d+), Received = (\d+)",
                r"(\d+) packets transmitted, (\d+) (packets received|received)"
            ]
            
            for pattern in patterns:
                packets = re.search(pattern, output)
                if packets:
                    result["packets_sent"] = int(packets.group(1))
                    result["packets_received"] = int(packets.group(2))
                    break

            time_patterns = [
                r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms",
                r"Minimum = ([0-9.]+)ms, Maximum = ([0-9.]+)ms, Average = ([0-9.]+)ms",
                r"min/avg/max/[^=]*= ([0-9.]+)/([0-9.]+)/([0-9.]+)"
            ]
            
            for pattern in time_patterns:
                times = re.search(pattern, output)
                if times:
                    result["min_rtt"] = float(times.group(1))
                    result["max_rtt"] = float(times.group(2))
                    result["avg_rtt"] = float(times.group(3))
                    break
        else:
            patterns = [
                r"(\d+) packets transmitted, (\d+) (packets received|received)",
                r"(\d+) packets transmitted, (\d+) (packets received|received)",
                r"Sent = (\d+), Received = (\d+)"
            ]
            
            for pattern in patterns:
                packets = re.search(pattern, output)
                if packets:
                    result["packets_sent"] = int(packets.group(1))
                    result["packets_received"] = int(packets.group(2))
                    break

            # Multiple  patterns for Linux/Unix
            time_patterns = [
                r"min/avg/max/[^=]*= ([0-9.]+)/([0-9.]+)/([0-9.]+)",
                r"rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)",
                r"Minimum = ([0-9.]+)ms, Maximum = ([0-9.]+)ms, Average = ([0-9.]+)ms"
            ]
            
            for pattern in time_patterns:
                times = re.search(pattern, output)
                if times:
                    result["min_rtt"] = float(times.group(1))
                    result["max_rtt"] = float(times.group(2))
                    result["avg_rtt"] = float(times.group(3))
                    break

        # packet loss if we have valid packet counts
        if result["packets_sent"] > 0:
            result["packet_loss"] = 100 - (result["packets_received"] / result["packets_sent"] * 100)

        return result
    
    # check ports
    def check_port(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            
            return {
                "port": port,
                "status": "open" if result == 0 else "closed",
                "service": self._get_common_service_name(port)
            }
        except socket.gaierror:
            return {"port": port, "status": "error", "error": "Could not resolve hostname"}
        except Exception as e:
            return {"port": port, "status": "error", "error": str(e)}
        
    def _get_common_service_name(self, port):
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            27017: "MongoDB"
        }
        return common_ports.get(port, "Unknown")

    # DNS lookup
    def dns_lookup(self, host):
        results = {
            "hostname": host,
            "records": {}
        }
        
        try:
            # A record (IPv4)
            results["records"]["A"] = socket.gethostbyname(host)
            
            # all available records
            all_records = socket.getaddrinfo(host, None)
            
            # unique IPv6 addresses
            ipv6_addresses = set()
            for record in all_records:
                if record[0] == socket.AF_INET6:
                    ipv6_addresses.add(record[4][0])
            
            if ipv6_addresses:
                results["records"]["AAAA"] = list(ipv6_addresses)
                
        except socket.gaierror as e:
            results["error"] = f"DNS lookup failed: {str(e)}"
        
        return results
    
    def run_diagnostics(self, host, ports=[80, 443, 22, 21]):
        results = {
            "timestamp": datetime.now().isoformat(),
            "host": host,
            "ping_test": self.ping(host),
            "dns_lookup": self.dns_lookup(host),
            "port_scan": [self.check_port(host, port) for port in ports]
        }
        
        return results

def format_diagnostics_results(results):
    output = []
    
    output.append(f"Network Diagnostics Report")
    output.append(f"Timestamp: {results['timestamp']}")
    output.append(f"Host: {results['host']}")
    output.append("")
    
    # DNS Information
    output.append("DNS Lookup Results:")
    dns_results = results['dns_lookup']
    if "error" in dns_results:
        output.append(f"  Error: {dns_results['error']}")
    else:
        for record_type, value in dns_results['records'].items():
            if isinstance(value, list):
                for v in value:
                    output.append(f"  {record_type}: {v}")
            else:
                output.append(f"  {record_type}: {value}")
    output.append("")
    
    # Ping Results
    output.append("Ping Results:")
    ping_results = results['ping_test']
    if ping_results['status'] == 'success':
        output.append(f"  Packets: Sent={ping_results['packets_sent']}, "
                     f"Received={ping_results['packets_received']}, "
                     f"Lost={ping_results['packet_loss']}%")
        if ping_results['avg_rtt']:
            output.append(f"  Round-trip time (ms): "
                         f"min={ping_results['min_rtt']}, "
                         f"avg={ping_results['avg_rtt']}, "
                         f"max={ping_results['max_rtt']}")
    else:
        output.append(f"  Error: {ping_results.get('error', 'Unknown error')}")
    output.append("")
    
    # Port Scan Results
    output.append("Port Scan Results:")
    for port_result in results['port_scan']:
        status = port_result['status']
        if status == 'open':
            output.append(f"  Port {port_result['port']} ({port_result['service']}): {status}")
        elif status == 'error':
            output.append(f"  Port {port_result['port']}: Error - {port_result['error']}")
        else:
            output.append(f"  Port {port_result['port']}: {status}")
    
    return "\n".join(output)

if __name__ == "__main__":
    diagnostics = NetworkDiagnostics()
    
    host = "google.com"
    print(f"Running network diagnostics for {host}...")
    
    results = diagnostics.run_diagnostics(host)
    print("\n" + format_diagnostics_results(results))