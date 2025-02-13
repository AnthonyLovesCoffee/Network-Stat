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