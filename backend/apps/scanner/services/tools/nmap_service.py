import nmap
import logging
import shutil

logger = logging.getLogger(__name__)

class NmapService:
    @staticmethod
    def is_available():
        return shutil.which("nmap") is not None

    @staticmethod
    def run_scan(target_ip, ports="1-1000", arguments="-sV -T4"):
        """
        Runs an Nmap scan.
        """
        if not NmapService.is_available():
            return {
                "error": "Nmap not found",
                "details": "Please install nmap on the server (e.g., 'winget install Insecure.Nmap' or 'apt install nmap')."
            }

        try:
            nm = nmap.PortScanner()
            logger.info(f"Starting Nmap scan on {target_ip} ports={ports}")
            
            # Scan synchronously (for this simple tool interface)
            # arguments: -sV (Version detection), -T4 (Aggressive timing)
            # You might want to restrict arguments for security in a real app.
            nm.scan(hosts=target_ip, ports=ports, arguments=arguments)
            
            # Parse results
            scan_data = []
            for host in nm.all_hosts():
                host_data = {
                    "host": host,
                    "state": nm[host].state(),
                    "protocols": []
                }
                
                for proto in nm[host].all_protocols():
                    proto_data = {"protocol": proto, "ports": []}
                    lport = nm[host][proto].keys()
                    for port in sorted(lport):
                        service = nm[host][proto][port]
                        proto_data["ports"].append({
                            "port": port,
                            "state": service['state'],
                            "name": service['name'],
                            "product": service['product'],
                            "version": service['version']
                        })
                    host_data["protocols"].append(proto_data)
                
                scan_data.append(host_data)

            return {
                "status": "success",
                "command": nm.command_line(),
                "results": scan_data
            }

        except nmap.PortScannerError as e:
            return {"error": f"Nmap execution failed: {str(e)}"}
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return {"error": str(e)}
