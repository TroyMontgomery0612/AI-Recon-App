import nmap

def scan_target_ports(target):
    try:
        nm = nmap.PortScanner()
        # -sT is a TCP Connect scan (doesn't need root)
        # -T4 is fast timing
        # --top-ports 20 checks the most common doors (web, ssh, dns)
        print(f"DEBUG: Starting TCP Connect scan on {target}...")
        nm.scan(target, arguments='-sT -T4 --top-ports 20')
        
        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    results.append({
                        "port": port,
                        "service": nm[host][proto][port]['name'],
                        "state": nm[host][proto][port]['state']
                    })
        
        print(f"DEBUG: Scan complete. Found {len(results)} ports.")
        return results
        
    except Exception as e:
        print(f"DEBUG: Nmap Scan Exception -> {str(e)}")
        return []