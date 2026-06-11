import nmap

def scan_ports(ip):
    scanner = nmap.PortScanner()
    try:
        # -sS: Stealth Scan (Professional aur fast)
        # -Pn: No Ping (Firewall bypass karne mein madad karta hai)
        # -T4: Fast speed (Wapis fast scanning ke liye)
        scanner.scan(ip, '1-1024', arguments='-sS -Pn -T4')
    except Exception as e:
        print(f"Scan error: {e}")
        return []

    open_ports = []
    if ip in scanner.all_hosts():
        host = scanner[ip]
        if 'tcp' in host:
            for port in host['tcp']:
                if host['tcp'][port]['state'] == "open":
                    open_ports.append(port)
    return open_ports

def check_danger_ports(ports):
    # Dangerous ports list
    danger_ports = [21, 23, 80, 443, 3389]
    return [port for port in ports if port in danger_ports]