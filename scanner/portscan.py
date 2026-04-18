# ============================================================
# portscan.py — Socket-based Port Scanner
# ============================================================
# Uses concurrent.futures.ThreadPoolExecutor instead of
# threading.Thread directly — this avoids conflicts with
# eventlet's monkey-patching of Python's socket/thread libs.
# ============================================================

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Well-known port → service name mapping
COMMON_SERVICES = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    123:   "NTP",
    135:   "MS RPC",
    139:   "NetBIOS",
    143:   "IMAP",
    161:   "SNMP",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    587:   "SMTP TLS",
    631:   "IPP Printer",
    993:   "IMAPS",
    995:   "POP3S",
    1080:  "SOCKS Proxy",
    1433:  "MS SQL",
    1521:  "Oracle DB",
    1723:  "PPTP VPN",
    2049:  "NFS",
    2222:  "SSH Alt",
    3000:  "Dev Server",
    3306:  "MySQL",
    3389:  "RDP",
    4444:  "Metasploit",
    5000:  "Flask/UPnP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8000:  "HTTP Alt",
    8080:  "HTTP Proxy",
    8443:  "HTTPS Alt",
    8888:  "Jupyter",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

TOP_PORTS  = list(COMMON_SERVICES.keys())
TIMEOUT    = 1      # seconds per port attempt
MAX_WORKERS = 50    # concurrent threads in the pool


def check_port(ip, port):
    """
    Attempts a TCP connection to ip:port.

    Returns:
        dict if port is open, None if closed/filtered
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            return {
                "port":     port,
                "protocol": "tcp",
                "state":    "open",
                "service":  COMMON_SERVICES.get(port, "Unknown"),
                "version":  "N/A"
            }
    except Exception:
        pass
    return None


def scan_device(ip_address, socketio=None):
    """
    Scans a target IP for open ports using a thread pool.

    Args:
        ip_address (str)     : Target IP
        socketio   (SocketIO): Optional, emits live progress to browser

    Returns:
        dict: open ports + basic device info
    """
    print(f"[*] Scanning {ip_address} — {len(TOP_PORTS)} ports")

    open_ports  = []
    total       = len(TOP_PORTS)
    completed   = 0

    if socketio:
        socketio.emit("scan_progress", {
            "message": f"Starting scan on {ip_address}...",
            "percent": 0
        })

    # ThreadPoolExecutor is safer with eventlet than raw threading.Thread
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        # Submit all port checks at once
        futures = {
            executor.submit(check_port, ip_address, port): port
            for port in TOP_PORTS
        }

        # Process results as each thread finishes
        for future in as_completed(futures):
            completed += 1
            result = future.result()

            if result:
                open_ports.append(result)
                print(f"  [+] Open: {result['port']} ({result['service']})")

            # Emit progress update every 5 completions
            if socketio and completed % 5 == 0:
                percent = int((completed / total) * 100)
                socketio.emit("scan_progress", {
                    "message": f"Scanning... {completed}/{total} ports checked",
                    "percent": percent
                })

    open_ports.sort(key=lambda x: x["port"])
    print(f"[+] Scan complete — {len(open_ports)} open port(s) on {ip_address}")

    # Basic device info via reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        hostname = "Unknown"

    if socketio:
        socketio.emit("scan_progress", {
            "message": f"Done! Found {len(open_ports)} open port(s).",
            "percent": 100
        })

    return {
        "ip":       ip_address,
        "hostname": hostname,
        "os":       "N/A",
        "mac":      "See network scan above",
        "vendor":   "See network scan above",
        "ports":    open_ports
    }
