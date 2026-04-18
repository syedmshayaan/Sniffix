# ============================================================
# portscan.py — Custom Port Scanner using Python Sockets
# ============================================================
# Instead of using nmap (which is slow), we write our own
# port scanner using Python's built-in 'socket' library.
#
# HOW IT WORKS:
#   For each port we want to check, we attempt to open a
#   TCP connection to that port on the target device.
#   - If the connection SUCCEEDS → port is OPEN
#   - If the connection is REFUSED → port is CLOSED
#   - If it TIMES OUT → port is FILTERED (firewall blocking)
#
# We use THREADING to scan multiple ports simultaneously
# instead of one by one — this makes it dramatically faster.
#
# WHY SOCKETS OVER NMAP:
#   nmap is powerful but slow for demos. Python's socket
#   library gives us direct control and instant feedback.
# ============================================================

import socket
import threading

# ============================================================
# WELL-KNOWN PORTS DICTIONARY
# Maps port numbers to their common service names.
# ============================================================
COMMON_SERVICES = {
    20:    "FTP Data",
    21:    "FTP Control",
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
    1433:  "MS SQL Server",
    1521:  "Oracle DB",
    1723:  "PPTP VPN",
    2049:  "NFS",
    2222:  "SSH Alternate",
    3000:  "Dev Server",
    3306:  "MySQL",
    3389:  "RDP (Remote Desktop)",
    4444:  "Metasploit",
    5000:  "Flask / UPnP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8000:  "HTTP Alt",
    8080:  "HTTP Proxy",
    8443:  "HTTPS Alt",
    8888:  "Jupyter Notebook",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

# Ports to scan
TOP_PORTS = list(COMMON_SERVICES.keys())

# Timeout per port (seconds) — keep low for speed
TIMEOUT = 0.5

# Max simultaneous threads
MAX_THREADS = 100


def check_port(ip, port, open_ports, lock):
    """
    Attempts a TCP connection to a single port.
    Adds to open_ports list if successful.

    Args:
        ip         (str)  : Target IP
        port       (int)  : Port to check
        open_ports (list) : Shared results list
        lock       (Lock) : Thread lock for safe list writes
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            # Port is open — log it
            with lock:
                open_ports.append({
                    "port":     port,
                    "protocol": "tcp",
                    "state":    "open",
                    "service":  COMMON_SERVICES.get(port, "Unknown"),
                    "version":  "N/A"
                })
    except (socket.timeout, socket.error):
        pass


def get_device_info(ip):
    """
    Gets basic device info (hostname via reverse DNS).
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Unknown"

    return {
        "hostname": hostname,
        "os":       "N/A (nmap -O disabled for speed)",
        "mac":      "See network scan above",
        "vendor":   "See network scan above"
    }


def scan_device(ip_address, socketio=None):
    """
    Multithreaded TCP port scan on a target IP.

    Args:
        ip_address (str)     : Target IP
        socketio   (SocketIO): Optional, for live browser updates

    Returns:
        dict: open ports + device info
    """
    print(f"[*] Socket scan starting on {ip_address} — {len(TOP_PORTS)} ports, {MAX_THREADS} threads")

    open_ports = []
    lock = threading.Lock()
    threads = []
    total = len(TOP_PORTS)

    if socketio:
        socketio.emit("scan_progress", {"message": f"Scanning {total} ports on {ip_address}...", "percent": 0})

    for i, port in enumerate(TOP_PORTS):
        t = threading.Thread(target=check_port, args=(ip_address, port, open_ports, lock))
        t.daemon = True
        threads.append(t)
        t.start()

        # Emit progress every 10 ports
        if socketio and i % 10 == 0:
            socketio.emit("scan_progress", {
                "message": f"Scanning... ({i}/{total} ports)",
                "percent": int((i / total) * 100)
            })

        # Batch: wait when we hit thread limit
        if len(threads) >= MAX_THREADS:
            for t in threads:
                t.join()
            threads = []

    # Wait for remaining threads
    for t in threads:
        t.join()

    open_ports.sort(key=lambda x: x["port"])
    print(f"[+] Done. {len(open_ports)} open port(s) on {ip_address}.")

    info = get_device_info(ip_address)

    if socketio:
        socketio.emit("scan_progress", {"message": f"Done! {len(open_ports)} open port(s) found.", "percent": 100})

    return {
        "ip":       ip_address,
        "hostname": info["hostname"],
        "os":       info["os"],
        "mac":      info["mac"],
        "vendor":   info["vendor"],
        "ports":    open_ports
    }
