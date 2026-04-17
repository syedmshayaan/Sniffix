# ============================================================
# portscan.py
# ============================================================
# This module handles scanning a SPECIFIC device (by IP address)
# to find:
#   - Which ports are open
#   - What service/software is running on each port
#   - The device's operating system (best guess)
#   - The MAC address vendor (who manufactured the network card)
#
# HOW IT WORKS:
#   We use nmap (Network Mapper) — the industry-standard open-source
#   network scanning tool — via the python-nmap wrapper library.
#
#   nmap sends specially crafted TCP/UDP packets to each port on
#   the target device and analyzes the responses to determine
#   whether a port is open, closed, or filtered.
#
# PORT STATES:
#   open     — something is actively listening on this port
#   closed   — port is reachable but nothing is listening
#   filtered — a firewall is blocking our probe packets
#
# NOTE: This requires nmap to be installed on the OS.
#       Install with: sudo apt install nmap (Linux)
#                  or: brew install nmap (Mac)
# ============================================================

import nmap    # python-nmap: a Python wrapper around the nmap command-line tool


def scan_device(ip_address):
    """
    Performs a comprehensive scan on a single target device.

    Scan flags used:
        -sV   : Version detection — identifies what software is running on each port
                (e.g. port 22 → OpenSSH 8.2)
        -O    : OS detection — nmap guesses the operating system based on TCP/IP behavior
        -T4   : Timing template 4 (aggressive) — faster scan, good for local networks
        --open: Only show ports that are confirmed OPEN (skip closed/filtered)

    Args:
        ip_address (str): The IP address of the device to scan (e.g. "192.168.1.5")

    Returns:
        dict: A dictionary containing:
              - 'ip'       : The scanned IP address
              - 'hostname' : Hostname reported by nmap (if any)
              - 'os'       : Best OS guess from nmap
              - 'mac'      : MAC address (if available)
              - 'vendor'   : MAC vendor / manufacturer name
              - 'ports'    : List of open ports, each with:
                               - 'port'    : Port number (e.g. 80)
                               - 'protocol': "tcp" or "udp"
                               - 'state'   : "open", "closed", or "filtered"
                               - 'service' : Service name (e.g. "http")
                               - 'version' : Software version string (e.g. "Apache 2.4.1")
    """

    # Create a new nmap PortScanner instance
    # This is the object we use to run scans and read results
    nm = nmap.PortScanner()

    print(f"[*] Starting port scan on {ip_address} ...")

    # --- Run the nmap scan ---
    # arguments="-sV -O -T4 --open" passes these flags to the nmap CLI tool
    # This may take 30–90 seconds depending on the device and network
    nm.scan(hosts=ip_address, arguments="-sV -T4 --open --host-timeout 60s -F")

    # If nmap couldn't reach the host or got no results, return an error dict
    if ip_address not in nm.all_hosts():
        print(f"[!] Host {ip_address} did not respond to scan.")
        return {
            "ip": ip_address,
            "error": "Host did not respond or is unreachable."
        }

    # --- Extract host-level info ---
    host_data = nm[ip_address]    # nm[ip] gives us the full result object for that host

    # Hostname: nmap sometimes resolves this, sometimes not
    # We grab the first hostname entry if available
    hostname = "Unknown"
    if host_data.hostname():
        hostname = host_data.hostname()

    # --- OS Detection ---
    # nmap's OS detection returns a list of "matches" with confidence percentages
    # We pick the most accurate guess (first one in the sorted list)
    os_guess = "Unknown"
    if "osmatch" in host_data and len(host_data["osmatch"]) > 0:
        os_guess = host_data["osmatch"][0]["name"]    # e.g. "Linux 4.15 - 5.6"

    # --- MAC Address and Vendor ---
    # MAC addresses are only visible for devices on the SAME local network segment
    # (they don't travel across routers)
    mac_address = "Unknown"
    vendor = "Unknown"

    if "mac" in host_data["addresses"]:
        mac_address = host_data["addresses"]["mac"]

    if "vendor" in host_data and mac_address in host_data["vendor"]:
        vendor = host_data["vendor"][mac_address]   # e.g. "Apple, Inc." or "Raspberry Pi Foundation"

    # --- Port Scanning Results ---
    open_ports = []

    # Loop through each protocol (typically "tcp" and/or "udp")
    for protocol in host_data.all_protocols():

        # Get a sorted list of port numbers for this protocol
        port_list = sorted(host_data[protocol].keys())

        for port in port_list:
            port_info = host_data[protocol][port]

            # We only care about open ports (--open flag should handle this, but double-checking)
            if port_info["state"] == "open":

                open_ports.append({
                    "port": port,                          # e.g. 80
                    "protocol": protocol,                  # e.g. "tcp"
                    "state": port_info["state"],           # "open"
                    "service": port_info["name"],          # e.g. "http"
                    "version": (
                        # Combine product name + version string + extra info if available
                        f"{port_info.get('product', '')} "
                        f"{port_info.get('version', '')} "
                        f"{port_info.get('extrainfo', '')}"
                    ).strip() or "N/A"                     # If nothing, show "N/A"
                })

    print(f"[+] Scan complete. Found {len(open_ports)} open port(s).")

    # --- Build and return the final result dictionary ---
    return {
        "ip": ip_address,
        "hostname": hostname,
        "os": os_guess,
        "mac": mac_address,
        "vendor": vendor,
        "ports": open_ports
    }
