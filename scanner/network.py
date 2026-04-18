# ============================================================
# network.py
# ============================================================
# Discovers all devices on the local network using ARP.
# Automatically detects the OS and uses the correct method
# to find the active network interface and subnet.
#
# Linux : uses 'ip route' and 'ip addr' commands
# Windows: uses Python's socket library directly
# ============================================================

import socket
import platform
import subprocess
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


def get_subnet():
    """
    Detects the current OS and uses the appropriate method
    to find the local machine's IP and derive the subnet.

    Returns:
        tuple: (subnet, iface)
               subnet — e.g. "192.168.29.0/24"
               iface  — interface name (Linux) or None (Windows)
    """
    os_type = platform.system()   # "Windows", "Linux", or "Darwin" (Mac)
    print(f"[*] Detected OS: {os_type}")

    if os_type == "Windows":
        return get_subnet_windows()
    else:
        return get_subnet_linux()


def get_subnet_windows():
    """
    On Windows, we use Python's socket library to find the
    local IP address, then derive the /24 subnet from it.

    We don't need an interface name on Windows — scapy
    auto-selects the correct adapter.

    Returns:
        tuple: (subnet, None)
    """
    try:
        # Connect a UDP socket to an external address (no data is sent)
        # This tricks Python into revealing which IP the OS would use
        # for outbound traffic — i.e. our actual local IP
        temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp.connect(("8.8.8.8", 80))
        local_ip = temp.getsockname()[0]
        temp.close()

        print(f"[*] Local IP (Windows): {local_ip}")

        # Derive /24 subnet from IP
        # e.g. "192.168.29.90" → "192.168.29.0/24"
        octets = local_ip.split(".")
        subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        return subnet, None

    except Exception as e:
        raise RuntimeError(f"Could not detect subnet on Windows: {e}")


def get_subnet_linux():
    """
    On Linux, we use 'ip route' to find the active interface,
    then 'ip addr' to get its IP and derive the subnet.

    Returns:
        tuple: (subnet, iface)
    """
    try:
        # Find default route interface
        result = subprocess.check_output(["ip", "route"], text=True)
        iface  = None

        for line in result.splitlines():
            if line.startswith("default"):
                parts     = line.split()
                dev_index = parts.index("dev")
                iface     = parts[dev_index + 1]
                break

        if not iface:
            raise RuntimeError("No default route found.")

        print(f"[*] Active interface (Linux): {iface}")

        # Get IP address of that interface
        result = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface], text=True
        )
        for line in result.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                ip_cidr = line.split()[1]
                ip      = ip_cidr.split("/")[0]
                octets  = ip.split(".")
                subnet  = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                return subnet, iface

        raise RuntimeError(f"Could not find IP for interface {iface}.")

    except Exception as e:
        raise RuntimeError(f"Could not detect subnet on Linux: {e}")


def scan_network():
    """
    Auto-detects subnet and interface, then performs a
    multi-burst ARP scan to discover all devices.

    Multiple bursts help catch phones in deep sleep that
    miss a single broadcast.

    Returns:
        list[dict]: Each device has 'ip', 'mac', 'hostname'
    """

    # Step 1: Get subnet and interface
    subnet, iface = get_subnet()
    print(f"[*] Scanning: {subnet} | Interface: {iface or 'auto'}")

    # Step 2: Craft ARP broadcast packet
    arp_packet     = ARP(pdst=subnet)
    ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    combined       = ethernet_frame / arp_packet

    # Step 3: Send 3 ARP bursts to catch sleeping phones
    seen_ips = {}   # Keyed by IP to deduplicate across bursts

    for burst in range(3):
        print(f"[*] ARP burst {burst + 1}/3 ...")

        # On Linux: pass iface explicitly
        # On Windows: let scapy auto-select (iface=None is ignored below)
        kwargs = {"timeout": 3, "verbose": False}
        if iface:
            kwargs["iface"] = iface

        answered, _ = srp(combined, **kwargs)

        for sent, received in answered:
            ip = received.psrc
            if ip not in seen_ips:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = "Unknown"

                seen_ips[ip] = {
                    "ip":       ip,
                    "mac":      received.hwsrc,
                    "hostname": hostname
                }

    devices = list(seen_ips.values())
    print(f"[+] Found {len(devices)} device(s) on {subnet}.")
    return devices
