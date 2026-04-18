# ============================================================
# network.py
# ============================================================
# Discovers all devices on the local network using ARP.
# Automatically detects the subnet and interface — no hardcoding.
# ============================================================

import socket
import subprocess
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


def get_default_interface():
    """
    Finds the active network interface by reading the system's
    default route. This is the interface currently used for
    internet traffic — i.e. the one connected to the network
    we want to scan.

    Returns:
        str: interface name e.g. "wlan0", "enp0s3", "eth0"
    """
    try:
        # 'ip route' lists all routes. The default route line looks like:
        # "default via 192.168.29.1 dev wlan0 proto dhcp ..."
        # We grab the interface name from that line.
        result = subprocess.check_output(["ip", "route"], text=True)
        for line in result.splitlines():
            if line.startswith("default"):
                # Line format: default via X.X.X.X dev <INTERFACE> ...
                parts = line.split()
                dev_index = parts.index("dev")
                return parts[dev_index + 1]   # e.g. "wlan0"
    except Exception as e:
        print(f"[!] Could not detect interface via ip route: {e}")

    return None


def get_subnet_for_interface(iface):
    """
    Given an interface name, finds its IP address and derives
    the /24 subnet to scan.

    For example: interface "wlan0" has IP "10.0.0.5"
                 → returns "10.0.0.0/24"

    Args:
        iface (str): Network interface name

    Returns:
        str: Subnet in CIDR notation e.g. "10.0.0.0/24"
    """
    try:
        # 'ip -4 addr show <iface>' shows the IPv4 address of the interface
        # Output contains a line like: "inet 192.168.29.90/24 brd ..."
        result = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface], text=True
        )
        for line in result.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                # Extract "192.168.29.90/24" from "inet 192.168.29.90/24 brd ..."
                ip_cidr = line.split()[1]           # e.g. "192.168.29.90/24"
                ip      = ip_cidr.split("/")[0]     # e.g. "192.168.29.90"
                octets  = ip.split(".")
                subnet  = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                return subnet
    except Exception as e:
        print(f"[!] Could not get subnet for {iface}: {e}")

    return None


def scan_network():
    """
    Auto-detects the active interface and subnet, then performs
    an ARP scan to discover all devices on the network.

    Returns:
        list[dict]: Each device has 'ip', 'mac', 'hostname'
    """

    # Step 1: Find active interface
    iface = get_default_interface()
    if not iface:
        raise RuntimeError("Could not detect active network interface.")
    print(f"[*] Active interface: {iface}")

    # Step 2: Derive subnet from interface IP
    subnet = get_subnet_for_interface(iface)
    if not subnet:
        raise RuntimeError(f"Could not determine subnet for interface {iface}.")
    print(f"[*] Scanning subnet: {subnet} on interface: {iface}")

    # Step 3: Craft and send ARP broadcast
    arp_packet     = ARP(pdst=subnet)
    ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    combined       = ethernet_frame / arp_packet

    # Send 3 ARP bursts — phones in deep sleep often miss a single
    # broadcast but wake up and respond to subsequent probes.
    # We deduplicate responses across all bursts using a dict keyed by IP.
    seen_ips = {}

    for burst in range(3):
        print(f"[*] ARP burst {burst + 1}/3 ...")
        answered, _ = srp(combined, iface=iface, timeout=3, verbose=False)

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


# NOTE: The scan_network() function above already handles
# multi-burst scanning via the loop below.
# If you still miss phones, ask them to:
#   1. Keep screen ON and unlocked
#   2. Disable "Private Wi-Fi Address" in iPhone Wi-Fi settings
#   3. Disable battery saver on Android
