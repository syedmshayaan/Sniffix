# ============================================================
# network.py
# ============================================================
# This module is responsible for discovering all devices
# currently connected to the same local network as this machine.
#
# HOW IT WORKS:
#   We use a technique called an ARP (Address Resolution Protocol)
#   broadcast. Basically, we shout onto the network:
#   "Hey! Who's out there? Tell me your IP and MAC address!"
#   Every active device on the network shouts back.
#
# WHY SCAPY?
#   Scapy is a powerful Python library that lets us craft and
#   send raw network packets — things that normal libraries
#   like requests or socket can't do.
# ============================================================

import socket                        # Built-in Python library for hostname resolution
from scapy.layers.l2 import ARP, Ether   # ARP = Address Resolution Protocol packet
                                          # Ether = Ethernet frame (the wrapper around ARP)
from scapy.sendrecv import srp       # srp = Send and Receive Packets (layer 2)


def get_local_subnet():
    """
    Automatically figures out what subnet (network range) this
    machine is on, so we know what range of IPs to scan.

    For example, if this machine's IP is 192.168.1.5,
    the subnet would be 192.168.1.0/24
    (meaning: scan all IPs from 192.168.1.1 to 192.168.1.254)

    Returns:
        str: subnet in CIDR notation e.g. "192.168.1.0/24"
    """

    # Create a temporary UDP socket just to find our own IP
    # We connect to an external IP (doesn't actually send data)
    # just to let the OS figure out our outbound network interface
    temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        temp_socket.connect(("8.8.8.8", 80))      # Google DNS — just used as a target to determine our IP
        local_ip = temp_socket.getsockname()[0]    # Our actual local IP (e.g. 192.168.1.5)
    finally:
        temp_socket.close()

    # Split the IP into 4 parts (octets): ['192', '168', '1', '5']
    octets = local_ip.split(".")

    # Build the subnet by keeping the first 3 octets and setting the last to 0
    # Then append /24 which means "scan all 254 addresses in this range"
    subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"

    return subnet


def scan_network():
    """
    Performs an ARP scan on the local subnet to discover
    all active devices.

    Steps:
        1. Figure out the local subnet
        2. Craft an ARP request packet
        3. Wrap it in an Ethernet broadcast frame
        4. Send it out and collect responses
        5. Parse responses into a clean list of devices

    Returns:
        list[dict]: A list of devices, each with:
                    - 'ip'       : IP address (e.g. "192.168.1.1")
                    - 'mac'      : MAC address (e.g. "aa:bb:cc:dd:ee:ff")
                    - 'hostname' : Human-readable name if available, else "Unknown"
    """

    subnet = get_local_subnet()
    print(f"[*] Scanning subnet: {subnet}")

    # --- Step 1: Craft the ARP packet ---
    # ARP packet asking "who has IP X? tell me your MAC"
    # pdst = "protocol destination" = the IP range to ask about
    arp_packet = ARP(pdst=subnet)

    # --- Step 2: Wrap in an Ethernet broadcast frame ---
    # hwdst="ff:ff:ff:ff:ff:ff" means BROADCAST — send to everyone on the network
    ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Stack the Ethernet frame ON TOP of the ARP packet (like an envelope around a letter)
    combined_packet = ethernet_frame / arp_packet

    # --- Step 3: Send the packet and collect replies ---
    # srp() = send & receive at layer 2 (data link layer)
    # timeout=2 means wait 2 seconds for responses
    # verbose=False means don't print raw scapy output to the terminal
    answered, unanswered = srp(combined_packet, timeout=2, verbose=False)

    # --- Step 4: Parse the responses ---
    devices = []

    # 'answered' is a list of (sent_packet, received_response) pairs
    for sent, received in answered:

        # Try to resolve the IP to a hostname (e.g. "router.local")
        # If it fails (many devices don't respond to DNS), just say "Unknown"
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = "Unknown"

        # Build a dictionary for this device and add it to the list
        devices.append({
            "ip": received.psrc,         # psrc = "protocol source" = the device's IP
            "mac": received.hwsrc,       # hwsrc = "hardware source" = the device's MAC address
            "hostname": hostname
        })

    print(f"[+] Found {len(devices)} device(s) on the network.")
    return devices
