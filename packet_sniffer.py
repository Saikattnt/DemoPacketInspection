import sys
import time
import argparse
import threading
from datetime import datetime
from queue import Queue, Empty

# Ensure Windows terminal doesn't crash on character encoding
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

from scapy.all import sniff, conf, IFACES, get_working_ifaces, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR

# 1. FIFO Queue Data Structure
# Python's queue.Queue implements a thread-safe First-In, First-Out (FIFO) queue.
packet_queue = Queue()

# Event to coordinate clean shutdown across threads
stop_event = threading.Event()

# Packet statistics counter
packet_stats = {
    "total": 0,
    "ipv4": 0,
    "ipv6": 0,
    "tcp": 0,
    "udp": 0,
    "dns": 0,
    "https_tls": 0,
    "http": 0,
    "quic": 0,
    "arp": 0,
    "other": 0,
}
stats_lock = threading.Lock()


def get_default_interface():
    """
    Automatically detects the active network interface connected to the internet.
    Fixes the Windows Scapy issue where conf.iface defaults to an inactive or virtual adapter.
    """
    # Method 1: Ask Scapy's routing table which interface reaches public internet (8.8.8.8)
    try:
        route_dev = conf.route.route("8.8.8.8")[0]
        if route_dev:
            iface = IFACES.get(route_dev)
            if iface:
                return iface
    except Exception:
        pass

    # Method 2: Check working interfaces for a valid, routable local IP (192.168.x.x, 10.x.x.x, etc.)
    candidates = []
    for iface in get_working_ifaces():
        ip = getattr(iface, "ip", None)
        if not ip or ip.startswith("127.") or ip.startswith("169.254."):
            continue
        desc = getattr(iface, "description", "").lower()
        name = getattr(iface, "name", "").lower()
        is_virtual = any(k in desc or k in name for k in ("virtualbox", "vmware", "radmin", "pseudo", "loopback"))
        candidates.append((1 if is_virtual else 0, iface))

    if candidates:
        candidates.sort(key=lambda x: x[0])
        return candidates[0][1]

    # Method 3: Fall back to Scapy's default
    return conf.iface


def resolve_interface(target):
    """
    Resolves a user-provided interface name, description, or IP address into a Scapy interface.
    """
    if not target:
        return get_default_interface()

    target_str = str(target).strip()
    for iface in get_working_ifaces():
        name = getattr(iface, "name", "")
        desc = getattr(iface, "description", "")
        ip = getattr(iface, "ip", "")
        net_name = getattr(iface, "network_name", "")

        if target_str.lower() == name.lower():
            return iface
        if target_str.lower() in desc.lower():
            return iface
        if target_str == ip or target_str == net_name:
            return iface

    # If no match in working ifaces, return target directly (Scapy will attempt resolution)
    return target


def list_available_interfaces():
    """
    Prints a table of all available network interfaces for easy inspection.
    """
    print("\nAvailable Network Interfaces:")
    print("-" * 80)
    print(f"{'Interface Name':<28} | {'IP Address':<16} | {'Description'}")
    print("-" * 80)
    for iface in get_working_ifaces():
        name = getattr(iface, "name", "N/A")[:27]
        ip = getattr(iface, "ip", "No IP")[:15]
        desc = getattr(iface, "description", "N/A")
        print(f"{name:<28} | {ip:<16} | {desc}")
    print("-" * 80)
    default_if = get_default_interface()
    def_name = getattr(default_if, "name", default_if)
    def_desc = getattr(default_if, "description", "N/A")
    print(f"[*] Auto-detected Internet Interface: {def_name} ({def_desc})\n")


def extract_tls_sni(payload):
    """
    Fast, lightweight byte parser to extract the Server Name Indication (SNI) from TLS ClientHello.
    This lets us identify the domain of HTTPS websites (e.g. www.google.com, github.com)
    without needing heavy external cryptography libraries.
    """
    if len(payload) < 43 or payload[0] != 0x16:  # 0x16 = Handshake record
        return None
    if payload[5] != 0x01:  # 0x01 = ClientHello
        return None

    try:
        sess_id_len = payload[43]
        pos = 44 + sess_id_len
        if pos + 2 > len(payload):
            return None

        cipher_len = int.from_bytes(payload[pos:pos+2], "big")
        pos += 2 + cipher_len
        if pos + 1 > len(payload):
            return None

        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None

        ext_total_len = int.from_bytes(payload[pos:pos+2], "big")
        pos += 2
        ext_end = pos + ext_total_len

        while pos + 4 <= ext_end and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos:pos+2], "big")
            ext_len = int.from_bytes(payload[pos+2:pos+4], "big")
            pos += 4
            if ext_type == 0 and pos + 2 <= len(payload):  # Extension 0 = server_name
                if pos + 5 <= len(payload) and payload[pos+2] == 0:  # Name type 0 = host_name
                    name_len = int.from_bytes(payload[pos+3:pos+5], "big")
                    if pos + 5 + name_len <= len(payload):
                        return payload[pos+5:pos+5+name_len].decode("utf-8", errors="ignore")
            pos += ext_len
    except Exception:
        return None
    return None


def extract_http_info(payload):
    """
    Extracts HTTP request method and Host header, or HTTP response status.
    """
    try:
        text = payload[:1000].decode("latin-1", errors="ignore")
        lines = text.split("\r\n")
        first_line = lines[0].strip()

        methods = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ")
        if any(first_line.startswith(m) for m in methods):
            host = None
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break
            return "request", first_line, host
        elif first_line.startswith("HTTP/1."):
            return "response", first_line, None
    except Exception:
        pass
    return None


def capture_packet(interface=None, packet_count=0, bpf_filter=None):
    """
    Captures network packets using Scapy and puts them into the FIFO queue.
    :param interface: Network interface to sniff on (auto-detects active if None)
    :param packet_count: Number of packets to capture (0 for continuous capture)
    :param bpf_filter: Optional BPF filter string (e.g. 'tcp port 443')
    """
    print(f"[*] capture_packet(): Starting capture on interface: {getattr(interface, 'name', interface)}...")
    if bpf_filter:
        print(f"[*] capture_packet(): Active filter: '{bpf_filter}'")

    def enqueue_packet(packet):
        # FIFO Operation: Put packet at the tail of the queue
        packet_queue.put(packet)

    try:
        sniff(
            iface=interface,
            prn=enqueue_packet,
            filter=bpf_filter,
            count=packet_count if packet_count > 0 else 0,
            stop_filter=lambda x: stop_event.is_set(),
            store=False  # Avoid extra memory consumption in Scapy internal storage
        )
    except Exception as e:
        if not stop_event.is_set():
            print(f"[!] Sniffing error: {e}")
    finally:
        print("[*] capture_packet(): Packet capture stopped.")


def process_packets():
    """
    Consumer function that retrieves packets from the FIFO queue and processes them.
    """
    print("[*] process_packets(): Waiting for packets from FIFO queue...")
    packet_number = 0

    while not stop_event.is_set() or not packet_queue.empty():
        try:
            # FIFO Operation: Get packet from the head of the queue (First-In, First-Out)
            packet = packet_queue.get(timeout=0.5)
            packet_number += 1

            # Process & print packet
            print_packet(packet, packet_number)

            # Notify the queue that the item processing is complete
            packet_queue.task_done()

        except Empty:
            # Queue empty, re-check stop_event
            continue
        except Exception as e:
            print(f"[!] Processing error: {e}")

    print("[*] process_packets(): Processor stopped.")


def print_packet(packet, packet_num=1):
    """
    Prints structured summary, network layer (IPv4/IPv6/ARP), transport layer (TCP/UDP),
    and application layer details (HTTP, HTTPS/TLS SNI, DNS, QUIC/HTTP3).
    """
    timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S.%f")[:-3]
    summary = packet.summary()

    with stats_lock:
        packet_stats["total"] += 1

    print(f"\n[+] Packet #{packet_num} [{timestamp}] - {summary}")

    # --- Layer 3: Network Layer (IPv4 / IPv6 / ARP) ---
    is_ip = False
    src_ip, dst_ip = None, None

    if packet.haslayer(IP):
        is_ip = True
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        ttl = packet[IP].ttl
        with stats_lock:
            packet_stats["ipv4"] += 1
        print(f"    |-- [IPv4] {src_ip} -> {dst_ip} (Protocol: {proto}, TTL: {ttl})")

    elif packet.haslayer(IPv6):
        is_ip = True
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        nh = packet[IPv6].nh
        with stats_lock:
            packet_stats["ipv6"] += 1
        print(f"    |-- [IPv6] {src_ip} -> {dst_ip} (NextHeader: {nh})")

    elif packet.haslayer(ARP):
        with stats_lock:
            packet_stats["arp"] += 1
        arp_op = "Request (Who has?)" if packet[ARP].op == 1 else "Reply"
        print(f"    |-- [ARP] {arp_op} | {packet[ARP].psrc} -> {packet[ARP].pdst}")
        return

    # --- Layer 4: Transport Layer (TCP / UDP / ICMP) ---
    sport, dport = None, None
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        with stats_lock:
            packet_stats["tcp"] += 1
        print(f"    |-- [TCP] Port {sport} -> {dport} [Flags: {flags}]")

    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        with stats_lock:
            packet_stats["udp"] += 1
        print(f"    |-- [UDP] Port {sport} -> {dport}")

    elif packet.haslayer(ICMP):
        print(f"    |-- [ICMP] Type: {packet[ICMP].type}, Code: {packet[ICMP].code}")
        return

    # --- Layer 7: Application / Web Inspection (DNS, HTTPS/TLS, HTTP, QUIC) ---
    # 1. DNS (Domain Name System)
    if packet.haslayer(DNS):
        with stats_lock:
            packet_stats["dns"] += 1
        dns = packet[DNS]
        if dns.qr == 0 and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            qtype = packet[DNSQR].qtype
            type_str = "A" if qtype == 1 else ("AAAA" if qtype == 28 else str(qtype))
            print(f"    \\-- [DNS Query] Lookup Domain: {qname} (Type: {type_str})")
        elif dns.qr == 1:
            answers = []
            if dns.ancount > 0 and dns.an:
                for i in range(dns.ancount):
                    try:
                        rr = dns.an[i]
                        rdata = getattr(rr, "rdata", None)
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode(errors="ignore")
                        answers.append(str(rdata))
                    except Exception:
                        pass
            ans_str = ", ".join(answers[:3]) if answers else "Resolved"
            print(f"    \\-- [DNS Response] Answers: {ans_str}")
        return

    # 2. Inspect Raw Payload for Web Traffic
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw])

        # HTTPS / TLS Handshake (SNI Server Name)
        if (sport == 443 or dport == 443) and packet.haslayer(TCP):
            sni = extract_tls_sni(payload)
            if sni:
                with stats_lock:
                    packet_stats["https_tls"] += 1
                print(f"    \\-- [HTTPS / TLS SNI] Website: https://{sni} (Client Hello)")
                return
            else:
                with stats_lock:
                    packet_stats["https_tls"] += 1
                print(f"    \\-- [HTTPS / TLS] Encrypted Web Traffic ({len(payload)} bytes)")
                return

        # QUIC / HTTP/3 over UDP Port 443
        if (sport == 443 or dport == 443) and packet.haslayer(UDP):
            with stats_lock:
                packet_stats["quic"] += 1
            print(f"    \\-- [QUIC / HTTP/3] Modern Web Traffic ({len(payload)} bytes)")
            return

        # Plaintext HTTP (Port 80, 8080, etc.)
        http_info = extract_http_info(payload)
        if http_info:
            with stats_lock:
                packet_stats["http"] += 1
            kind = http_info[0]
            if kind == "request":
                req_line, host = http_info[1], http_info[2]
                host_str = f"Host: {host}" if host else ""
                print(f"    \\-- [HTTP Request] {req_line} | {host_str}")
            else:
                resp_line = http_info[1]
                print(f"    \\-- [HTTP Response] {resp_line}")
            return


def print_stats():
    """
    Prints a clean summary of captured packets by protocol.
    """
    print("\n" + "=" * 60)
    print("                PACKET CAPTURE SUMMARY")
    print("=" * 60)
    print(f" Total Packets Captured : {packet_stats['total']}")
    print(f"  |-- IPv4 Packets      : {packet_stats['ipv4']}")
    print(f"  |-- IPv6 Packets      : {packet_stats['ipv6']}")
    print(f"  |-- TCP Packets       : {packet_stats['tcp']}")
    print(f"  |-- UDP Packets       : {packet_stats['udp']}")
    print(f"  |-- HTTPS/TLS Packets : {packet_stats['https_tls']}")
    print(f"  |-- HTTP Packets      : {packet_stats['http']}")
    print(f"  |-- QUIC/HTTP3 Packets: {packet_stats['quic']}")
    print(f"  |-- DNS Packets       : {packet_stats['dns']}")
    print(f"  \\-- ARP Packets       : {packet_stats['arp']}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Scapy FIFO Packet Sniffer & Web Traffic Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python packet_sniffer.py                   # Auto-detects internet adapter and captures all packets
  python packet_sniffer.py --list            # Lists all available interfaces
  python packet_sniffer.py -i "Wi-Fi"        # Captures on Wi-Fi interface
  python packet_sniffer.py --web             # Captures only web traffic (HTTP, HTTPS, DNS, QUIC)
  python packet_sniffer.py -c 50             # Captures 50 packets then exits
"""
    )
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: auto-detected active adapter)")
    parser.add_argument("-l", "--list", action="store_true", help="List all available network interfaces and exit")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = continuous capture)")
    parser.add_argument("-f", "--filter", help="Custom BPF filter expression (e.g. 'tcp port 443')")
    parser.add_argument("--web", action="store_true", help="Filter capture to web traffic only (ports 80, 443, 53)")

    args = parser.parse_args()

    if args.list:
        list_available_interfaces()
        return

    # Auto-detect or resolve target interface
    selected_iface = resolve_interface(args.interface)
    # Ensure Scapy's global interface matches
    try:
        conf.iface = selected_iface
    except Exception:
        pass

    iface_name = getattr(selected_iface, "name", str(selected_iface))
    iface_desc = getattr(selected_iface, "description", "N/A")
    iface_ip = getattr(selected_iface, "ip", "No IP")

    # Determine BPF filter
    bpf_filter = args.filter
    if args.web and not bpf_filter:
        bpf_filter = "tcp port 80 or tcp port 443 or udp port 53 or udp port 443"

    print("=" * 60)
    print("Scapy FIFO Packet Sniffer & Web Traffic Analyzer")
    print("Workflow: SCAPY -> capture_packet() -> QUEUE -> process_packets() -> print(packet)")
    print("=" * 60)
    print(f"[+] Active Interface   : {iface_name}")
    print(f"[+] Device Description : {iface_desc}")
    print(f"[+] Assigned IP        : {iface_ip}")
    if bpf_filter:
        print(f"[+] Active Filter      : {bpf_filter}")
    else:
        print("[+] Active Filter      : ALL Packets (IPv4, IPv6, TCP, UDP, etc.)")
    print("[*] Press Ctrl+C at any time to stop capturing.\n")

    # Start Consumer thread (process_packets)
    consumer_thread = threading.Thread(target=process_packets, daemon=True)
    consumer_thread.start()

    # Start Producer thread (capture_packet)
    producer_thread = threading.Thread(
        target=capture_packet,
        kwargs={"interface": selected_iface, "packet_count": args.count, "bpf_filter": bpf_filter},
        daemon=True
    )
    producer_thread.start()

    try:
        # Keep main thread alive while either thread is running
        while producer_thread.is_alive() or (args.count > 0 and consumer_thread.is_alive() and not packet_queue.empty()):
            time.sleep(0.5)
            if args.count > 0 and packet_stats["total"] >= args.count:
                break
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Stopping capture and draining queue...")
    finally:
        stop_event.set()
        producer_thread.join(timeout=2)
        consumer_thread.join(timeout=2)
        print_stats()
        print("[*] Completed successfully.")


if __name__ == "__main__":
    main()