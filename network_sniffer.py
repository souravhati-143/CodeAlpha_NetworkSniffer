#!/usr/bin/env python3
"""
========================================================
  Basic Network Sniffer — CodeAlpha Cybersecurity Internship
  Task 1: Network Packet Capture & Analysis
  
  Description:
    This program captures live network packets and displays
    useful information such as source/destination IPs,
    protocols, ports, and payload data.

  Requirements:
    pip install scapy

  Usage:
    sudo python3 network_sniffer.py
    sudo python3 network_sniffer.py --count 20
    sudo python3 network_sniffer.py --filter "tcp" --count 10
    sudo python3 network_sniffer.py --iface eth0 --count 50
========================================================
"""

import argparse
import datetime
import sys
from collections import defaultdict

# ── Try importing Scapy ────────────────────────────────
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── Fallback: raw socket sniffer (no external libraries) ──
import socket
import struct
import textwrap


# ══════════════════════════════════════════════════════════
#  STATISTICS TRACKER
# ══════════════════════════════════════════════════════════
class Stats:
    def __init__(self):
        self.total      = 0
        self.protocols  = defaultdict(int)
        self.top_src    = defaultdict(int)
        self.top_dst    = defaultdict(int)
        self.start_time = datetime.datetime.now()

    def update(self, proto, src, dst):
        self.total += 1
        self.protocols[proto] += 1
        self.top_src[src]     += 1
        self.top_dst[dst]     += 1

    def display(self):
        elapsed = (datetime.datetime.now() - self.start_time).seconds
        print("\n" + "═" * 60)
        print("  📊  CAPTURE SUMMARY")
        print("═" * 60)
        print(f"  Total packets captured : {self.total}")
        print(f"  Capture duration       : {elapsed}s")
        print()
        print("  Protocol Breakdown:")
        for p, c in sorted(self.protocols.items(), key=lambda x: -x[1]):
            bar = "█" * min(c, 30)
            print(f"    {p:<8} {bar} {c}")
        print()
        print("  Top Source IPs:")
        for ip, c in sorted(self.top_src.items(), key=lambda x: -x[1])[:5]:
            print(f"    {ip:<20} {c} packets")
        print()
        print("  Top Destination IPs:")
        for ip, c in sorted(self.top_dst.items(), key=lambda x: -x[1])[:5]:
            print(f"    {ip:<20} {c} packets")
        print("═" * 60)


stats = Stats()
packet_num = 0


# ══════════════════════════════════════════════════════════
#  SCAPY-BASED SNIFFER
# ══════════════════════════════════════════════════════════

def get_protocol_name(pkt):
    """Identify the main protocol of a packet."""
    if pkt.haslayer(TCP):  return "TCP"
    if pkt.haslayer(UDP):  return "UDP"
    if pkt.haslayer(ICMP): return "ICMP"
    if pkt.haslayer(ARP):  return "ARP"
    return "OTHER"


def format_payload(payload_bytes, max_len=64):
    """Format payload bytes into readable hex + ASCII."""
    if not payload_bytes:
        return ""
    data = payload_bytes[:max_len]
    hex_str = " ".join(f"{b:02x}" for b in data)
    asc_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"\n      HEX : {hex_str}\n      TXT : {asc_str}"


def process_packet_scapy(pkt):
    """Callback function — called for every captured packet."""
    global packet_num
    packet_num += 1

    ts  = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    sep = "─" * 60

    # ── IP layer ──────────────────────────────────────────
    if pkt.haslayer(IP):
        src_ip  = pkt[IP].src
        dst_ip  = pkt[IP].dst
        ttl     = pkt[IP].ttl
        length  = pkt[IP].len
        proto   = get_protocol_name(pkt)

        stats.update(proto, src_ip, dst_ip)

        print(f"\n{sep}")
        print(f"  Packet #{packet_num:<4}  [{ts}]  Protocol: {proto}")
        print(f"  Source IP      : {src_ip}")
        print(f"  Destination IP : {dst_ip}")
        print(f"  TTL            : {ttl}    Length: {length} bytes")

        # ── TCP details ───────────────────────────────────
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = []
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x08: flags.append("PSH")
            print(f"  Source Port    : {tcp.sport}")
            print(f"  Dest Port      : {tcp.dport}")
            print(f"  TCP Flags      : {' | '.join(flags) if flags else 'NONE'}")
            print(f"  Seq / Ack      : {tcp.seq} / {tcp.ack}")

            # Detect common services
            service = detect_service(tcp.sport, tcp.dport)
            if service:
                print(f"  Service Hint   : {service}")

        # ── UDP details ───────────────────────────────────
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            print(f"  Source Port    : {udp.sport}")
            print(f"  Dest Port      : {udp.dport}")
            service = detect_service(udp.sport, udp.dport)
            if service:
                print(f"  Service Hint   : {service}")

            # DNS query display
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                try:
                    qname = pkt[DNS].qd.qname.decode()
                    print(f"  DNS Query      : {qname}")
                except Exception:
                    pass

        # ── ICMP details ──────────────────────────────────
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "Time Exceeded"}
            print(f"  ICMP Type      : {icmp_types.get(icmp.type, str(icmp.type))}")

        # ── Payload ───────────────────────────────────────
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)
            print(f"  Payload ({len(raw)} bytes):{format_payload(raw)}")

    # ── ARP layer ─────────────────────────────────────────
    elif pkt.haslayer(ARP):
        arp = pkt[ARP]
        op  = "Request (Who has?)" if arp.op == 1 else "Reply (Is at)"
        stats.update("ARP", arp.psrc, arp.pdst)
        print(f"\n{sep}")
        print(f"  Packet #{packet_num:<4}  [{ts}]  Protocol: ARP")
        print(f"  Operation      : {op}")
        print(f"  Sender IP/MAC  : {arp.psrc} / {arp.hwsrc}")
        print(f"  Target IP/MAC  : {arp.pdst} / {arp.hwdst}")

    # ── Other packets ─────────────────────────────────────
    else:
        stats.update("OTHER", "?", "?")
        print(f"\n{sep}")
        print(f"  Packet #{packet_num:<4}  [{ts}]  (Non-IP/ARP frame)")


def detect_service(sport, dport):
    """Guess the application-layer service from port numbers."""
    well_known = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
        80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    }
    for port in (sport, dport):
        if port in well_known:
            return well_known[port]
    return None


def run_scapy_sniffer(iface, count, bpf_filter):
    """Start packet capture using Scapy."""
    print("\n" + "═" * 60)
    print("  🔍  NETWORK SNIFFER — CodeAlpha Internship Task 1")
    print("═" * 60)
    print(f"  Interface : {iface or 'auto-detect'}")
    print(f"  Filter    : {bpf_filter or 'none (all traffic)'}")
    print(f"  Count     : {count or 'unlimited'}")
    print("  Press Ctrl+C to stop and view summary")
    print("═" * 60)

    kwargs = {"prn": process_packet_scapy, "store": False}
    if iface:      kwargs["iface"] = iface
    if count:      kwargs["count"] = count
    if bpf_filter: kwargs["filter"] = bpf_filter

    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        pass
    finally:
        stats.display()


# ══════════════════════════════════════════════════════════
#  FALLBACK: RAW SOCKET SNIFFER (No Scapy needed)
# ══════════════════════════════════════════════════════════

def unpack_ip_header(data):
    """Parse raw IP header fields."""
    iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version_ihl = iph[0]
    ihl = (version_ihl & 0xF) * 4
    ttl, proto = iph[5], iph[6]
    src = socket.inet_ntoa(iph[8])
    dst = socket.inet_ntoa(iph[9])
    return ihl, ttl, proto, src, dst


def unpack_tcp_header(data):
    """Parse raw TCP header fields."""
    tcph = struct.unpack("!HHLLBBHHH", data[:20])
    return tcph[0], tcph[1], tcph[4], tcph[5]   # sport, dport, offset, flags


def unpack_udp_header(data):
    """Parse raw UDP header fields."""
    udph = struct.unpack("!HHHH", data[:8])
    return udph[0], udph[1], udph[2]             # sport, dport, length


def run_raw_socket_sniffer(count):
    """Fallback sniffer using raw sockets (no Scapy required)."""
    print("\n" + "═" * 60)
    print("  🔍  NETWORK SNIFFER (Raw Socket Mode)")
    print("  ⚠️   Scapy not installed — using built-in socket library")
    print("═" * 60)
    print(f"  Count     : {count or 'unlimited'}")
    print("  Press Ctrl+C to stop")
    print("═" * 60)

    global packet_num

    PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

    try:
        # Create raw socket — requires root/admin
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind(("0.0.0.0", 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Windows: enable promiscuous mode
        if sys.platform == "win32":
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        print("\n  ❌  Permission denied! Please run with sudo / as Administrator.")
        print("  Example:  sudo python3 network_sniffer.py\n")
        sys.exit(1)
    except OSError as e:
        print(f"\n  ❌  Socket error: {e}")
        sys.exit(1)

    try:
        while True:
            if count and packet_num >= count:
                break

            raw_data, _ = s.recvfrom(65535)
            packet_num += 1
            ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

            try:
                ihl, ttl, proto_num, src, dst = unpack_ip_header(raw_data)
            except Exception:
                continue

            proto = PROTO_MAP.get(proto_num, f"PROTO-{proto_num}")
            stats.update(proto, src, dst)
            remaining = raw_data[ihl:]

            print(f"\n{'─'*60}")
            print(f"  Packet #{packet_num:<4}  [{ts}]  Protocol: {proto}")
            print(f"  Source IP      : {src}")
            print(f"  Destination IP : {dst}")
            print(f"  TTL            : {ttl}")

            if proto_num == 6 and len(remaining) >= 20:   # TCP
                sport, dport, offset, flags = unpack_tcp_header(remaining)
                flag_bits = []
                if flags & 0x02: flag_bits.append("SYN")
                if flags & 0x10: flag_bits.append("ACK")
                if flags & 0x01: flag_bits.append("FIN")
                if flags & 0x04: flag_bits.append("RST")
                print(f"  Source Port    : {sport}")
                print(f"  Dest Port      : {dport}")
                print(f"  TCP Flags      : {' | '.join(flag_bits) or 'NONE'}")
                payload = remaining[offset * 4:]
                if payload:
                    preview = payload[:32]
                    hex_p = " ".join(f"{b:02x}" for b in preview)
                    asc_p = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
                    print(f"  Payload (first {len(preview)}B):")
                    print(f"      HEX: {hex_p}")
                    print(f"      TXT: {asc_p}")

            elif proto_num == 17 and len(remaining) >= 8:  # UDP
                sport, dport, length = unpack_udp_header(remaining)
                print(f"  Source Port    : {sport}")
                print(f"  Dest Port      : {dport}")
                print(f"  UDP Length     : {length}")

            elif proto_num == 1 and len(remaining) >= 4:   # ICMP
                icmp_type = remaining[0]
                icmp_names = {0: "Echo Reply", 8: "Echo Request",
                              3: "Dest Unreachable", 11: "Time Exceeded"}
                print(f"  ICMP Type      : {icmp_names.get(icmp_type, str(icmp_type))}")

    except KeyboardInterrupt:
        pass
    finally:
        if sys.platform == "win32":
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        s.close()
        stats.display()


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer — CodeAlpha Cybersecurity Task 1",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  sudo python3 network_sniffer.py
  sudo python3 network_sniffer.py --count 20
  sudo python3 network_sniffer.py --filter "tcp port 80"
  sudo python3 network_sniffer.py --iface eth0 --count 50
        """
    )
    parser.add_argument("--iface",  "-i", default=None,  help="Network interface (e.g. eth0, wlan0)")
    parser.add_argument("--count",  "-c", default=0,     type=int, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--filter", "-f", default=None,  help="BPF filter string (Scapy mode only, e.g. 'tcp')")
    args = parser.parse_args()

    if SCAPY_AVAILABLE:
        run_scapy_sniffer(args.iface, args.count or None, args.filter)
    else:
        print("\n  ℹ️  Scapy not found. Using raw socket fallback.")
        print("  To install Scapy:  pip install scapy\n")
        run_raw_socket_sniffer(args.count or None)


if __name__ == "__main__":
    main()
