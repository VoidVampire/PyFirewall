import time
from collections import defaultdict
from scapy.all import IP, TCP, ICMP

class FloodProtection:
    def __init__(self, max_connections_per_ip=3, syn_timeout=5, icmp_timeout=5, block_timeout=3):
        self.max_connections_per_ip = max_connections_per_ip
        self.syn_timeout = syn_timeout
        self.icmp_timeout = icmp_timeout
        self.block_timeout = block_timeout
        self.syn_connections = defaultdict(list)
        self.icmp_connections = defaultdict(list)
        self.blocked_ips = {}

    def check_syn_flood(self, src_ip):
        now = time.time()
        self.syn_connections[src_ip] = [conn for conn in self.syn_connections[src_ip] if now - conn < self.syn_timeout]
        if len(self.syn_connections[src_ip]) >= self.max_connections_per_ip:
            return True
        self.syn_connections[src_ip].append(now)
        return False

    def check_icmp_flood(self, src_ip):
        now = time.time()
        self.icmp_connections[src_ip] = [conn for conn in self.icmp_connections[src_ip] if now - conn < self.icmp_timeout]
        if len(self.icmp_connections[src_ip]) >= self.max_connections_per_ip:
            return True
        self.icmp_connections[src_ip].append(now)
        return False

    def process_packet(self, packet, IP):
        src_ip = packet[IP].src

        # Check if the source IP is currently blocked
        if src_ip in self.blocked_ips and time.time() - self.blocked_ips[src_ip] < self.block_timeout:
            print(f"Packet from {src_ip} is blocked due to recent flood detection.")
            return "block"

        # Check for SYN/ICMP flood
        if packet[IP].proto == 1:  # ICMP
            if self.check_icmp_flood(src_ip):
                print(f"ICMP flood detected from {src_ip}, dropping packet")
                self.blocked_ips[src_ip] = time.time()
                return "block"
        elif packet[IP].proto == 6:  # TCP
            if packet[TCP].flags == 0x2:  # SYN
                if self.check_syn_flood(src_ip):
                    print(f"SYN flood detected from {src_ip}, dropping packet")
                    self.blocked_ips[src_ip] = time.time()
                    return "block"

        return "allow"
