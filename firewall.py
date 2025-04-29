import asyncio
import sqlite3
from datetime import datetime
from scapy.all import sniff, IP
from rule_engine import RuleEngine
from flood_protection import FloodProtection
from spoof_detection import SpoofDetector
from antivirus import Antivirus 

import subprocess

class Firewall:
    def __init__(self, db_path='firewall.db'):
        self.db_path = db_path
        self.rule_engine = RuleEngine()
        self.flood_protection = FloodProtection()
        self.spoof_detector = SpoofDetector(db_path)
        self.antivirus = Antivirus()
        self.init_db()
        self.is_allow = int(input("Press 1 to spoof_detect :"))
        #self.spoof_detector.add_trusted_network('192.168.137.129')

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS packet_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol INTEGER,
                    action TEXT
                )
            ''')

    def add_rule(self, rule):
        self.rule_engine.add_rule(rule)
        self.apply_iptables_rule(rule)

    def apply_iptables_rule(self, rule):
        # Convert our rule to an iptables rule
        
        iptables_rule = self.convert_to_iptables(rule)
        full_command = ["sudo","iptables", "-A", "INPUT"] + iptables_rule
        
        print(f"Running command: {' '.join(full_command)}")  # Debug print
        try:
        
            subprocess.run(full_command, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to apply iptables rule: {e.stderr}")

    def convert_to_iptables(self, rule):
        iptables_rule = []
        
        # Map numeric protocols to string representations
        protocol_mapping = {
            1: "icmp",  # ICMP
            6: "tcp",   # TCP
            17: "udp"   # UDP
        }

        # Convert numeric protocol to string
        if rule.protocol is not None:
            proto_str = protocol_mapping.get(rule.protocol, None)
            if proto_str:
                iptables_rule.extend(["-p", proto_str])
            else:
                print(f"Warning: Unknown protocol number {rule.protocol}")
        if rule.src_ip:
            iptables_rule.extend(["-s", rule.src_ip])
        if rule.dst_ip:
            iptables_rule.extend(["-d", rule.dst_ip])
        if rule.src_port:
            iptables_rule.extend(["--sport", str(rule.src_port)])
        if rule.dst_port:
            iptables_rule.extend(["--dport", str(rule.dst_port)])
        if rule.action == "block":
            iptables_rule.extend(["-j", "DROP"])
        elif rule.action == "allow":
            iptables_rule.extend(["-j", "ACCEPT"])
        
        return iptables_rule

    async def start(self):
        await self.capture_packets()

    async def capture_packets(self):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._sniff_packets)

    def _sniff_packets(self):
        sniff(prn=self.process_packet, store=0)
    def process_packet(self, packet):
        if IP in packet:
            
            if self.antivirus.check_packet(packet):
                print(f"Malicious packet detected from {packet[IP].src} to {packet[IP].dst}")
                self.log_packet(packet, "block") 
                print("------------")
                return 
            if self.is_allow==1:
            	is_spoofed, confidence, reason = self.spoof_detector.detect_spoofing(packet)
            
            	if is_spoofed:
                	print(f"Spoofed packet detected from {packet[IP].src} to {packet[IP].dst}")
                	print(f"Reason: {reason} (Confidence: {confidence:.2f})")
                	self.log_packet(packet, "block") 
                	print("------------")
                	return
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            action = self.flood_protection.process_packet(packet, IP)
            if action == 'block':
                self.log_packet(packet, action)  # Log blocked packets
                # Since we are blocking, we don't need to process the packet further
                print(f"Blocked packet: {packet.summary()}")
                print("------------")
                return
                
            action = self.rule_engine.process_packet(packet)
            
            print(f"Packet: {src_ip} -> {dst_ip} (Protocol: {protocol}) - Action: {action}")

            # Log the packet before applying iptables rule, even if it's blocked
            if action == 'block':
                self.log_packet(packet, action)  # Log blocked packets
                # Since we are blocking, we don't need to process the packet further
                print(f"Blocked packet: {packet.summary()}")
                print("------------")
                return
            
            self.log_packet(packet, action)  # Log allowed packets
            print("------------")

    def log_packet(self, packet, action):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO packet_logs (timestamp, src_ip, dst_ip, protocol, action)
                VALUES (?, ?, ?, ?, ?)
            ''', (datetime.now(), packet[IP].src, packet[IP].dst, packet[IP].proto, action))
        print(f"Logged packet: {packet.summary()} - Action: {action}")
    


    async def capture_packets(self):
            loop = asyncio.get_event_loop()
            sniff(prn=self.process_packet, filter="ip", store=0)

    async def periodic_cleanup(self, max_age_hours=24):
        while True:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    DELETE FROM packet_logs
                    WHERE timestamp < datetime('now', '-' || ? || ' hours')
                ''', (max_age_hours,))
            await asyncio.sleep(3600)  # Run cleanup every hour
