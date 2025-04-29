from scapy.all import IP
import ipaddress
import sqlite3
from datetime import datetime, timedelta
import logging

class SpoofDetector:
    def __init__(self, db_path='firewall.db'):
        self.db_path = db_path
        self.trusted_networks = []
        self.suspicious_ips = {}  # Cache for quick lookups
        self.init_db()
        
    def init_db(self):
        """Initialize database with tables for both basic and detailed spoof logging"""
        with sqlite3.connect(self.db_path) as conn:
            # Basic spoof logs (existing)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS spoof_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    reason TEXT,
                    confidence FLOAT
                )
            ''')
            
            # Detailed spoof detection logs (new)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS detailed_spoof_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol INTEGER,
                    ttl INTEGER,
                    options TEXT,
                    reason TEXT,
                    confidence FLOAT,
                    source_port INTEGER,
                    dest_port INTEGER,
                    packet_size INTEGER,
                    is_private_ip BOOLEAN,
                    is_trusted_network BOOLEAN
                )
            ''')
    
    def add_trusted_network(self, network):
        """Add a trusted network in CIDR notation (e.g., '192.168.1.0/24')"""
        self.trusted_networks.append(ipaddress.ip_network(network))
    
    def is_private_ip(self, ip):
        """Check if an IP address is private"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    def is_trusted_network(self, ip):
        """Check if IP is from a trusted network"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in network for network in self.trusted_networks)
        except ValueError:
            return False

    def is_valid_source(self, ip):
        """Check if source IP is valid (not bogon, multicast, etc)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_multicast or 
                       ip_obj.is_reserved or 
                       ip_obj.is_loopback or 
                       ip_obj.is_unspecified)
        except ValueError:
            return False
    
    def check_ttl_anomaly(self, packet):
        """Check for TTL-based anomalies that might indicate spoofing"""
        if IP in packet:
            ttl = packet[IP].ttl
            # Most operating systems use initial TTL values of 64, 128, or 255
            standard_ttls = [64, 128, 255]
            # Calculate how many hops the packet has traveled
            for initial_ttl in standard_ttls:
                if ttl <= initial_ttl:
                    hops = initial_ttl - ttl

                    # If the number of hops is suspiciously low or high
                    if hops > 30 or hops < 1:
                        return True
        return False

    def detect_spoofing(self, packet):
        """
        Main spoofing detection method
        Returns: (is_spoofed, confidence, reason)
        """
        if IP not in packet:
            return False, 0, "Not an IP packet"
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Initialize confidence score
        confidence = 0
        reasons = []
        
        # Check 1: Invalid source IP
        if not self.is_valid_source(src_ip):
            confidence += 0.8
            reasons.append("Invalid source IP")
        
        # Check 2: Private IP from public network
        is_private = self.is_private_ip(src_ip)
        is_trusted = self.is_trusted_network(src_ip)
        if is_private and not is_trusted:
            confidence += 0.6
            reasons.append("Private IP from untrusted network")
        
        # Check 3: TTL-based anomaly detection
        ttl_anomaly = self.check_ttl_anomaly(packet)
        if ttl_anomaly:
            confidence += 0.4
            reasons.append("TTL anomaly detected")
        
        # Check 4: Source routing checks
        has_source_routing = False
        if hasattr(packet[IP], 'options') and packet[IP].options:
            confidence += 0.7
            reasons.append("Source routing detected")
            has_source_routing = True
        
        # Determine if packet is spoofed based on confidence threshold
        is_spoofed = confidence >= 0.6
        reason_str = "; ".join(reasons)
        
        # Log detailed information if spoofed
        if is_spoofed:
            self.log_spoofed_packet(
                packet=packet,
                reason=reason_str,
                confidence=confidence,
                is_private=is_private,
                is_trusted=is_trusted,
                has_source_routing=has_source_routing,
                ttl_anomaly=ttl_anomaly
            )
            
            # Cache the suspicious IP for quick future reference
            self.suspicious_ips[src_ip] = {
                'timestamp': datetime.now(),
                'confidence': confidence
            }
        
        return is_spoofed, confidence, reason_str

    def log_spoofed_packet(self, packet, reason, confidence, is_private, is_trusted, has_source_routing, ttl_anomaly):
        """
        Log detailed information about spoofed packets
        """
        try:
            # Extract additional packet information
            src_port = packet[IP].sport if hasattr(packet[IP], 'sport') else None
            dst_port = packet[IP].dport if hasattr(packet[IP], 'dport') else None
            options = str(packet[IP].options) if has_source_routing else None
            
            # Log to both tables
            with sqlite3.connect(self.db_path) as conn:
                # Basic spoof log (existing)
                conn.execute('''
                    INSERT INTO spoof_logs (timestamp, src_ip, dst_ip, reason, confidence)
                    VALUES (?, ?, ?, ?, ?)
                ''', (datetime.now(), packet[IP].src, packet[IP].dst, reason, confidence))
                
                # Detailed spoof log (new)
                conn.execute('''
                    INSERT INTO detailed_spoof_logs (
                        timestamp, src_ip, dst_ip, protocol, ttl, options,
                        reason, confidence, source_port, dest_port,
                        packet_size, is_private_ip, is_trusted_network
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now(),
                    packet[IP].src,
                    packet[IP].dst,
                    packet[IP].proto,
                    packet[IP].ttl,
                    options,
                    reason,
                    confidence,
                    src_port,
                    dst_port,
                    len(packet),
                    is_private,
                    is_trusted
                ))
                
            print(f"Logged spoofed packet: {packet[IP].src} -> {packet[IP].dst}")
            print(f"Reason: {reason} (Confidence: {confidence:.2f})")
            
        except Exception as e:
            print(f"Error logging spoofed packet: {e}")
    
    def cleanup_old_logs(self, hours=24):
        """Clean up old logs and cached suspicious IPs"""
        with sqlite3.connect(self.db_path) as conn:
            # Clean up basic spoof logs
            conn.execute('''
                DELETE FROM spoof_logs
                WHERE timestamp < datetime('now', '-' || ? || ' hours')
            ''', (hours,))
            
            # Clean up detailed spoof logs
            conn.execute('''
                DELETE FROM detailed_spoof_logs
                WHERE timestamp < datetime('now', '-' || ? || ' hours')
            ''', (hours,))
        
        # Cleanup cached suspicious IPs
        current_time = datetime.now()
        self.suspicious_ips = {
            ip: data for ip, data in self.suspicious_ips.items()
            if current_time - data['timestamp'] < timedelta(hours=hours)
        }
