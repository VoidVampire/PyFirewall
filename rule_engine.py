from scapy.all import IP, TCP, UDP, ICMP
import requests
class Rule:
    def __init__(self, action, protocol=None, src_ip=None, src_port=None, dst_ip=None, dst_port=None):
        self.action = action  # 'allow', 'block'
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port

    def matches(self, packet):
        if IP not in packet:
            print("Not an IP packet")
            return False
        
        if self.protocol is not None and packet[IP].proto != self.protocol:
            print(f"Protocol mismatch: {packet[IP].proto} != {self.protocol}")
            return False
        
        if self.src_ip and packet[IP].src != self.src_ip:
            print(f"Source IP mismatch: {packet[IP].src} != {self.src_ip}")
            return False
        
        if self.dst_ip and packet[IP].dst != self.dst_ip:
            print(f"Destination IP mismatch: {packet[IP].dst} != {self.dst_ip}")
            return False
        
        if TCP in packet:
            if self.src_port and packet[TCP].sport != self.src_port:
                print(f"TCP Source port mismatch: {packet[TCP].sport} != {self.src_port}")
                return False
            if self.dst_port and packet[TCP].dport != self.dst_port:
                print(f"TCP Destination port mismatch: {packet[TCP].dport} != {self.dst_port}")
                return False
        
        elif UDP in packet:
            if self.src_port and packet[UDP].sport != self.src_port:
                print(f"UDP Source port mismatch: {packet[UDP].sport} != {self.src_port}")
                return False
            if self.dst_port and packet[UDP].dport != self.dst_port:
                print(f"UDP Destination port mismatch: {packet[UDP].dport} != {self.dst_port}")
                return False
        
        print("Rule matched!")
        return True

class RuleEngine:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule):
        self.rules.append(rule)
        print(f"Added rule: {rule.action}, protocol: {rule.protocol}, src_ip: {rule.src_ip}, dst_ip: {rule.dst_ip}")
    def get_country_from_ip(self, ip):
        try:
            # Example of using an API to get the country code
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                return response.json().get('countryCode', 'Unknown')  # Use 'countryCode' for a two-letter code
            else:
                print(f"Failed to retrieve country for IP {ip}, status code: {response.status_code}")
                return 'Unknown'
        except requests.RequestException as e:
            print(f"Error during IP to country lookup: {e}")
            return 'Unknown' 
    
    def is_country_blocked(self, packet):
        src_ip = packet[IP].src
        blocked_countries = ["US", "CN", "RU"]  # Example list of blocked country codes
        
        # Fetch the country code from the IP
        country = self.get_country_from_ip(src_ip)
        
        if country in blocked_countries:
            print(f"Packet from {src_ip} is blocked due to country: {country}.")
            return True
        else:
            print(f"Packet from {src_ip} allowed, country: {country}.")
            return False
    def process_packet(self, packet):
        if self.is_country_blocked(packet):

            return 'block'

        for rule in self.rules:
            if rule.matches(packet):
                print(f"Packet matched rule: {rule.action}")
                return rule.action
        print("No matching rule found, defaulting to block")
        return 'block'  