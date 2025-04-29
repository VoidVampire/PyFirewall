# 🛡️ PyFirewall - Packet Filtering Firewall

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-2.4.5-orange?style=for-the-badge&logo=python)](https://scapy.net/)
[![SQLite](https://img.shields.io/badge/SQLite-3.35.5-blue?style=for-the-badge&logo=sqlite)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Compatible-purple?style=for-the-badge&logo=kali-linux)](https://www.kali.org/)

A powerful Python-based packet filtering firewall with advanced security features, including IP spoofing detection, flood protection, intrusion prevention, and country-based blocking.

## ✨ Features

- 🔍 **Deep Packet Inspection** - Analyze network packets in real-time
- 🛑 **Rule-Based Filtering** - Configure custom allow/block rules with YAML
- 🕵️ **IP Spoofing Detection** - Identify and block spoofed packets with confidence scoring
- 🌊 **Flood Protection** - Prevent SYN and ICMP flood attacks
- 🦠 **Malware Detection** - Scan packets for known malicious signatures
- 🚫 **Geolocation Blocking** - Block traffic from specific countries
- 🔄 **IPTables Integration** - Apply rules directly to Linux kernel firewall
- 📊 **Detailed Logging** - Comprehensive SQLite database for packet analysis

## 🚀 Setup & Usage

This firewall has been specifically developed and tested on **Kali Linux** (running on VMware). The testing environment included Metasploitable2 and Kali Linux itself.

### Installation & Configuration

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/pyfirewall.git
   cd pyfirewall
   ```

2. **Install dependencies**
   ```bash
   # Install system requirements
   sudo apt-get update
   sudo apt-get install -y python3-pip python3-scapy libpcap-dev
   
   # Install Python dependencies
   pip3 install -r requirements.txt
   ```

3. **Configure the firewall** by editing `firewall_config.yaml`:
   ```yaml
   db_path: firewall.db
   
   # Define filtering rules
   rules:
     - action: block
       protocol: 6  # TCP
       dst_port: 10000  # Block TCP port 10000
     - action: allow
       protocol: 1  # ICMP
       src_ip: 192.168.137.131  # Allow this specific IP
     # Add more rules as needed
       
   # Optional: Specify regions to restrict (for testing purposes)
   blocked_countries:
     - XX  # Replace with actual country codes as needed
     - YY
   ```

4. **Launch the firewall**
   ```bash
   # Root privileges required for packet sniffing
   sudo python3 main.py
   ```


## 🏗️ Architecture

PyFirewall consists of several modular components:

| Module | Description |
|--------|-------------|
| `firewall.py` | Core firewall functionality and packet processing |
| `rule_engine.py` | Rule parsing and matching logic |
| `spoof_detection.py` | Advanced IP spoofing detection algorithms |
| `flood_protection.py` | DDoS and flood attack prevention |
| `antivirus.py` | Malicious signature detection in packets |
| `config_loader.py` | YAML configuration parser |


## 💻 Daily Operations

### Monitoring

Monitor firewall activity in real-time:

```bash
# View the latest logged packets
sqlite3 firewall.db "SELECT * FROM packet_logs ORDER BY timestamp DESC LIMIT 10;"

# Check detected spoofing attempts
sqlite3 firewall.db "SELECT * FROM detailed_spoof_logs ORDER BY timestamp DESC;"

# Monitor traffic from specific IP
sqlite3 firewall.db "SELECT * FROM packet_logs WHERE src_ip = '192.168.1.100';"
```

### Rule Management

1. Edit `firewall_config.yaml` to modify your ruleset
2. Restart the firewall for changes to take effect
3. Monitor logs to verify rule effectiveness


## 🛡️ Security Features

PyFirewall implements multiple security mechanisms to protect your network:

### IP Spoofing Detection

The system employs a multi-layered approach to identify spoofed packets:

- **TTL Analysis** - Detects inconsistencies in Time-To-Live values that indicate packet manipulation
- **Source Routing Detection** - Identifies packets with suspicious routing options
- **Private IP Validation** - Verifies private addresses are coming from trusted networks
- **Confidence Scoring** - Multiple detection methods contribute to an overall confidence score

### Flood Attack Prevention

Protection against common DoS/DDoS attacks:

```python
# Default thresholds (customizable)
max_connections_per_ip = 3
syn_timeout = 5  # seconds
icmp_timeout = 5  # seconds
```

### Geographic Traffic Filtering

For testing and educational purposes, the firewall can filter traffic based on country of origin, which can be useful in development environments.

### Malicious Signature Detection

The integrated antivirus module scans packet payloads for known malicious signatures and patterns.

## 📸 PyFirewall in Action

Below are demonstrations of PyFirewall's capabilities in a real testing environment using Kali Linux and Metasploitable2 VMs:

### ICMP Traffic Filtering - Allow and Deny

<div>
<p><strong>Figure 1.a:</strong> Kali Linux terminal showing PyFirewall processing and allowing legitimate ICMP ping requests based on ruleset matches</p>
  <img src="https://i.imgur.com/cSR1ijl.png" alt="Kali Linux Terminal: Allowing ICMP Traffic"/>
</div>

<div>
  <p><strong>Figure 1.b:</strong> Metasploitable2 terminal showing successful ping response - 2 packets transmitted, 2 packets received (0% packet loss)</p>
  <img src="https://i.imgur.com/1XCQksf.png" alt="Metasploitable2: Successful Ping"/>
  
</div>

<div>
<p><strong>Figure 2.a:</strong> PyFirewall identifying and blocking unauthorized traffic based on defined rules</p>
  <img src="https://i.imgur.com/EUWSeqM.png" alt="Kali Linux Terminal: Blocking Traffic"/>
  
</div>

<div>
<p><strong>Figure 2.b:</strong> Metasploitable2 terminal showing failed connection attempt - 8 packets transmitted, 0 received (100% packet loss)</p>
  <img src="https://i.imgur.com/SYfq4jJ.png" alt="Metasploitable2: Blocked Connection"/>
  
</div>

### Other Security Features

<div>
<p><strong>Figure 3:</strong> PyFirewall detecting and mitigating an ICMP flood attack, automatically implementing rate-limiting protections</p>
  <img src="https://i.imgur.com/mr1Ra9G.png" alt="ICMP Flood Detection"/>
  
</div>

<div>
<p><strong>Figure 4:</strong> Multi-factor IP spoofing detection identifying a packet with manipulated source address and TTL anomalies</p>
  <img src="https://i.imgur.com/qGfBtbA.png" alt="IP Spoofing Detection"/>
  
</div>

<div>
<p><strong>Figure 5:</strong> Geographic filtering mechanism blocking traffic from restricted regions as defined in configuration</p>
  <img src="https://i.imgur.com/P0zDlHo.png" alt="Geographic Restriction"/>
  
</div>

<div>
<p><strong>Figure 6:</strong> Antivirus module identifying and blocking a packet containing known malicious signature patterns</p>
  <img src="https://i.imgur.com/ezl6pK8.png" alt="Malicious Payload Detection"/>
  
</div>

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.