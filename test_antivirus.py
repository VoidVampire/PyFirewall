from scapy.all import send, IP, TCP, Raw

# Replace these with appropriate IPs
src_ip = "192.168.137.128"  
dst_ip = "192.138.137.129"   

# Send a malicious packet
send(IP(src=src_ip, dst=dst_ip)/TCP(dport=80, flags="S")/Raw(load=b'PAYLOAD2'))

# Send a normal packet
send(IP(src=src_ip, dst=dst_ip)/TCP(dport=80, flags="S")/Raw(load=b'NORMAL_PAYLOAD'))
