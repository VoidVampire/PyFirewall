from scapy.all import *
import time

def send_test_packets():    
    target_ip = "192.168.1.100"
    
    print("Sending test packets...")
    
    # 1. Invalid source IP test
    print("\nSending invalid source IP packet...")
    send(IP(src="0.0.0.0", dst=target_ip)/ICMP())
    print("----------")
    time.sleep(1)
    
    # 2. Private IP from outside test
    print("\nSending packet from untrusted private IP...")
    send(IP(src="192.168.2.1", dst=target_ip)/TCP(dport=80))
    print("----------")
    time.sleep(1)
   
    # 3 Source routing test
    print("\nSending packet with source routing...")
    lsrr_option = IPOption(b'\x83\x08\x04\x01\x01\x01\x01')
    send(IP(src="8.8.8.8", dst=target_ip, 
            options=[lsrr_option])/TCP(dport=80))
    print("----------")
    time.sleep(1)
    
    # 4. Combined suspicious indicators
    print("\nSending packet with multiple suspicious indicators...")
    lsrr_option = IPOption(b'\x83\x08\x04\x01\x01\x01\x01')
    send(IP(src="192.168.2.1", dst=target_ip, ttl=1,
            options=[lsrr_option])/TCP(dport=80))

if __name__ == "__main__":
    # Requires root privileges
    send_test_packets()
