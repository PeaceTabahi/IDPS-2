# test_traffic.py - Generate test traffic for testing
import socket
import time
import threading
import requests
from scapy.all import *

class TrafficGenerator:
    def __init__(self, target_ip="127.0.0.1"):
        self.target_ip = target_ip
        
    def generate_port_scan(self):
        """Simulate port scanning activity"""
        print("Generating port scan traffic...")
        for port in range(20, 100):  # Will trigger port scan detection
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect((self.target_ip, port))
                sock.close()
            except:
                pass
            time.sleep(0.1)
                
    def generate_syn_flood(self):
        """Simulate SYN flood attack"""
        print("Generating SYN flood traffic...")
        for i in range(60):  # Will trigger SYN flood detection
            packet = IP(dst=self.target_ip)/TCP(dport=80, flags="S")
            send(packet, verbose=0)
            time.sleep(0.1)
            
    def generate_malicious_http(self):
        """Generate HTTP requests with malicious payloads"""
        print("Generating malicious HTTP traffic...")
        payloads = [
            "?id=1' UNION SELECT * FROM users--",  # SQL injection
            "?search=<script>alert('xss')</script>",  # XSS
            "?file=../../../etc/passwd",  # Directory traversal
        ]
        
        for payload in payloads:
            try:
                requests.get(f"http://{self.target_ip}/{payload}", timeout=1)
            except:
                pass
            time.sleep(1)

if __name__ == "__main__":
    generator = TrafficGenerator()
    
    print("Starting traffic generation for testing...")
    print("This will trigger various NIDPS detections")
    
    # Run different attack simulations
    threading.Thread(target=generator.generate_port_scan).start()
    time.sleep(5)
    threading.Thread(target=generator.generate_syn_flood).start()
    time.sleep(5)
    threading.Thread(target=generator.generate_malicious_http).start()
