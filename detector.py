# detector.py - Detection Engine
import re
import time
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import json

class DetectionEngine:
    def __init__(self, prevention_system, alert_system):
        self.prevention_system = prevention_system
        self.alert_system = alert_system
        self.running = False
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'ips_blocked': 0
        }
        
        # Connection tracking for anomaly detection
        self.connection_counts = defaultdict(int)
        self.syn_flood_tracker = defaultdict(lambda: deque(maxlen=100))
        self.port_scan_tracker = defaultdict(set)
        
        # Load signatures
        self.load_signatures()
        
    def load_signatures(self):
        """Load threat signatures"""
        self.signatures = [
            {
                'name': 'SQL Injection',
                'pattern': rb'(?i)(select.*from|union.*select|insert.*into|drop.*table)',
                'severity': 'HIGH'
            },
            {
                'name': 'XSS Attack',
                'pattern': rb'(?i)<script[^>]*>.*?</script>',
                'severity': 'HIGH'
            },
            {
                'name': 'Command Injection',
                'pattern': rb'(?i)(;|\|).*(cat|ls|whoami|id|uname)',
                'severity': 'CRITICAL'
            },
            {
                'name': 'Directory Traversal',
                'pattern': rb'\.\./|\.\.\\',
                'severity': 'MEDIUM'
            }
        ]
        
    def start_monitoring(self):
        """Start packet monitoring"""
        self.running = True
        self.alert_system.log_info("Starting packet monitoring...")
        
        try:
            # Start packet capture
            sniff(prn=self.analyze_packet, store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            self.alert_system.log_error(f"Packet capture error: {e}")
            
    def stop(self):
        """Stop monitoring"""
        self.running = False
        
    def analyze_packet(self, packet):
        """Analyze each captured packet"""
        try:
            self.stats['packets_processed'] += 1
            self.save_stats_to_file()
            
            if not packet.haslayer(IP):
                return
                
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Check for various attack patterns
            self.check_port_scan(packet, src_ip)
            self.check_syn_flood(packet, src_ip)
            self.check_payload_signatures(packet)
            
            # ICMP flood detection
            if packet.haslayer(ICMP):
                self.check_icmp_flood(src_ip)
                
        except Exception as e:
            self.alert_system.log_error(f"Packet analysis error: {e}")
            
    def check_port_scan(self, packet, src_ip):
        """Detect port scanning attempts"""
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            
            # Track unique ports accessed by source IP
            self.port_scan_tracker[src_ip].add(dst_port)
            
            # Alert if accessing too many different ports
            if len(self.port_scan_tracker[src_ip]) > 20:  # Threshold: 20 different ports
                self.handle_threat(src_ip, "Port Scan", "MEDIUM")
                self.port_scan_tracker[src_ip].clear()  # Reset counter
                
    def check_syn_flood(self, packet, src_ip):
        """Detect SYN flood attacks"""
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN flag
            current_time = time.time()
            self.syn_flood_tracker[src_ip].append(current_time)
            
            # Check if too many SYNs in short time
            recent_syns = [t for t in self.syn_flood_tracker[src_ip] if current_time - t < 10]  # Last 10 seconds
            
            if len(recent_syns) > 50:  # More than 50 SYNs in 10 seconds
                self.handle_threat(src_ip, "SYN Flood", "HIGH")
                
    def check_icmp_flood(self, src_ip):
        """Detect ICMP flood attacks"""
        current_time = time.time()
        if src_ip not in self.syn_flood_tracker:
            self.syn_flood_tracker[src_ip] = deque(maxlen=100)
            
        self.syn_flood_tracker[src_ip].append(current_time)
        
        # Check ICMP rate
        recent_icmp = [t for t in self.syn_flood_tracker[src_ip] if current_time - t < 5]
        if len(recent_icmp) > 30:  # More than 30 ICMP in 5 seconds
            self.handle_threat(src_ip, "ICMP Flood", "MEDIUM")
            
    def check_payload_signatures(self, packet):
        """Check packet payload against known attack signatures"""
        if packet.haslayer('Raw'):
            payload = bytes(packet['Raw'])
            
            for signature in self.signatures:
                if re.search(signature['pattern'], payload):
                    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
                    self.handle_threat(src_ip, signature['name'], signature['severity'])
                    
    def handle_threat(self, src_ip, threat_type, severity):
        """Handle detected threat"""
        self.stats['threats_detected'] += 1
        self.save_stats_to_file()
        
        # Log the threat
        message = f"THREAT DETECTED: {threat_type} from {src_ip} (Severity: {severity})"
        self.alert_system.log_warning(message)
        self.save_alert_to_file(message)
        
        # Take prevention action based on severity
        if severity in ['HIGH', 'CRITICAL']:
            if self.prevention_system.block_ip(src_ip):
                self.stats['ips_blocked'] += 1
                self.save_stats_to_file()
                block_msg = f"BLOCKED IP: {src_ip} due to {threat_type}"
                self.alert_system.send_alert(block_msg)
                self.save_alert_to_file(block_msg)
                
    def get_stats(self):
        """Get system statistics"""
        return self.stats.copy()

    def save_stats_to_file(self):
        with open('nidps_stats.json', 'w') as f:
            json.dump(self.stats, f)

    def save_alert_to_file(self, message):
        try:
            alerts = []
            try:
                with open('nidps_alerts.json', 'r') as f:
                    alerts = json.load(f)
            except Exception:
                alerts = []
            from datetime import datetime
            alerts.insert(0, {'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'message': message})
            alerts = alerts[:50]
            with open('nidps_alerts.json', 'w') as f:
                json.dump(alerts, f)
        except Exception as e:
            self.alert_system.log_error(f'Failed to write alert to file: {e}')
