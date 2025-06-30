# prevention.py - Prevention System
import subprocess
import platform
import os

class PreventionSystem:
    def __init__(self, alert_system):
        self.alert_system = alert_system
        self.blocked_ips = set()
        self.system_type = platform.system().lower()
        
    def block_ip(self, ip_address):
        """Block an IP address using system firewall"""
        if ip_address in self.blocked_ips:
            return False  # Already blocked
            
        try:
            if self.system_type == 'linux':
                return self._block_ip_linux(ip_address)
            elif self.system_type == 'windows':
                return self._block_ip_windows(ip_address)
            else:
                self.alert_system.log_warning(f"Unsupported OS for IP blocking: {self.system_type}")
                return False
                
        except Exception as e:
            self.alert_system.log_error(f"Failed to block IP {ip_address}: {e}")
            return False
            
    def _block_ip_linux(self, ip_address):
        """Block IP on Linux using iptables"""
        try:
            # Add to INPUT chain to block incoming traffic
            cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.blocked_ips.add(ip_address)
                self.alert_system.log_info(f"Successfully blocked IP: {ip_address}")
                return True
            else:
                self.alert_system.log_error(f"iptables command failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.alert_system.log_error(f"Linux IP blocking error: {e}")
            return False
            
    def _block_ip_windows(self, ip_address):
        """Block IP on Windows using netsh"""
        try:
            rule_name = f"NIDPS_Block_{ip_address.replace('.', '_')}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" protocol=any dir=in action=block remoteip={ip_address}'
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.blocked_ips.add(ip_address)
                self.alert_system.log_info(f"Successfully blocked IP: {ip_address}")
                return True
            else:
                self.alert_system.log_error(f"netsh command failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.alert_system.log_error(f"Windows IP blocking error: {e}")
            return False
            
    def unblock_ip(self, ip_address):
        """Unblock a previously blocked IP"""
        if ip_address not in self.blocked_ips:
            return False
            
        try:
            if self.system_type == 'linux':
                cmd = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
                subprocess.run(cmd, shell=True)
            elif self.system_type == 'windows':
                rule_name = f"NIDPS_Block_{ip_address.replace('.', '_')}"
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                subprocess.run(cmd, shell=True)
                
            self.blocked_ips.remove(ip_address)
            self.alert_system.log_info(f"Unblocked IP: {ip_address}")
            return True
            
        except Exception as e:
            self.alert_system.log_error(f"Failed to unblock IP {ip_address}: {e}")
            return False
            
    def get_blocked_ips(self):
        """Get list of currently blocked IPs"""
        return list(self.blocked_ips)
