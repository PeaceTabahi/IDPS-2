# config.py - Configuration Management
import json
import os

class Config:
    def __init__(self, config_file='nidps_config.json'):
        self.config_file = config_file
        self.default_config = {
            'detection': {
                'port_scan_threshold': 20,
                'syn_flood_threshold': 50,
                'icmp_flood_threshold': 30,
                'time_window': 10
            },
            'prevention': {
                'auto_block': True,
                'block_duration': 3600  # seconds
            },
            'monitoring': {
                'interface': 'any',
                'packet_filter': 'tcp or udp or icmp'
            },
            'alerts': {
                'email_enabled': False,
                'email_config': {
                    'smtp_server': '',
                    'port': 587,
                    'username': '',
                    'password': '',
                    'from': '',
                    'to': ''
                }
            }
        }
        self.load_config()
        
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")
                self.config = self.default_config
        else:
            self.config = self.default_config
            self.save_config()
            
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")
            
    def get(self, key_path):
        """Get configuration value using dot notation"""
        keys = key_path.split('.')
        value = self.config
        for key in keys:
            value = value.get(key, {})
        return value
