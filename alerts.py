# alerts.py - Alert and Logging System
import logging
from datetime import datetime

class AlertSystem:
    def __init__(self):
        self.setup_logging()
        self.alert_count = 0
        
    def setup_logging(self):
        """Configure logging system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('nidps.log'),
                logging.StreamHandler()  # Also print to console
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def log_info(self, message):
        """Log info message"""
        self.logger.info(message)
        
    def log_warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
        
    def log_error(self, message):
        """Log error message"""
        self.logger.error(message)
        
    def send_alert(self, message):
        """Send critical alert"""
        self.alert_count += 1
        alert_msg = f"ALERT #{self.alert_count}: {message}"
        self.log_warning(alert_msg)

        # Console display for high-priority alerts
        print(f"\n{'='*50}")
        print(f"🚨 SECURITY ALERT 🚨")
        print(f"Time: {datetime.now()}")
        print(f"Message: {message}")
        print(f"{'='*50}\n")
