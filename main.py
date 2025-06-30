# main.py - Entry point for NIDPS
import threading
import time
import signal
import sys
from detector import DetectionEngine
from prevention import PreventionSystem
from alerts import AlertSystem
from config import Config

class NIDPS:
    def __init__(self):
        self.config = Config()
        self.alert_system = AlertSystem()
        self.prevention_system = PreventionSystem(self.alert_system)
        self.detection_engine = DetectionEngine(self.prevention_system, self.alert_system)
        self.running = False
        
    def start(self):
        """Start the NIDPS system"""
        print("Starting NIDPS...")
        self.running = True
        
        # Start detection in separate thread
        detection_thread = threading.Thread(target=self.detection_engine.start_monitoring)
        detection_thread.daemon = True
        detection_thread.start()
        
        # Start statistics reporting
        stats_thread = threading.Thread(target=self.report_stats)
        stats_thread.daemon = True
        stats_thread.start()
        
        print("NIDPS started successfully!")
        
    def stop(self):
        """Stop the NIDPS system"""
        print("\nStopping NIDPS...")
        self.running = False
        self.detection_engine.stop()
        print("NIDPS stopped.")
        
    def report_stats(self):
        """Report system statistics periodically"""
        while self.running:
            time.sleep(60)  # Report every minute
            stats = self.detection_engine.get_stats()
            self.alert_system.log_info(f"Stats: {stats}")

def signal_handler(sig, frame):
    global nidps
    nidps.stop()
    sys.exit(0)

if __name__ == "__main__":
    nidps = NIDPS()
    
    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        nidps.start()
        # Keep main thread alive
        while True:
            time.sleep(1)
    except Exception as e:
        print(f"Error: {e}")
        nidps.stop()
