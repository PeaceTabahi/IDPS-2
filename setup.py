# setup.py - Installation and setup script
import os
import sys
import subprocess

def install_requirements():
    """Install required packages"""
    print("Installing requirements...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def setup_directories():
    """Create necessary directories"""
    directories = ['logs', 'templates', 'rules']
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")

def check_permissions():
    """Check if running with appropriate permissions"""
    if os.name == 'posix':  # Unix/Linux
        if os.geteuid() != 0:
            print("WARNING: NIDPS requires root privileges for packet capture and IP blocking.")
            print("Run with: sudo python main.py")
    
def main():
    print("Setting up NIDPS...")
    setup_directories()
    install_requirements()
    check_permissions()
    print("Setup complete!")
    print("\nTo start NIDPS:")
    print("1. Run: sudo python main.py (Linux/Mac)")
    print("2. Run: python main.py (Windows as Administrator)")
    print("3. Open dashboard: python dashboard.py (optional)")

if __name__ == "__main__":
    main()
