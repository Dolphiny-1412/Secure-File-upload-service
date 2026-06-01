#!/usr/bin/env python3
"""
Start all services for the Secure File Upload Demo.
Run this script to start vulnerable-service, hardened-service, and Streamlit UI.
"""

import os
import sys
import time
import signal
import subprocess
import threading
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def check_port(port):
    """Check if a port is available."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) != 0

def start_service(name, cmd, port, cwd=None):
    """Start a service and return the process."""
    print(f"Starting {name} on port {port}...")
    if not check_port(port):
        print(f"Warning: Port {port} is already in use")
    
    process = subprocess.Popen(
        cmd,
        cwd=cwd or project_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        bufsize=1
    )
    
    # Start a thread to print output
    def print_output():
        for line in iter(process.stdout.readline, ''):
            print(f"[{name}] {line.rstrip()}")
    
    thread = threading.Thread(target=print_output, daemon=True)
    thread.start()
    
    return process

def wait_for_service(port, name, timeout=30):
    """Wait for a service to be ready."""
    import requests
    url = f"http://127.0.0.1:{port}/"
    
    for i in range(timeout):
        try:
            response = requests.get(url, timeout=1)
            if response.status_code < 500:
                print(f"✓ {name} is ready on port {port}")
                return True
        except:
            pass
        time.sleep(1)
    
    print(f"✗ {name} failed to start on port {port}")
    return False

def main():
    """Main function to start all services."""
    print("🚀 Starting Secure File Upload Demo Services")
    print("=" * 50)
    
    # Check if .env exists
    if not Path(".env").exists():
        print("Creating .env file...")
        import secrets
        with open(".env", "w") as f:
            f.write(f"SECRET_KEY={secrets.token_urlsafe(32)}\n")
            f.write("MAX_UPLOAD_SIZE=5242880\n")
            f.write("TOKEN_EXP_SECONDS=300\n")
            f.write("RATE_LIMIT_REQUESTS=50\n")
            f.write("RATE_LIMIT_WINDOW_SECONDS=60\n")
            f.write("CLAMD_HOST=\n")
        print("✓ Created .env file")
    
    # Create necessary directories
    Path("data/storage").mkdir(parents=True, exist_ok=True)
    Path("data/quarantine").mkdir(parents=True, exist_ok=True)
    Path("vulnerable_service/webroot/uploads").mkdir(parents=True, exist_ok=True)
    
    processes = []
    
    try:
        # Start vulnerable service
        vuln_cmd = [
            sys.executable, "-m", "uvicorn", 
            "vulnerable_service.app.main:app",
            "--host", "127.0.0.1", "--port", "8001"
        ]
        processes.append(start_service("vulnerable-service", vuln_cmd, 8001))
        
        # Start hardened service
        hard_cmd = [
            sys.executable, "-m", "uvicorn",
            "hardened_service.app.main:app", 
            "--host", "127.0.0.1", "--port", "8000"
        ]
        processes.append(start_service("hardened-service", hard_cmd, 8000))
        
        # Start Streamlit UI
        ui_cmd = [
            sys.executable, "-m", "streamlit", "run",
            "streamlit_service/app/main.py",
            "--server.port", "8501",
            "--server.address", "127.0.0.1"
        ]
        processes.append(start_service("streamlit-ui", ui_cmd, 8501))
        
        # Wait for services to be ready
        print("\n⏳ Waiting for services to start...")
        wait_for_service(8001, "vulnerable-service")
        wait_for_service(8000, "hardened-service") 
        wait_for_service(8501, "streamlit-ui")
        
        print("\n🎉 All services are running!")
        print("=" * 50)
        print("📊 Services:")
        print("  • Vulnerable Service: http://127.0.0.1:8001")
        print("  • Hardened Service:   http://127.0.0.1:8000")
        print("  • Streamlit UI:       http://127.0.0.1:8501")
        print("\n📝 API Documentation:")
        print("  • Vulnerable: http://127.0.0.1:8001/docs")
        print("  • Hardened:   http://127.0.0.1:8000/docs")
        print("\n🛑 Press Ctrl+C to stop all services")
        print("=" * 50)
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Shutting down services...")
        
    finally:
        # Terminate all processes
        for process in processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        
        print("✓ All services stopped")

if __name__ == "__main__":
    main()
