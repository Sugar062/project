import os
import sys
import time
import subprocess
import webbrowser

# Map port numbers to service file targets
SERVICES = {
    "Web Portal (Port 8000)": "frontend/server.py",
    "Order Service (Port 8001)": "services/order/main.py",
    "Payment Gateway (Port 8002)": "services/payment_orchestrator/main.py",
    "Fraud Engine (Port 8003)": "services/fraud_engine/main.py",
    "KMS / HSM (Port 8004)": "services/kms/main.py",
    "Reconciler Worker": "services/reconciliation/main.py"
}

processes = []

def start_services():
    print("==========================================================")
    print("       NT219 - SECURE PAYMENTS TRANSACTION SYSTEM          ")
    print("==========================================================")
    print("Starting system services locally...\n")
    
    project_root = os.path.dirname(os.path.abspath(__file__))
    
    for name, relative_path in SERVICES.items():
        script_path = os.path.join(project_root, relative_path)
        if not os.path.exists(script_path):
            print(f"❌ Error: Script not found: {relative_path}")
            sys.exit(1)
            
        print(f"🚀 Spawning: {name}...")
        
        # Start the process in its correct directory setting CWD
        service_dir = os.path.dirname(script_path)
        
        # We run via active python interpreter
        p = subprocess.Popen(
            [sys.executable, script_path],
            cwd=service_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        processes.append((name, p))
        
    print("\nInitialization complete! All services running.")
    print("Waiting 3 seconds for servers to bind...")
    time.sleep(3)
    
    # Auto-open browser dashboard
    portal_url = "http://127.0.0.1:8000"
    print(f"\n🖥️ Opening transaction web dashboard: {portal_url}")
    webbrowser.open(portal_url)
    
    print("\nPress Ctrl+C to terminate all services gracefully.")
    print("----------------------------------------------------------")

def monitor_processes():
    try:
        while True:
            # Poll each process to verify it hasn't crashed
            for name, p in processes:
                return_code = p.poll()
                if return_code is not None:
                    print(f"\n⚠️ Warning: {name} terminated unexpectedly with code {return_code}")
                    # Read some lines from stdout to output debugging logs
                    stdout_data = p.stdout.read() if p.stdout else ""
                    if stdout_data:
                        print(f"--- Log output for {name} ---")
                        print(stdout_data)
                        print("-----------------------------")
                    processes.remove((name, p))
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n\n🛑 Shutdown signal received. Terminating all processes...")
    finally:
        shutdown_services()

def shutdown_services():
    for name, p in processes:
        print(f"Stopping: {name} (PID: {p.pid})...")
        p.terminate()
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            print(f"Forcing termination of: {name}...")
            p.kill()
    print("Clean shutdown completed successfully. All ports released.")

if __name__ == "__main__":
    start_services()
    monitor_processes()
