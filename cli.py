import subprocess
import time
import argparse

def monitor_processes():
    print("Starting process monitoring. Press Ctrl+C to stop.\n")
    try:
        while True:
            output = subprocess.check_output(["ps", "aux"], text=True)
            print(output)
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")

def launch_sandbox():
    print("Launching sandboxed bash shell with syscall restrictions...\n")
    # Runs sandbox.py with /bin/bash inside sandbox
    subprocess.call(["python3", "sandbox.py", "/bin/bash"])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SysGuard CLI interface")
    parser.add_argument('--monitor', action='store_true', help='Start process monitoring')
    parser.add_argument('--sandbox', action='store_true', help='Launch sandboxed bash shell')

    args = parser.parse_args()

    if args.monitor:
        monitor_processes()
    elif args.sandbox:
        launch_sandbox()
    else:
        print("Please specify --monitor to start monitoring or --sandbox to launch sandbox.")
