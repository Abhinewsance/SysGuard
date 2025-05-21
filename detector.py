import os
import json

# File paths
LOG_FILE = "../logs/syscall_log.txt"
ALERT_FILE = "alert_log.txt"
DENYLIST_FILE = "../config/denylist.json"

# Color codes for severity levels
COLORS = {
    "HIGH": "\033[1;31m",    # Red
    "MEDIUM": "\033[1;33m",  # Yellow
    "LOW": "\033[1;34m",     # Blue
    "RESET": "\033[0m"       # Reset
}

def load_denylist():
    if not os.path.exists(DENYLIST_FILE):
        print(f"[❌] Denylist file not found: {DENYLIST_FILE}")
        return {}

    with open(DENYLIST_FILE, "r") as file:
        try:
            config = json.load(file)
            return config.get("denylist", {})
        except json.JSONDecodeError:
            print("[❌] Error parsing denylist.json")
            return {}

def detect_suspicious_syscalls():
    denylist = load_denylist()
    if not denylist:
        print("[⚠️] No denylist loaded. Exiting.")
        return

    if not os.path.exists(LOG_FILE):
        print("[❌] Log file not found:", LOG_FILE)
        return

    alerts = []

    print("\n📌 Starting syscall analysis...\n")

    with open(LOG_FILE, "r") as logfile:
        for line_number, line in enumerate(logfile, start=1):
            for syscall, severity in denylist.items():
                if syscall in line:
                    timestamp = line.split()[0] if "[" in line else "N/A"
                    color = COLORS.get(severity.upper(), COLORS["RESET"])
                    alert_msg = f"{timestamp} {color}[{severity}] Suspicious syscall '{syscall}' on line {line_number}:{COLORS['RESET']} {line.strip()}"
                    print(alert_msg)
                    alerts.append(f"{timestamp} [{severity}] {syscall} on line {line_number}: {line.strip()}")

    if alerts:
        with open(ALERT_FILE, "w") as alert_file:
            for alert in alerts:
                alert_file.write(alert + "\n")
        print(f"\n✅ Alerts saved to: {ALERT_FILE}")
    else:
        print("\n✅ No suspicious syscalls found.")

if __name__ == "__main__":
    detect_suspicious_syscalls()
