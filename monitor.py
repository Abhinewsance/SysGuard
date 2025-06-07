import time
import subprocess
import random

# Simulated syscall names
SYSCALLS = [
    "open", "read", "write", "close", "execve", "chmod",
    "unlink", "mkdir", "rmdir", "socket", "connect", "accept",
    "send", "recv", "fork", "clone", "kill", "ptrace"
]

MAX_SEQ_LEN = 30
syscall_sequence = []

def predict_sequence(seq):
    syscall_str = " ".join(seq)
    result = subprocess.run(
        ['python3', 'predict_syscall_sequence.py', syscall_str],
        capture_output=True,
        text=True
    )
    return result.stdout.strip()

def simulate_syscall_stream():
    print("[~] Starting simulated syscall monitoring...")
    while True:
        syscall = random.choice(SYSCALLS)
        print(f"[+] Simulated syscall: {syscall}")
        syscall_sequence.append(syscall)

        if len(syscall_sequence) > MAX_SEQ_LEN:
            syscall_sequence.pop(0)

        if len(syscall_sequence) == MAX_SEQ_LEN:
            prediction = predict_sequence(syscall_sequence)
            print(f"[ML Model] Prediction: {prediction}")
            if prediction == "MALICIOUS":
                print("[!] ALERT: Malicious syscall pattern detected. (Simulated block)")
                syscall_sequence.clear()
            else:
                print("[+] Benign syscall pattern.\n")
                syscall_sequence.clear()

        time.sleep(0.5)  # simulate delay between syscalls

if __name__ == "__main__":
    simulate_syscall_stream()
