import argparse
import json
import random
import uuid
import datetime
import os
from pathlib import Path

# Constants for normal behavior
WEB_PROCESSES = ["nginx", "node", "gunicorn"]
NORMAL_SYSCALLS = ["read", "write", "epoll_wait", "stat", "getpid", "futex", "close"]

# Constants for attacks
ATTACK_SCENARIOS = {
    "priv_escape": {
        "name": "Privileged Container Escape",
        "syscalls": ["mount", "openat", "chroot", "execve"],
        "process": "bash"
    },
    "docker_sock": {
        "name": "Mounted Docker Socket Abuse",
        "syscalls": ["socket", "connect", "write", "execve"],
        "process": "docker"
    },
    "mem_inject": {
        "name": "Memory Injection",
        "syscalls": ["ptrace", "process_vm_writev", "capset", "setuid"],
        "process": "python"
    }
}

def generate_session(is_threat=False):
    container_id = uuid.uuid4().hex[:12]
    pod_name = f"pod-{uuid.uuid4().hex[:8]}"
    namespace = random.choice(["default", "kube-system", "monitoring"])
    start_time = datetime.datetime.now(datetime.timezone.utc)
    
    logs = []
    
    if is_threat:
        attack_key = random.choice(list(ATTACK_SCENARIOS.keys()))
        attack = ATTACK_SCENARIOS[attack_key]
        process_name = attack["process"]
        syscalls = attack["syscalls"]
        attack_type = attack["name"]
        threat_flag = 1
    else:
        process_name = random.choice(WEB_PROCESSES)
        # Generate a sequence of normal syscalls
        syscalls = random.choices(NORMAL_SYSCALLS, k=random.randint(10, 50))
        attack_type = "None"
        threat_flag = 0

    # Simulate some normal prefix even for threats to make it realistic
    if is_threat:
        prefix_syscalls = random.choices(NORMAL_SYSCALLS, k=random.randint(5, 15))
        syscalls = prefix_syscalls + syscalls
    
    current_time = start_time
    for syscall in syscalls:
        # Increment time slightly for each syscall
        current_time += datetime.timedelta(milliseconds=random.randint(1, 10))
        
        log_entry = {
            "timestamp": current_time.isoformat(),
            "container_id": container_id,
            "pod_name": pod_name,
            "namespace": namespace,
            "syscall": syscall,
            "process_name": process_name,
            "return_value": random.choice([0, 1, -1]) if syscall not in ["execve", "mount"] else 0,
            "is_threat": threat_flag,
            "attack_type": attack_type
        }
        logs.append(log_entry)
        
    return logs

def main():
    parser = argparse.ArgumentParser(description="Kubernetes Attack Telemetry Simulator")
    parser.add_argument("--num-sessions", type=int, default=100, help="Number of container sessions to simulate")
    parser.add_argument("--threat-ratio", type=float, default=0.1, help="Ratio of sessions that should contain attacks (0.0 to 1.0)")
    parser.add_argument("--output-path", type=str, default="data/raw_ebpf_logs.json", help="Path to write the generated JSON logs")
    
    args = parser.parse_args()
    
    # Ensure directory exists
    output_path = Path(args.output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    all_logs = []
    num_threats = int(args.num_sessions * args.threat_ratio)
    
    # Generate threats
    for _ in range(num_threats):
        all_logs.extend(generate_session(is_threat=True))
        
    # Generate normal sessions
    for _ in range(args.num_sessions - num_threats):
        all_logs.extend(generate_session(is_threat=False))
        
    # Sort logs by timestamp to simulate a real stream
    all_logs.sort(key=lambda x: x["timestamp"])
    
    with open(output_path, "w") as f:
        for log in all_logs:
            f.write(json.dumps(log) + "\n")
            
    print(f"Generated {len(all_logs)} log events across {args.num_sessions} sessions.")
    print(f"Output saved to {args.output_path}")

if __name__ == "__main__":
    main()
