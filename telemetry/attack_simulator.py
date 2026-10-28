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

# Benign workload profiles. Some legitimately use syscalls that also appear in attacks,
# which gives the models realistic grey areas instead of perfectly separable data.
BENIGN_SCENARIOS = {
    "web": {
        "name": "Web server",
        "weight": 0.55,
        "processes": WEB_PROCESSES,
        "extra_syscalls": [],
        "extra_count": (0, 0)
    },
    "network_client": {
        "name": "Service calling a database",
        "weight": 0.20,
        "processes": ["node", "gunicorn", "java"],
        "extra_syscalls": ["socket", "connect"],
        "extra_count": (1, 4)
    },
    "maintenance": {
        "name": "Init / maintenance job",
        "weight": 0.15,
        "processes": ["sh", "bash"],
        "extra_syscalls": ["mount", "openat", "execve"],
        "extra_count": (1, 3)
    },
    "debugger": {
        "name": "Debugger / profiler (strace)",
        "weight": 0.10,
        "processes": ["strace", "gdb"],
        "extra_syscalls": ["ptrace", "capset"],
        "extra_count": (1, 3)
    }
}

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
    },
    "ns_escape": {
        "name": "Namespace Escape",
        "syscalls": ["nsenter", "execve"],
        "process": "sh"
    }
}

# How openly an attack runs. Stealthy attacks run only part of the chain, hide it in
# a long stretch of normal activity, and often disguise the process as a web server.
ATTACK_STYLES = {
    "full": {"label": "full chain", "weight": 0.5},
    "stealthy": {"label": "stealthy, partial chain", "weight": 0.5}
}


def _weighted_choice(options):
    keys = list(options.keys())
    return random.choices(keys, weights=[options[k]["weight"] for k in keys], k=1)[0]


def _insert_randomly(base, extras):
    """Inserts each extra syscall at a random position, preserving the base order."""
    result = list(base)
    for syscall in extras:
        result.insert(random.randint(0, len(result)), syscall)
    return result


def generate_session(is_threat=False, scenario=None, style=None):
    """
    Generates one container session of syscall events.

    scenario: a key of BENIGN_SCENARIOS (benign) or ATTACK_SCENARIOS (threat); random if omitted.
    style: a key of ATTACK_STYLES for threats; random if omitted.
    Sessions stay under 50 events so each one maps to a single detection window.
    """
    container_id = uuid.uuid4().hex[:12]
    pod_name = f"pod-{uuid.uuid4().hex[:8]}"
    namespace = random.choice(["default", "kube-system", "monitoring"])
    start_time = datetime.datetime.now(datetime.timezone.utc)

    logs = []

    if is_threat:
        attack_key = scenario or random.choice(list(ATTACK_SCENARIOS.keys()))
        attack = ATTACK_SCENARIOS[attack_key]
        style_key = style or _weighted_choice(ATTACK_STYLES)
        attack_type = attack["name"]
        threat_flag = 1

        if style_key == "full":
            process_name = attack["process"]
            # Simulate some normal prefix even for threats to make it realistic
            prefix_syscalls = random.choices(NORMAL_SYSCALLS, k=random.randint(5, 15))
            syscalls = prefix_syscalls + attack["syscalls"]
        else:
            process_name = random.choice([attack["process"]] + WEB_PROCESSES)
            chain = attack["syscalls"]
            partial = chain if len(chain) <= 2 else chain[:random.randint(2, len(chain) - 1)]
            background = random.choices(NORMAL_SYSCALLS, k=random.randint(20, 40))
            syscalls = _insert_randomly(background, partial)

        session_scenario = f"Attack: {attack_type} ({ATTACK_STYLES[style_key]['label']})"
    else:
        benign_key = scenario or _weighted_choice(BENIGN_SCENARIOS)
        profile = BENIGN_SCENARIOS[benign_key]
        process_name = random.choice(profile["processes"])
        # Generate a sequence of normal syscalls
        syscalls = random.choices(NORMAL_SYSCALLS, k=random.randint(10, 45))
        low, high = profile["extra_count"]
        if high:
            extras = random.choices(profile["extra_syscalls"], k=random.randint(low, high))
            syscalls = _insert_randomly(syscalls, extras)
        attack_type = "None"
        threat_flag = 0
        session_scenario = f"Normal: {profile['name']}"

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
            "attack_type": attack_type,
            "scenario": session_scenario
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
