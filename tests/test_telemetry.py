import os
import tempfile
from telemetry.attack_simulator import generate_session, BENIGN_SCENARIOS, ATTACK_SCENARIOS, ATTACK_STYLES
from telemetry.log_parser import parse_log_line, process_log_file

def test_generate_normal_session():
    logs = generate_session(is_threat=False, scenario="web")
    assert len(logs) > 0
    for log in logs:
        assert log["is_threat"] == 0
        assert log["attack_type"] == "None"
        assert log["syscall"] in ["read", "write", "epoll_wait", "stat", "getpid", "futex", "close"]

def test_generate_grey_area_normal_sessions():
    for key, profile in BENIGN_SCENARIOS.items():
        logs = generate_session(is_threat=False, scenario=key)
        assert all(log["is_threat"] == 0 and log["attack_type"] == "None" for log in logs)
        assert logs[0]["scenario"] == f"Normal: {profile['name']}"
        assert len(logs) < 50  # one detection window per session

def test_generate_threat_session():
    logs = generate_session(is_threat=True)
    assert len(logs) > 0
    threat_logs = [log for log in logs if log["attack_type"] != "None"]
    assert len(threat_logs) > 0
    assert logs[0]["is_threat"] == 1 # All logs in session carry the flag

def test_generate_every_attack_style():
    for key, attack in ATTACK_SCENARIOS.items():
        for style in ATTACK_STYLES:
            logs = generate_session(is_threat=True, scenario=key, style=style)
            syscalls = [log["syscall"] for log in logs]
            assert all(log["attack_type"] == attack["name"] for log in logs)
            assert any(s in attack["syscalls"] for s in syscalls)
            assert len(logs) < 50  # one detection window per session

def test_parse_valid_log_line():
    valid_line = '{"timestamp": "2026-09-08T10:36:35Z", "container_id": "abc123def456", "pod_name": "pod-1", "namespace": "default", "syscall": "read", "process_name": "nginx", "return_value": 0, "is_threat": 0, "attack_type": "None"}'
    record = parse_log_line(valid_line)
    assert record is not None
    assert "epoch_time" in record
    assert record["epoch_time"] > 0

def test_parse_invalid_json():
    invalid_line = '{"timestamp": "2026-09-08T10:36:35Z", '
    record = parse_log_line(invalid_line)
    assert record is None

def test_parse_missing_fields():
    missing_fields_line = '{"timestamp": "2026-09-08T10:36:35Z", "syscall": "read"}'
    record = parse_log_line(missing_fields_line)
    assert record is None
    
def test_process_log_file():
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write('{"timestamp": "2026-09-08T10:36:35Z", "container_id": "abc123def456", "pod_name": "pod-1", "namespace": "default", "syscall": "read", "process_name": "nginx", "return_value": 0, "is_threat": 0, "attack_type": "None"}\n')
        f.write('invalid json line\n')
        f_name = f.name
        
    records = process_log_file(f_name)
    assert len(records) == 1
    os.remove(f_name)
