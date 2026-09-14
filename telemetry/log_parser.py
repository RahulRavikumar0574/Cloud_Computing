import json
import datetime
from typing import List, Dict, Any, Optional

def parse_iso_timestamp(timestamp_str: str) -> Optional[float]:
    """Parse ISO timestamp to UNIX epoch seconds."""
    try:
        # Handle the Z suffix if present
        if timestamp_str.endswith('Z'):
            timestamp_str = timestamp_str[:-1] + '+00:00'
        dt = datetime.datetime.fromisoformat(timestamp_str)
        return dt.timestamp()
    except ValueError:
        return None

def validate_record(record: Dict[str, Any]) -> bool:
    """Validate that the record has all required fields with correct types."""
    required_fields = {
        "timestamp": str,
        "container_id": str,
        "pod_name": str,
        "namespace": str,
        "syscall": str,
        "process_name": str,
        "return_value": int,
        "is_threat": int,
        "attack_type": str
    }
    
    for field, expected_type in required_fields.items():
        if field not in record:
            return False
        if not isinstance(record[field], expected_type):
            return False
            
    return True

def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single JSON log line and validate it."""
    try:
        record = json.loads(line)
        if validate_record(record):
            epoch_time = parse_iso_timestamp(record["timestamp"])
            if epoch_time is not None:
                record["epoch_time"] = epoch_time
                return record
    except json.JSONDecodeError:
        pass
    return None

def process_log_file(file_path: str) -> List[Dict[str, Any]]:
    """Process a file containing JSON log lines."""
    parsed_records = []
    with open(file_path, 'r') as f:
        for line in f:
            parsed_record = parse_log_line(line)
            if parsed_record:
                parsed_records.append(parsed_record)
    return parsed_records
