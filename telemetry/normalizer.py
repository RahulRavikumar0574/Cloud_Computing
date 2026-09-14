import json
import re
from typing import Dict, Any, List, Optional


class TelemetryNormalizer:
    """
    Normalizes runtime telemetry from production security agents (Falco, Tetragon)
    into the framework's internal feature representation schema.
    
    IMPORTANT: Real-world agents do not produce ground-truth labels ('is_threat', 'attack_type').
    These fields are initialized to benign defaults (0 / 'None') and will be classified
    dynamically by the ML detection pipeline.
    """

    @staticmethod
    def _clean_syscall_name(raw_name: str) -> str:
        """Strips sys_ prefix or event decorators to produce a canonical syscall name."""
        name = raw_name.lower().strip()
        if name.startswith("sys_"):
            name = name[4:]
        elif name.startswith("__x64_sys_"):
            name = name[10:]
        elif name.startswith("__arm64_sys_"):
            name = name[12:]
        return name

    @staticmethod
    def normalize_falco_event(raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Maps a Falco / Falcosidekick JSON event to standard telemetry schema.
        Expected Falco fields:
          - time / timestamp
          - output_fields: { container.id, k8s.pod.name, k8s.ns.name, evt.type, proc.name, evt.res }
        """
        output_fields = raw_event.get("output_fields", {})
        
        # Determine syscall / event type
        raw_syscall = output_fields.get("evt.type") or raw_event.get("rule", "unknown")
        syscall = TelemetryNormalizer._clean_syscall_name(raw_syscall)

        # Parse return code
        evt_res = str(output_fields.get("evt.res", "SUCCESS")).upper()
        return_value = 0 if evt_res in ["SUCCESS", "0"] else -1

        container_id = output_fields.get("container.id") or raw_event.get("container_id", "host")
        pod_name = output_fields.get("k8s.pod.name") or raw_event.get("pod_name", "host")
        namespace = output_fields.get("k8s.ns.name") or raw_event.get("namespace", "default")
        process_name = output_fields.get("proc.name") or raw_event.get("process_name", "unknown")
        timestamp = raw_event.get("time") or raw_event.get("timestamp", "")

        return {
            "timestamp": timestamp,
            "container_id": container_id,
            "pod_name": pod_name,
            "namespace": namespace,
            "syscall": syscall,
            "process_name": process_name,
            "return_value": return_value,
            "is_threat": 0,
            "attack_type": "None"
        }

    @staticmethod
    def normalize_tetragon_event(raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Maps a Cilium Tetragon JSON event (process_kprobe / process_tracepoint) to schema.
        """
        process_kprobe = raw_event.get("process_kprobe") or raw_event.get("process_tracepoint", {})
        process = process_kprobe.get("process", {})
        pod_info = process.get("pod", {})
        container_info = pod_info.get("container", {})

        raw_func = process_kprobe.get("function_name", "unknown")
        syscall = TelemetryNormalizer._clean_syscall_name(raw_func)

        # Container id may be in format 'containerd://<id>'
        raw_cid = container_info.get("id", "host")
        container_id = raw_cid.split("://")[-1][:12] if "://" in raw_cid else raw_cid[:12]

        pod_name = pod_info.get("name", "host")
        namespace = pod_info.get("namespace", "default")
        process_name = process.get("binary", "unknown").split("/")[-1]
        
        # Return code
        return_code = process_kprobe.get("return", {}).get("code", 0)
        return_val = 0 if return_code == 0 else -1

        timestamp = raw_event.get("time", "")

        return {
            "timestamp": timestamp,
            "container_id": container_id,
            "pod_name": pod_name,
            "namespace": namespace,
            "syscall": syscall,
            "process_name": process_name,
            "return_value": return_val,
            "is_threat": 0,
            "attack_type": "None"
        }

    @staticmethod
    def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Auto-detects format and normalizes the event.
        If already conforming to internal schema, returns a sanitized copy.
        """
        if "output_fields" in event:
            return TelemetryNormalizer.normalize_falco_event(event)
        elif "process_kprobe" in event or "process_tracepoint" in event:
            return TelemetryNormalizer.normalize_tetragon_event(event)

        # Native / synthetic schema: ensure required fields exist
        return {
            "timestamp": event.get("timestamp", ""),
            "container_id": str(event.get("container_id", "unknown")),
            "pod_name": str(event.get("pod_name", "unknown")),
            "namespace": str(event.get("namespace", "default")),
            "syscall": TelemetryNormalizer._clean_syscall_name(str(event.get("syscall", "read"))),
            "process_name": str(event.get("process_name", "unknown")),
            "return_value": int(event.get("return_value", 0)),
            "is_threat": int(event.get("is_threat", 0)),
            "attack_type": str(event.get("attack_type", "None"))
        }

    @staticmethod
    def normalize_batch(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalizes a list of raw events."""
        normalized = []
        for e in events:
            if isinstance(e, dict):
                norm = TelemetryNormalizer.normalize_event(e)
                if norm:
                    normalized.append(norm)
        return normalized
