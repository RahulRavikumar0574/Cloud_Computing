import os
import json
import tempfile
import pytest
from pathlib import Path

from telemetry.normalizer import TelemetryNormalizer
from cloud.azure_storage import AzureBlobTelemetryIngester
from cloud.event_dispatcher import SecurityEventDispatcher
from cloud.ingestion_worker import IngestionWorker
from cloud.monitoring import CloudSecurityMetrics


def test_falco_event_normalization():
    falco_raw = {
        "output": "10:30:00: Warning Privileged container escape (user=root proc=bash)",
        "priority": "Warning",
        "rule": "Privileged Container Escape",
        "time": "2026-09-14T10:30:00.123456Z",
        "output_fields": {
            "container.id": "c1234567890a",
            "k8s.pod.name": "nginx-pod-abcde",
            "k8s.ns.name": "production",
            "evt.type": "sys_mount",
            "proc.name": "bash",
            "evt.res": "SUCCESS"
        }
    }
    normalized = TelemetryNormalizer.normalize_event(falco_raw)

    assert normalized["syscall"] == "mount"
    assert normalized["container_id"] == "c1234567890a"
    assert normalized["pod_name"] == "nginx-pod-abcde"
    assert normalized["namespace"] == "production"
    assert normalized["process_name"] == "bash"
    assert normalized["return_value"] == 0
    assert normalized["is_threat"] == 0
    assert normalized["attack_type"] == "None"


def test_tetragon_event_normalization():
    tetragon_raw = {
        "process_kprobe": {
            "process": {
                "pod": {
                    "namespace": "kube-system",
                    "name": "coredns-559",
                    "container": {
                        "id": "containerd://9876543210ab"
                    }
                },
                "binary": "/usr/bin/python3"
            },
            "function_name": "__x64_sys_ptrace",
            "return": {"code": -1}
        },
        "time": "2026-09-14T10:35:00Z"
    }
    normalized = TelemetryNormalizer.normalize_event(tetragon_raw)

    assert normalized["syscall"] == "ptrace"
    assert normalized["container_id"] == "9876543210ab"
    assert normalized["pod_name"] == "coredns-559"
    assert normalized["namespace"] == "kube-system"
    assert normalized["process_name"] == "python3"
    assert normalized["return_value"] == -1


def test_azure_storage_mock_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        ingester = AzureBlobTelemetryIngester(mock_dir=tmpdir)
        assert ingester.mock_mode is True

        # Test upload egress
        sample_report = {
            "incident_id": "test-inc-001",
            "overall_risk_score": 0.95
        }
        success = ingester.upload_egress_report("incident_test.json", sample_report)
        assert success is True

        egress_file = Path(tmpdir) / "egress-alerts" / "incident_test.json"
        assert egress_file.exists()
        with open(egress_file, "r") as f:
            data = json.load(f)
        assert data["incident_id"] == "test-inc-001"

        # Test ingress list & safe deletion
        ingress_dir = Path(tmpdir) / "ingress-telemetry"
        test_blob = ingress_dir / "batch_001.json"
        with open(test_blob, "w") as f:
            json.dump([{"syscall": "mount"}], f)

        blobs = ingester.list_ingress_blobs(max_files=5)
        assert len(blobs) == 1
        assert blobs[0][0] == "batch_001.json"
        assert blobs[0][1] == [{"syscall": "mount"}]

        # Deletion
        deleted = ingester.delete_ingress_blob("batch_001.json")
        assert deleted is True
        assert not test_blob.exists()


def test_event_dispatcher_local_mode():
    with tempfile.TemporaryDirectory() as tmpdir:
        dispatcher = SecurityEventDispatcher(
            topic_endpoint=None,
            local_events_dir=tmpdir,
            save_local_events=True
        )
        assert dispatcher.mode == "local"

        report = {
            "incident_id": "inc-456",
            "container_id": "c-test",
            "pod_name": "pod-test",
            "overall_risk_score": 0.88,
            "bilstm_score": 0.85,
            "xgb_score": 0.91,
            "attack_classification": "Privileged Container Breakout",
            "shap_top_indicators": [{"feature": "count_mount", "contribution": 0.5}]
        }

        res = dispatcher.dispatch_incident(report)
        assert res["status"] == "logged"
        assert res["mode"] == "local"

        saved_file = Path(tmpdir) / "event_inc-456.json"
        assert saved_file.exists()
        with open(saved_file, "r") as f:
            event = json.load(f)
        assert event["subject"] == "container-escape/inc-456"
        assert event["event_type"] == "SecurityAlert.ContainerBreakout"
        assert event["data"]["overall_risk_score"] == 0.88


def test_monitoring_adapter_local_metrics():
    metrics = CloudSecurityMetrics()
    metrics.record_request("/detect", latency_ms=15.5, status_code=200)
    metrics.record_inference(windows_count=2, threats_count=1, max_risk_score=0.92)

    summary = metrics.get_summary()
    assert summary["mode"] == "local"
    assert summary["request_count"] == 1
    assert summary["windows_processed"] == 2
    assert summary["threats_detected"] == 1
    assert summary["max_observed_risk"] == 0.92
