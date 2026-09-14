import os
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("MonitoringAdapter")

# Check for Azure Monitor OpenTelemetry
HAS_AZURE_MONITOR = False
try:
    from azure.monitor.opentelemetry import configure_azure_monitor
    from opentelemetry import metrics
    HAS_AZURE_MONITOR = True
except ImportError:
    HAS_AZURE_MONITOR = False


class CloudSecurityMetrics:
    """
    Monitoring and Metrics Adapter for Cloud Security Engine.
    Integrates with Azure Monitor / Application Insights when configured,
    and falls back to thread-safe local in-memory aggregation for local mode.
    """

    def __init__(self, connection_string: Optional[str] = None):
        self.connection_string = (
            connection_string or
            os.environ.get("APPLICATIONINSIGHTS_CONNECTION_STRING") or
            os.environ.get("AZURE_MONITOR_CONNECTION_STRING")
        )

        self.azure_mode = bool(self.connection_string and HAS_AZURE_MONITOR)

        # In-memory metric counters (always tracked)
        self.total_requests: int = 0
        self.total_errors: int = 0
        self.total_latency_ms: float = 0.0
        self.total_windows_processed: int = 0
        self.total_threats_detected: int = 0
        self.total_high_risk_incidents: int = 0
        self.max_observed_risk: float = 0.0
        self.inference_failures: int = 0

        self.meter = None
        self._init_azure_monitor()

    def _init_azure_monitor(self):
        if self.azure_mode:
            try:
                configure_azure_monitor(connection_string=self.connection_string)
                self.meter = metrics.get_meter("cloud_sec_engine", "2.0.0")
                self.req_counter = self.meter.create_counter("request_count")
                self.threat_counter = self.meter.create_counter("threats_detected")
                self.incident_counter = self.meter.create_counter("high_risk_incidents")
                self.latency_recorder = self.meter.create_histogram("request_latency_ms")
                logger.info("Azure Monitor OpenTelemetry successfully configured.")
            except Exception as e:
                logger.error(f"Failed to initialize Azure Monitor: {e}. Falling back to local metrics.")
                self.azure_mode = False
        else:
            logger.info("Running in local metrics mode (Azure Monitor not configured).")

    def record_request(self, endpoint: str, latency_ms: float, status_code: int):
        """Records HTTP request telemetry."""
        self.total_requests += 1
        self.total_latency_ms += latency_ms
        if status_code >= 400:
            self.total_errors += 1

        if self.azure_mode and self.meter:
            try:
                tags = {"endpoint": endpoint, "status_code": str(status_code)}
                self.req_counter.add(1, tags)
                self.latency_recorder.record(latency_ms, tags)
            except Exception as e:
                logger.debug(f"Telemetry export error: {e}")

    def record_inference(self, windows_count: int, threats_count: int, max_risk_score: float):
        """Records ML detection telemetry."""
        self.total_windows_processed += windows_count
        self.total_threats_detected += threats_count
        if max_risk_score > self.max_observed_risk:
            self.max_observed_risk = max_risk_score

        if threats_count > 0:
            self.total_high_risk_incidents += threats_count

        if self.azure_mode and self.meter:
            try:
                self.threat_counter.add(threats_count)
                if threats_count > 0:
                    self.incident_counter.add(threats_count)
            except Exception as e:
                logger.debug(f"Telemetry export error: {e}")

    def record_inference_failure(self, reason: str):
        """Records an ML inference processing error."""
        self.inference_failures += 1
        logger.error(f"Inference failure recorded: {reason}")

    def get_summary(self) -> Dict[str, Any]:
        """Returns snapshot summary of tracked metrics."""
        avg_latency = (
            round(self.total_latency_ms / self.total_requests, 2)
            if self.total_requests > 0 else 0.0
        )
        return {
            "mode": "azure_monitor" if self.azure_mode else "local",
            "request_count": self.total_requests,
            "request_errors": self.total_errors,
            "avg_latency_ms": avg_latency,
            "windows_processed": self.total_windows_processed,
            "threats_detected": self.total_threats_detected,
            "high_risk_incidents": self.total_high_risk_incidents,
            "max_observed_risk": round(self.max_observed_risk, 4),
            "inference_failures": self.inference_failures
        }


# Global metrics instance
metrics_client = CloudSecurityMetrics()
