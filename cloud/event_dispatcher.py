import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Try importing Azure Event Grid and Identity SDKs
try:
    from azure.eventgrid import EventGridPublisherClient, EventGridEvent
    from azure.core.credentials import AzureKeyCredential
    HAS_EVENTGRID = True
except ImportError:
    HAS_EVENTGRID = False

try:
    from azure.identity import DefaultAzureCredential
    HAS_IDENTITY = True
except ImportError:
    HAS_IDENTITY = False


class SecurityEventDispatcher:
    """
    Dispatcher for container security incidents to Azure Event Grid.
    Supports:
      - Azure Event Grid Topic using Managed Identity or Topic Key
      - Local mock fallback: structured logging and optional local persistence (mock_storage/events/)
    """

    def __init__(
        self,
        topic_endpoint: Optional[str] = None,
        topic_key: Optional[str] = None,
        local_events_dir: str = "mock_storage/events",
        save_local_events: bool = True
    ):
        self.topic_endpoint = topic_endpoint or os.environ.get("EVENT_GRID_TOPIC_ENDPOINT")
        self.topic_key = topic_key or os.environ.get("EVENT_GRID_TOPIC_KEY")
        self.local_events_dir = Path(local_events_dir)
        self.save_local_events = save_local_events

        self.client: Optional[Any] = None
        self.mode: str = "local"

        self._initialize()

    def _initialize(self):
        if self.topic_endpoint and HAS_EVENTGRID:
            try:
                if self.topic_key:
                    credential = AzureKeyCredential(self.topic_key)
                    self.client = EventGridPublisherClient(self.topic_endpoint, credential)
                    self.mode = "azure_key"
                    logger.info(f"EventDispatcher initialized with Topic Key for {self.topic_endpoint}")
                elif HAS_IDENTITY:
                    credential = DefaultAzureCredential()
                    self.client = EventGridPublisherClient(self.topic_endpoint, credential)
                    self.mode = "azure_managed_identity"
                    logger.info(f"EventDispatcher initialized with Managed Identity for {self.topic_endpoint}")
                else:
                    logger.warning("Event Grid endpoint set, but neither key nor DefaultAzureCredential available. Falling back to local mode.")
                    self.mode = "local"
            except Exception as e:
                logger.error(f"Failed to initialize EventGridPublisherClient: {e}. Falling back to local mode.")
                self.mode = "local"
        else:
            self.mode = "local"
            logger.info("No EVENT_GRID_TOPIC_ENDPOINT provided or SDK unavailable. Running in local event dispatcher mode.")

        if self.mode == "local" and self.save_local_events:
            self.local_events_dir.mkdir(parents=True, exist_ok=True)

    def format_incident_data(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Ensures the event data conforms to the required specification schema."""
        return {
            "incident_id": report.get("incident_id", "unknown"),
            "container_id": report.get("container_id", "unknown"),
            "pod_name": report.get("pod_name", "unknown"),
            "overall_risk_score": float(report.get("overall_risk_score", 0.0)),
            "bilstm_score": float(report.get("bilstm_score", 0.0)),
            "xgb_score": float(report.get("xgb_score", 0.0)),
            "attack_classification": report.get("attack_classification", "Unknown"),
            "shap_top_indicators": report.get("shap_top_indicators", [])
        }

    def dispatch_incident(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dispatches a security incident to Azure Event Grid or local mock destination.
        Returns a result status dictionary.
        """
        incident_id = report.get("incident_id", "unknown")
        subject = f"container-escape/{incident_id}"
        event_type = "SecurityAlert.ContainerBreakout"
        event_data = self.format_incident_data(report)

        # 1. Azure Mode
        if self.mode.startswith("azure") and self.client and HAS_EVENTGRID:
            try:
                event = EventGridEvent(
                    subject=subject,
                    event_type=event_type,
                    data=event_data,
                    data_version="1.0"
                )
                self.client.send([event])
                logger.warning(
                    f"Successfully published Incident {incident_id} to Azure Event Grid topic {self.topic_endpoint}"
                )
                return {
                    "status": "published",
                    "mode": self.mode,
                    "incident_id": incident_id,
                    "destination": self.topic_endpoint
                }
            except Exception as e:
                logger.error(f"Failed to publish incident {incident_id} to Azure Event Grid: {e}")
                # Fall back to local logging on failure
                self._dispatch_local(incident_id, subject, event_type, event_data)
                return {
                    "status": "fallback_local",
                    "mode": "local",
                    "incident_id": incident_id,
                    "error": str(e)
                }

        # 2. Local Mode
        return self._dispatch_local(incident_id, subject, event_type, event_data)

    def _dispatch_local(
        self,
        incident_id: str,
        subject: str,
        event_type: str,
        event_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Dispatches an incident in local mode (structured log + optional file)."""
        logger.warning(
            f"[LOCAL DISPATCH] Security Incident Alert: {subject} | Type: {event_type} | "
            f"Risk: {event_data.get('overall_risk_score', 0):.4f} | Container: {event_data.get('container_id')}"
        )

        saved_path = None
        if self.save_local_events:
            try:
                file_path = self.local_events_dir / f"event_{incident_id}.json"
                event_envelope = {
                    "subject": subject,
                    "event_type": event_type,
                    "data": event_data,
                    "data_version": "1.0"
                }
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(event_envelope, f, indent=2)
                saved_path = str(file_path)
            except Exception as e:
                logger.error(f"Failed to save local event file: {e}")

        return {
            "status": "logged",
            "mode": "local",
            "incident_id": incident_id,
            "saved_to": saved_path
        }
