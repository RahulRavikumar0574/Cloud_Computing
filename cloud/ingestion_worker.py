import os
import sys
import time
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cloud.azure_storage import AzureBlobTelemetryIngester
from cloud.event_dispatcher import SecurityEventDispatcher
from cloud.engine import SecurityInferenceEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("IngestionWorker")


class IngestionWorker:
    """
    Autonomous Ingestion Worker:
      1. Discovers and downloads incoming telemetry from Azure Blob Storage (or mock storage).
      2. Validates and runs ensemble inference via SecurityInferenceEngine.
      3. Uploads incident reports to egress-alerts container.
      4. Dispatches high-risk alerts to Azure Event Grid.
      5. Safely deletes the source blob only upon successful processing.
      6. Can run as a single batch job (Azure Container App Job / CronJob) or continuous loop.
    """

    def __init__(
        self,
        artifacts_dir: str = "artifacts",
        risk_threshold: float = 0.65,
        storage_ingester: Optional[AzureBlobTelemetryIngester] = None,
        event_dispatcher: Optional[SecurityEventDispatcher] = None
    ):
        self.artifacts_dir = artifacts_dir
        self.risk_threshold = risk_threshold

        logger.info("Initializing IngestionWorker components...")
        self.ingester = storage_ingester or AzureBlobTelemetryIngester()
        self.dispatcher = event_dispatcher or SecurityEventDispatcher()
        self.engine = SecurityInferenceEngine(
            artifacts_dir=self.artifacts_dir,
            risk_threshold=self.risk_threshold
        )
        logger.info(
            f"IngestionWorker initialized. Storage mode: {self.ingester.auth_mode}, "
            f"EventGrid mode: {self.dispatcher.mode}"
        )

    def process_single_blob(self, blob_name: str, raw_payload: Any) -> Dict[str, Any]:
        """Processes a single blob payload through the security pipeline."""
        # Normalize payload to a list of events
        events: List[Dict[str, Any]] = []
        if isinstance(raw_payload, list):
            events = raw_payload
        elif isinstance(raw_payload, dict):
            if "events" in raw_payload and isinstance(raw_payload["events"], list):
                events = raw_payload["events"]
            else:
                events = [raw_payload]
        else:
            logger.warning(f"Unrecognized payload format in blob {blob_name}: {type(raw_payload)}")
            return {"status": "skipped", "error": "unrecognized_format", "threats": 0}

        # Run inference
        detection_result = self.engine.run_detection(events)
        reports = detection_result.get("reports", [])

        # Upload reports and dispatch alerts
        for report in reports:
            incident_id = report.get("incident_id")
            report_filename = f"incident_{incident_id}.json"
            
            # 1. Upload to egress container
            self.ingester.upload_egress_report(report_filename, report)

            # 2. Dispatch to Azure Event Grid
            self.dispatcher.dispatch_incident(report)

        return {
            "status": "success",
            "blob_name": blob_name,
            "processed_windows": detection_result.get("processed_windows", 0),
            "threats_detected": len(reports),
            "reports": reports
        }

    def process_batch(self, max_blobs: int = 10) -> Dict[str, Any]:
        """
        Retrieves pending blobs, processes them, and safely deletes them on success.
        Returns summary of the batch run.
        """
        pending_blobs = self.ingester.list_ingress_blobs(max_files=max_blobs)
        if not pending_blobs:
            logger.debug("No new telemetry blobs found in ingress.")
            return {"processed_blobs": 0, "threats_detected": 0}

        logger.info(f"Discovered {len(pending_blobs)} pending telemetry blobs.")
        total_threats = 0
        successful_blobs = 0
        failed_blobs = 0

        for blob_name, payload in pending_blobs:
            try:
                result = self.process_single_blob(blob_name, payload)
                if result.get("status") == "success":
                    threats = result.get("threats_detected", 0)
                    total_threats += threats
                    # Safe transactional deletion
                    deleted = self.ingester.delete_ingress_blob(blob_name)
                    if deleted:
                        successful_blobs += 1
                    else:
                        logger.warning(f"Processed {blob_name} but could not delete it.")
                else:
                    logger.warning(f"Blob {blob_name} processing skipped or non-standard.")
            except Exception as e:
                failed_blobs += 1
                logger.error(
                    f"Failed to process telemetry blob '{blob_name}': {e}. Blob retained for retry.",
                    exc_info=True
                )

        logger.info(
            f"Batch completed: {successful_blobs} blobs processed & deleted, "
            f"{failed_blobs} failed, {total_threats} threats identified."
        )
        return {
            "processed_blobs": successful_blobs,
            "failed_blobs": failed_blobs,
            "threats_detected": total_threats
        }

    def run_loop(self, poll_interval_seconds: int = 10, max_iterations: Optional[int] = None):
        """Runs the continuous ingestion loop."""
        logger.info(f"Starting ingestion loop (poll interval: {poll_interval_seconds}s)...")
        iterations = 0
        try:
            while True:
                self.process_batch()
                iterations += 1
                if max_iterations and iterations >= max_iterations:
                    logger.info(f"Reached max iterations ({max_iterations}). Stopping.")
                    break
                time.sleep(poll_interval_seconds)
        except KeyboardInterrupt:
            logger.info("IngestionWorker stopped by user.")


def main():
    parser = argparse.ArgumentParser(description="Container Security Telemetry Ingestion Worker")
    parser.add_argument("--once", action="store_true", help="Run a single batch and exit (for CronJobs/ACA Jobs)")
    parser.add_argument("--max-blobs", type=int, default=10, help="Maximum blobs per batch")
    parser.add_argument("--poll-interval", type=int, default=10, help="Polling interval in seconds for continuous mode")
    parser.add_argument("--artifacts-dir", type=str, default=os.environ.get("ARTIFACTS_DIR", "artifacts"))
    parser.add_argument("--risk-threshold", type=float, default=0.65)

    args = parser.parse_args()

    worker = IngestionWorker(
        artifacts_dir=args.artifacts_dir,
        risk_threshold=args.risk_threshold
    )

    if args.once:
        worker.process_batch(max_blobs=args.max_blobs)
    else:
        worker.run_loop(poll_interval_seconds=args.poll_interval)


if __name__ == "__main__":
    main()
