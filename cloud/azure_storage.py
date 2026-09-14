import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Callable

from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import AzureError, ResourceNotFoundError

logger = logging.getLogger(__name__)

# Try importing DefaultAzureCredential
try:
    from azure.identity import DefaultAzureCredential
    HAS_AZURE_IDENTITY = True
except ImportError:
    HAS_AZURE_IDENTITY = False


class AzureBlobTelemetryIngester:
    """
    Production-ready telemetry ingester for Azure Blob Storage.
    Supports:
      - DefaultAzureCredential (Managed Identity / Workload Identity) via AZURE_STORAGE_ACCOUNT_URL
      - Connection string via AZURE_STORAGE_CONNECTION_STRING
      - Automatic local filesystem fallback (mock mode) when neither is configured
      - Safe retrieval, JSON validation, retry policies, and safe deletion.
    """

    def __init__(
        self,
        connection_string: Optional[str] = None,
        account_url: Optional[str] = None,
        mock_dir: str = "mock_storage",
        ingress_container: str = "ingress-telemetry",
        egress_container: str = "egress-alerts",
        retry_total: int = 3
    ):
        self.ingress_container = ingress_container
        self.egress_container = egress_container
        self.mock_dir = Path(mock_dir)
        self.retry_total = retry_total

        # Resolution priority:
        # 1. account_url / AZURE_STORAGE_ACCOUNT_URL with DefaultAzureCredential
        # 2. connection_string / AZURE_STORAGE_CONNECTION_STRING
        # 3. mock_dir fallback
        self.account_url = account_url or os.environ.get("AZURE_STORAGE_ACCOUNT_URL")
        self.connection_string = connection_string or os.environ.get("AZURE_STORAGE_CONNECTION_STRING")

        self.blob_service_client: Optional[BlobServiceClient] = None
        self.auth_mode: str = "mock"

        self._initialize_client()

    def _initialize_client(self):
        """Initializes the BlobServiceClient or sets up mock mode."""
        if self.account_url:
            if not HAS_AZURE_IDENTITY:
                logger.warning("azure-identity not installed. Cannot use DefaultAzureCredential with account_url. Falling back to mock mode.")
                self.auth_mode = "mock"
                self._setup_mock_directories()
                return

            try:
                credential = DefaultAzureCredential()
                self.blob_service_client = BlobServiceClient(
                    account_url=self.account_url,
                    credential=credential,
                    retry_total=self.retry_total
                )
                self.auth_mode = "managed_identity"
                logger.info(f"AzureBlobTelemetryIngester connected via DefaultAzureCredential to {self.account_url}")
                self._ensure_containers_exist()
            except Exception as e:
                logger.error(f"Failed to initialize BlobServiceClient with Managed Identity: {e}")
                self.auth_mode = "mock"
                self._setup_mock_directories()

        elif self.connection_string:
            try:
                self.blob_service_client = BlobServiceClient.from_connection_string(
                    self.connection_string,
                    retry_total=self.retry_total
                )
                self.auth_mode = "connection_string"
                logger.info("AzureBlobTelemetryIngester connected via connection string")
                self._ensure_containers_exist()
            except Exception as e:
                logger.error(f"Failed to initialize BlobServiceClient with connection string: {e}")
                self.auth_mode = "mock"
                self._setup_mock_directories()
        else:
            self.auth_mode = "mock"
            logger.info("No Azure Storage credentials or URL provided. Running in local mock mode.")
            self._setup_mock_directories()

    @property
    def mock_mode(self) -> bool:
        return self.auth_mode == "mock"

    def _setup_mock_directories(self):
        (self.mock_dir / self.ingress_container).mkdir(parents=True, exist_ok=True)
        (self.mock_dir / self.egress_container).mkdir(parents=True, exist_ok=True)

    def _ensure_containers_exist(self):
        """Ensures ingress and egress containers exist in Azure Blob Storage."""
        if self.mock_mode or not self.blob_service_client:
            return

        for container_name in [self.ingress_container, self.egress_container]:
            try:
                container_client = self.blob_service_client.get_container_client(container_name)
                if not container_client.exists():
                    container_client.create_container()
                    logger.info(f"Created Azure container: {container_name}")
            except Exception as e:
                logger.warning(f"Could not verify/create container '{container_name}': {e}")

    def _parse_and_validate_blob_data(self, raw_data: bytes, source_name: str) -> Optional[Any]:
        """Safely decodes and parses JSON / NDJSON content."""
        try:
            content_str = raw_data.decode("utf-8").strip()
            if not content_str:
                logger.warning(f"Empty content in {source_name}")
                return None
            try:
                return json.loads(content_str)
            except json.JSONDecodeError:
                # Try NDJSON
                records = [json.loads(line) for line in content_str.splitlines() if line.strip()]
                return records
        except Exception as e:
            logger.error(f"Malformed or invalid JSON data in {source_name}: {e}")
            return None

    def download_ingress_batches(
        self,
        max_files: int = 10,
        delete_after_download: bool = False
    ) -> List[Any]:
        """
        Downloads newly uploaded eBPF/Falco JSON event batches.
        Returns a list of parsed JSON objects (lists of events or dicts).
        """
        batches = []

        if self.mock_mode:
            ingress_path = self.mock_dir / self.ingress_container
            files = sorted(ingress_path.glob("*.json"))[:max_files]
            for file_path in files:
                try:
                    with open(file_path, "rb") as f:
                        raw_data = f.read()
                    parsed = self._parse_and_validate_blob_data(raw_data, str(file_path))
                    if parsed is not None:
                        batches.append(parsed)
                    if delete_after_download:
                        file_path.unlink()
                except Exception as e:
                    logger.error(f"Failed to read/delete mock file {file_path}: {e}")
            return batches

        try:
            container_client = self.blob_service_client.get_container_client(self.ingress_container)
            blob_list = container_client.list_blobs()

            count = 0
            for blob in blob_list:
                if count >= max_files:
                    break
                if not blob.name.endswith(".json"):
                    continue

                blob_client = container_client.get_blob_client(blob)
                try:
                    blob_data = blob_client.download_blob().readall()
                    parsed = self._parse_and_validate_blob_data(blob_data, blob.name)
                    if parsed is not None:
                        batches.append(parsed)
                        count += 1
                        if delete_after_download:
                            blob_client.delete_blob()
                except Exception as e:
                    logger.error(f"Failed to process blob {blob.name}: {e}")

        except Exception as e:
            logger.error(f"Failed to download from Azure Blob Storage: {e}")

        return batches

    def list_ingress_blobs(self, max_files: int = 10) -> List[Tuple[str, Any]]:
        """
        Lists and downloads ingress blobs returning (blob_identifier, parsed_data) pairs
        WITHOUT deleting them. Used by workers for transactional processing.
        """
        results = []

        if self.mock_mode:
            ingress_path = self.mock_dir / self.ingress_container
            files = sorted(ingress_path.glob("*.json"))[:max_files]
            for file_path in files:
                try:
                    with open(file_path, "rb") as f:
                        raw = f.read()
                    parsed = self._parse_and_validate_blob_data(raw, file_path.name)
                    if parsed is not None:
                        results.append((file_path.name, parsed))
                except Exception as e:
                    logger.error(f"Error loading mock blob {file_path.name}: {e}")
            return results

        try:
            container_client = self.blob_service_client.get_container_client(self.ingress_container)
            count = 0
            for blob in container_client.list_blobs():
                if count >= max_files:
                    break
                if not blob.name.endswith(".json"):
                    continue

                blob_client = container_client.get_blob_client(blob)
                try:
                    raw = blob_client.download_blob().readall()
                    parsed = self._parse_and_validate_blob_data(raw, blob.name)
                    if parsed is not None:
                        results.append((blob.name, parsed))
                        count += 1
                except Exception as e:
                    logger.error(f"Error reading blob {blob.name}: {e}")
        except Exception as e:
            logger.error(f"Error listing ingress blobs: {e}")

        return results

    def delete_ingress_blob(self, blob_name: str) -> bool:
        """
        Safely deletes a specific ingress blob after successful processing.
        """
        if self.mock_mode:
            file_path = self.mock_dir / self.ingress_container / blob_name
            try:
                if file_path.exists():
                    file_path.unlink()
                    logger.info(f"Deleted processed mock blob: {blob_name}")
                    return True
            except Exception as e:
                logger.error(f"Failed to delete mock blob {blob_name}: {e}")
            return False

        try:
            container_client = self.blob_service_client.get_container_client(self.ingress_container)
            blob_client = container_client.get_blob_client(blob_name)
            blob_client.delete_blob()
            logger.info(f"Deleted processed Azure blob: {blob_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete Azure blob {blob_name}: {e}")
            return False

    def upload_egress_report(self, report_name: str, payload: Dict[str, Any]) -> bool:
        """
        Uploads processed threat detection reports and SHAP attribution payloads
        to the egress container.
        """
        if not report_name.endswith(".json"):
            report_name += ".json"

        try:
            data = json.dumps(payload, indent=2).encode("utf-8")
        except Exception as e:
            logger.error(f"Failed to serialize payload for {report_name}: {e}")
            return False

        if self.mock_mode:
            egress_path = self.mock_dir / self.egress_container / report_name
            try:
                with open(egress_path, "wb") as f:
                    f.write(data)
                logger.info(f"Mock uploaded report to {egress_path}")
                return True
            except Exception as e:
                logger.error(f"Failed to write mock report {egress_path}: {e}")
                return False

        try:
            blob_client = self.blob_service_client.get_blob_client(
                container=self.egress_container,
                blob=report_name
            )
            blob_client.upload_blob(data, overwrite=True)
            logger.info(f"Uploaded report {report_name} to Azure Blob Storage container '{self.egress_container}'")
            return True
        except Exception as e:
            logger.error(f"Failed to upload report {report_name} to Azure Blob Storage: {e}")
            return False
