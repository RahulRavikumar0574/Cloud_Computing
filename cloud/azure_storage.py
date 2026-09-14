import os
import json
import logging
from azure.storage.blob import BlobServiceClient
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class AzureBlobTelemetryIngester:
    def __init__(self, connection_string: str = None, mock_dir: str = "mock_storage"):
        """
        Initializes the Azure Blob Telemetry Ingester.
        
        Args:
            connection_string: Azure Storage Connection String. If None, looks for env var.
            mock_dir: Local directory to use if no connection string is provided (fallback).
        """
        self.connection_string = connection_string or os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
        self.mock_mode = not bool(self.connection_string)
        self.mock_dir = Path(mock_dir)
        
        self.ingress_container = "ingress-telemetry"
        self.egress_container = "egress-alerts"
        
        if self.mock_mode:
            logger.warning("No AZURE_STORAGE_CONNECTION_STRING provided. Running in mock mode.")
            self._setup_mock_directories()
        else:
            self.blob_service_client = BlobServiceClient.from_connection_string(self.connection_string)
            self._ensure_containers_exist()

    def _setup_mock_directories(self):
        (self.mock_dir / self.ingress_container).mkdir(parents=True, exist_ok=True)
        (self.mock_dir / self.egress_container).mkdir(parents=True, exist_ok=True)

    def _ensure_containers_exist(self):
        try:
            ingress_client = self.blob_service_client.get_container_client(self.ingress_container)
            if not ingress_client.exists():
                ingress_client.create_container()
                
            egress_client = self.blob_service_client.get_container_client(self.egress_container)
            if not egress_client.exists():
                egress_client.create_container()
        except Exception as e:
            logger.error(f"Failed to ensure containers exist: {e}")

    def download_ingress_batches(self, max_files: int = 10, delete_after_download: bool = False) -> List[Dict[str, Any]]:
        """
        Downloads newly uploaded eBPF/Falco JSON event batches.
        Returns a list of parsed JSON batches.
        """
        batches = []
        
        if self.mock_mode:
            ingress_path = self.mock_dir / self.ingress_container
            files = list(ingress_path.glob("*.json"))[:max_files]
            for file_path in files:
                try:
                    with open(file_path, "r") as f:
                        batches.append(json.load(f))
                    if delete_after_download:
                        file_path.unlink()
                except Exception as e:
                    logger.error(f"Failed to read mock file {file_path}: {e}")
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
                    batches.append(json.loads(blob_data))
                    count += 1
                    
                    if delete_after_download:
                        blob_client.delete_blob()
                except Exception as e:
                    logger.error(f"Failed to process blob {blob.name}: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to download from Azure Blob Storage: {e}")
            
        return batches

    def upload_egress_report(self, report_name: str, payload: Dict[str, Any]):
        """
        Uploads processed threat detection reports and SHAP attribution payloads to the egress container.
        """
        if not report_name.endswith(".json"):
            report_name += ".json"
            
        data = json.dumps(payload, indent=2).encode("utf-8")
        
        if self.mock_mode:
            egress_path = self.mock_dir / self.egress_container / report_name
            try:
                with open(egress_path, "wb") as f:
                    f.write(data)
                logger.info(f"Mock uploaded report to {egress_path}")
            except Exception as e:
                logger.error(f"Failed to write mock report {egress_path}: {e}")
            return
            
        try:
            blob_client = self.blob_service_client.get_blob_client(container=self.egress_container, blob=report_name)
            blob_client.upload_blob(data, overwrite=True)
            logger.info(f"Uploaded report {report_name} to Azure Blob Storage")
        except Exception as e:
            logger.error(f"Failed to upload report to Azure Blob Storage: {e}")
