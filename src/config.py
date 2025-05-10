import os
from pathlib import Path
from typing import Dict, Any

class Config:
    def __init__(self):
        self.env = os.getenv("DEPLOYMENT_ENV", "development")
        self.model_registry = os.getenv("MODEL_REGISTRY", "local")
        self.model_version = os.getenv("MODEL_VERSION", "latest")
        self.model_path = self._get_model_path()
        self.server_host = os.getenv("SERVER_HOST", "0.0.0.0")
        self.server_port = int(os.getenv("SERVER_PORT", "5000"))
        self.llm_model = os.getenv("LLM_MODEL", "orca-mini-3b-gguf2-q4_0.gguf")
        self.llm_max_workers = int(os.getenv("LLM_MAX_WORKERS", "20"))
        
    def _get_model_path(self) -> str:
        if self.model_registry == "local":
            return str(Path(__file__).parent.parent / "model" / "models" / "model.keras")
        elif self.model_registry == "s3":
            return f"s3://{os.getenv('AWS_BUCKET')}/models/model-{self.model_version}.keras"
        elif self.model_registry == "mlflow":
            return f"models:/ANTS/{self.model_version}"
        raise ValueError(f"Unknown model registry: {self.model_registry}") 