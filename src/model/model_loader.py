import os
from pathlib import Path
import tensorflow as tf
import boto3
import mlflow
from src.config import Config

class ModelLoader:
    def __init__(self, config: Config):
        self.config = config
        
    def load_model(self):
        if self.config.model_registry == "local":
            return tf.keras.models.load_model(self.config.model_path)
        elif self.config.model_registry == "s3":
            return self._load_from_s3()
        elif self.config.model_registry == "mlflow":
            return self._load_from_mlflow()
            
    def _load_from_s3(self):
        s3 = boto3.client('s3')
        local_path = "/tmp/model.keras"
        bucket = os.getenv('AWS_BUCKET')
        key = f"models/model-{self.config.model_version}.keras"
        s3.download_file(bucket, key, local_path)
        return tf.keras.models.load_model(local_path)
        
    def _load_from_mlflow(self):
        return mlflow.tensorflow.load_model(self.config.model_path) 