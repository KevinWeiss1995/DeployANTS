import sys
import os
from pathlib import Path

# Add src to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

import numpy as np
from src.config import Config
from src.model.model_loader import ModelLoader
from src.model.inference import NetworkMonitor

def test_model_deployment():
    config = Config()
    model_loader = ModelLoader(config)
    model = model_loader.load_model()
    
    monitor = NetworkMonitor(model)
    
    attack_traffic = {
        "Fwd Packet Length Max": 50.0,
        "Fwd Packet Length Min": 44.0,
        "Bwd Packet Length Min": 0.0,
        "Flow Bytes/s": 12022.688875459973,
        "Flow IAT Mean": 0.0039095304696718835,
        "Flow IAT Min": 7.867813110351562e-06,
        "Fwd IAT Total": 59.88227820396423,
        "Fwd IAT Mean": 0.0039095304696718835,
        "Fwd IAT Min": 7.867813110351562e-06,
        "Bwd IAT Total": 0.0,
        "Bwd IAT Mean": 0.0,
        "Bwd IAT Std": 0.0,
        "Bwd IAT Max": 0.0,
        "Bwd IAT Min": 0.0,
        "Fwd PSH Flags": 0,
        "Bwd Header Length": 0,
        "Fwd Packets/s": 255.80189096723348,
        "Bwd Packets/s": 0.0,
        "Min Packet Length": 44,
        "Max Packet Length": 50,
        "Packet Length Mean": 47.0,
        "Packet Length Std": 3.0,
        "Packet Length Variance": 9.0,
        "FIN Flag Count": 0,
        "SYN Flag Count": 7659,
        "RST Flag Count": 7659,
        "PSH Flag Count": 0,
        "ACK Flag Count": 7659,
        "URG Flag Count": 0,
        "CWE Flag Count": 0,
        "ECE Flag Count": 0,
        "Down/Up Ratio": 0.0,
        "Average Packet Size": 47.0,
        "Avg Fwd Segment Size": 47.0,
        "Avg Bwd Segment Size": 0.0,
        "Fwd Header Length": 61272
    }

    print("\nAnalyzing Attack Traffic Sample:")
    monitor.analyze_traffic(attack_traffic)

if __name__ == "__main__":
    test_model_deployment() 