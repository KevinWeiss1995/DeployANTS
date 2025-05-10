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
    

    normal_traffic = {
        "Fwd Packet Length Max": 1280.0,
        "Fwd Packet Length Min": 40.0,
        "Bwd Packet Length Min": 40.0,
        "Flow Bytes/s": 800.0,
        "Flow IAT Mean": 0.05,
        "Flow IAT Min": 0.001,
        "Fwd IAT Total": 10.0,
        "Fwd IAT Mean": 0.05,
        "Fwd IAT Min": 0.001,
        "Bwd IAT Total": 10.0,
        "Bwd IAT Mean": 0.05,
        "Bwd IAT Std": 0.01,
        "Bwd IAT Max": 0.1,
        "Bwd IAT Min": 0.001,
        "Fwd PSH Flags": 1,
        "Bwd Header Length": 320,
        "Fwd Packets/s": 20.0,
        "Bwd Packets/s": 15.0,
        "Min Packet Length": 40,
        "Max Packet Length": 1280,
        "Packet Length Mean": 500.0,
        "Packet Length Std": 300.0,
        "Packet Length Variance": 90000.0,
        "FIN Flag Count": 1,
        "SYN Flag Count": 1,
        "RST Flag Count": 0,
        "PSH Flag Count": 1,
        "ACK Flag Count": 10,
        "URG Flag Count": 0,
        "CWE Flag Count": 0,
        "ECE Flag Count": 0,
        "Down/Up Ratio": 0.75,
        "Average Packet Size": 500.0,
        "Avg Fwd Segment Size": 600.0,
        "Avg Bwd Segment Size": 400.0,
        "Fwd Header Length": 320
    }

    print("\nAnalyzing Attack Traffic Sample:")
    monitor.analyze_traffic(normal_traffic)
    monitor.analyze_traffic(attack_traffic)

if __name__ == "__main__":
    test_model_deployment() 