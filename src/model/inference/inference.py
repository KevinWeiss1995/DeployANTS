import tensorflow as tf
import numpy as np
from src.explanations.client import ExplanationClient, AlertWindow
from PySide6.QtWidgets import QApplication
import sys

class NetworkMonitor:
    def __init__(self, model):
        self.model = model
        self.client = ExplanationClient()
        self.app = QApplication.instance() or QApplication(sys.argv)
        # Match exact order from test_deployment.py
        self.feature_names = [
            "Fwd Packet Length Max",
            "Fwd Packet Length Min",
            "Bwd Packet Length Min",
            "Flow Bytes/s",
            "Flow IAT Mean",
            "Flow IAT Min",
            "Fwd IAT Total",
            "Fwd IAT Mean",
            "Fwd IAT Min",
            "Bwd IAT Total",
            "Bwd IAT Mean",
            "Bwd IAT Std",
            "Bwd IAT Max",
            "Bwd IAT Min",
            "Fwd PSH Flags",
            "Bwd Header Length",
            "Fwd Packets/s",
            "Bwd Packets/s",
            "Min Packet Length",
            "Max Packet Length",
            "Packet Length Mean",
            "Packet Length Std",
            "Packet Length Variance",
            "FIN Flag Count",
            "SYN Flag Count",
            "RST Flag Count",
            "PSH Flag Count",
            "ACK Flag Count",
            "URG Flag Count",
            "CWE Flag Count",
            "ECE Flag Count",
            "Down/Up Ratio",
            "Average Packet Size",
            "Avg Fwd Segment Size",
            "Avg Bwd Segment Size",
            "Fwd Header Length"
        ]
        
    def analyze_traffic(self, traffic_data):
        features = np.array([[traffic_data[feature] for feature in self.feature_names]])
        prediction = self.model.predict(features)[0][0]
        
        print(f"Probability of malicious traffic: {prediction:.2%}")
        print(f"Classification: {'Malicious' if prediction > 0.5 else 'Benign'}")
        
        if prediction > 0.5:
            alert = AlertWindow(self.client, list(traffic_data.values()), prediction, self.feature_names)
            explanation = self.client.get_explanation(
                list(traffic_data.values()),
                prediction,
                self.feature_names
            )
            alert.show_alert(explanation)
            return self.app.exec()
        
        return None
