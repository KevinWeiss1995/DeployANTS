import requests
import json
import numpy as np
from PySide6.QtWidgets import QMainWindow, QApplication, QTextEdit, QLineEdit, QPushButton, QVBoxLayout, QWidget
from PySide6.QtCore import Qt

class ExplanationClient:
    def __init__(self, server_url="http://localhost:5000"):
        self.server_url = server_url
        
    def get_explanation(self, features, prediction, feature_names, question=None):
        
        features = [float(f) if isinstance(f, np.floating) else int(f) if isinstance(f, np.integer) else f for f in features]
        prediction = float(prediction) if isinstance(prediction, np.floating) else prediction
        
        response = requests.post(f"{self.server_url}/explain", 
            json={
                "features": features,
                "prediction": prediction,
                "feature_names": feature_names,
                "question": question
            })
        return response.json()["explanation"]

class AlertWindow(QMainWindow):
    def __init__(self, client, features, prediction, feature_names):
        super().__init__()
        self.client = client
        self.features = features
        self.prediction = prediction
        self.feature_names = feature_names
        
        self.setWindowTitle("Security Alert")
        self.setMinimumSize(800, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        layout.addWidget(self.text_area)
        
        self.entry = QLineEdit()
        self.entry.setPlaceholderText("Ask a question about this traffic...")
        self.entry.returnPressed.connect(self.send_question)
        layout.addWidget(self.entry)
        
        self.send_button = QPushButton("Ask Question")
        self.send_button.clicked.connect(self.send_question)
        layout.addWidget(self.send_button)
        
    def send_question(self):
        question = self.entry.text()
        if question:
            self.text_area.append(f"\nQ: {question}")
            response = self.client.get_explanation(
                self.features, 
                self.prediction,
                self.feature_names,
                question
            )
            self.text_area.append(f"\nA: {response}\n")
            self.entry.clear()
    
    def show_alert(self, initial_explanation):
        self.text_area.setText(f"ALERT: Malicious Traffic Detected!\n\n{initial_explanation}\n")
        self.show() 