from src.network.capture import NetworkCapture
from src.model.inference import NetworkMonitor
from collections import deque
import threading
import time
import logging
from src.server.server import app
from PySide6.QtCore import QObject, Signal, Qt
from PySide6.QtWidgets import QApplication
from src.client.client import AlertWindow
import numpy as np

logger = logging.getLogger(__name__)

class TrafficAnalyzer(QObject):
    alert_signal = Signal(dict)
    
    def __init__(self, interface: str, model, window_size: int = 100, analysis_interval: float = 5.0):
        """
        Args:
            interface: Network interface to monitor
            model: ML model for analysis
            window_size: Number of packets to analyze at once
            analysis_interval: How often to run analysis (seconds)
        """
        super().__init__()
        
        # Remove QApplication creation from here
        self.capture = NetworkCapture(interface)
        self.monitor = NetworkMonitor(model)
        self.window_size = window_size
        self.analysis_interval = analysis_interval
        self.packet_buffer = deque(maxlen=window_size)
        self.stop_flag = threading.Event()
        
        # Connect signal to slot
        self.alert_signal.connect(self._show_alert, Qt.ConnectionType.QueuedConnection)
        
        try:
            self.server_thread = threading.Thread(target=self._run_server)
            self.server_thread.daemon = True 
            self.server_thread.start()
            logger.info("Started explanation server")
        except Exception as e:
            logger.warning(f"Could not start explanation server: {e}")
        
    def start(self):
        """Start capture and analysis threads"""
        self.capture.start_capture()
        self.analysis_thread = threading.Thread(target=self._analyze_loop)
        self.analysis_thread.start()
        
    def stop(self):
        """Stop all threads gracefully"""
        self.stop_flag.set()
        self.capture.stop_flag.set()
        self.capture.capture_thread.join()
        self.analysis_thread.join()
        
    def _show_alert(self, data):
        """Handle alert window creation on main thread"""
        try:
            logger.info("Creating alert window...")
            alert = AlertWindow(
                self.monitor.client,
                data['features'],
                data['prediction'],
                self.monitor.feature_names
            )
            
            # Get initial explanation
            logger.info("Getting explanation...")
            initial_explanation = self.monitor.client.get_explanation(
                data['features'],
                data['prediction'],
                self.monitor.feature_names
            )
            
            logger.info("Showing alert window...")
            alert.show_alert(initial_explanation)
            logger.info("Alert window shown")
        except Exception as e:
            logger.error(f"Failed to show alert window: {e}", exc_info=True)
            
    def _analyze_loop(self):
        """Periodically analyze buffered traffic"""
        while not self.stop_flag.is_set():
            time.sleep(self.analysis_interval)
            
            features = self.capture.get_features()
            if not features:
                continue
            
            logger.info("Analyzing traffic window...")
            logger.debug(f"Number of features extracted: {len(features)}")
            logger.debug(f"Number of features expected: {len(self.monitor.feature_names)}")
            logger.debug(f"Extra features: {set(features.keys()) - set(self.monitor.feature_names)}")
            
            feature_values = [features[name] for name in self.monitor.feature_names]
            prediction = self.monitor.model.predict(np.array([feature_values]))[0][0]
            
            print(f"Probability of malicious traffic: {prediction:.2%}")
            print(f"Classification: {'Malicious' if prediction > 0.5 else 'Benign'}")
            
            if prediction > 0.5:
                self.alert_signal.emit({
                    'features': feature_values,
                    'prediction': prediction
                })

    def _run_server(self):
        app.run(host="localhost", port=5000, use_reloader=False) 