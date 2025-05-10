import sys
import signal
import logging
from pathlib import Path
from multiprocessing import Process
from src.server.server import app
from src.config import Config
from src.network.capture import NetworkCapture
from src.model.inference import NetworkMonitor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def signal_handler(sig, frame):
    logger.info("Shutting down gracefully...")
    sys.exit(0)

def run_server(config):
    app.run(
        host=config.server_host, 
        port=config.server_port,
        use_reloader=False  
    )

def main():
    config = Config()
    monitor = NetworkMonitor(config.model)
    
    # Start network capture
    capture = NetworkCapture(interface="eth0")  # Adjust interface as needed
    capture.start_capture()
    
    try:
        for flow_features in capture._analyze_flows():
            # Analyze the flow
            monitor.analyze_traffic(flow_features)
            
    except KeyboardInterrupt:
        capture.stop_capture()

if __name__ == "__main__":
    main() 