import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.network.analyzer import TrafficAnalyzer
from src.config import Config
from src.model.model_loader import ModelLoader
import logging
import time
from PySide6.QtWidgets import QApplication

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    app = QApplication([])
    
    config = Config()
    model_loader = ModelLoader(config)
    model = model_loader.load_model()
    
    from scapy.arch import get_if_list
    interfaces = get_if_list()
    print("\nAvailable interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
 
    idx = int(input("\nSelect interface number: "))
    interface = interfaces[idx]
    
    analyzer = TrafficAnalyzer(
        interface=interface,
        model=model,
        window_size=100,  
        analysis_interval=5.0
    )
    
    try:
        analyzer.start()
        print("\nMonitoring traffic... Press Ctrl+C to stop")
        app.exec()  # Use Qt's event loop instead of our manual one
            
    except KeyboardInterrupt:
        print("\nStopping analysis...")
        analyzer.stop()

if __name__ == "__main__":
    main() 