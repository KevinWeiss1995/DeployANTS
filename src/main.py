import sys
import signal
import logging
from pathlib import Path
from multiprocessing import Process
from src.server.server import app
from src.config import Config

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

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    config = Config()
    
    server_process = Process(target=run_server, args=(config,))
    server_process.start()
    
    try:
        server_process.join()
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
        server_process.terminate()
        server_process.join()

if __name__ == "__main__":
    main() 