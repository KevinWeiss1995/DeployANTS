from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
import numpy as np
from typing import Dict
import threading
import queue
import logging

logger = logging.getLogger(__name__)

class NetworkCapture:
    def __init__(self, interface: str, analysis_interval: float = 1.0):
        self.interface = interface
        self.analysis_interval = analysis_interval
        self.packet_queue = queue.Queue()
        self.stop_flag = threading.Event()
        
        self.flow_start_time = time.time()
        self.packet_counts = {True: 0, False: 0}
        self.last_packet_time = {True: self.flow_start_time, False: self.flow_start_time}
        
    def start_capture(self):
        logger.info(f"Starting capture on interface {self.interface}")
        self.flow_start_time = time.time()
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.start()
        
    def _capture_packets(self):
        """Capture packets using scapy"""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                stop_filter=lambda _: self.stop_flag.is_set()
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            
    def _process_packet(self, packet):
        if IP in packet:
            self.packet_queue.put((time.time(), packet))
            
    def get_features(self) -> Dict[str, float]:
        """Extract features from current packet queue"""
        features = {
            # Flow-level features
            "Fwd Packet Length Max": 0.0,
            "Fwd Packet Length Min": float('inf'),
            "Bwd Packet Length Min": float('inf'),
            "Flow Bytes/s": 0.0,
            "Flow IAT Mean": 0.0,
            "Flow IAT Min": float('inf'),
            
            # Forward direction features
            "Fwd IAT Total": 0.0,
            "Fwd IAT Mean": 0.0,
            "Fwd IAT Min": float('inf'),
            "Fwd PSH Flags": 0,
            "Fwd Packets/s": 0.0,
            "Fwd Header Length": 0,
            
            # Backward direction features
            "Bwd IAT Total": 0.0,
            "Bwd IAT Mean": 0.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": 0.0,
            "Bwd IAT Min": float('inf'),
            "Bwd Header Length": 0,
            "Bwd Packets/s": 0.0,
            
            # Packet length features
            "Min Packet Length": float('inf'),
            "Max Packet Length": 0.0,
            "Packet Length Mean": 0.0,
            "Packet Length Std": 0.0,
            "Packet Length Variance": 0.0,
            
            # TCP flags
            "FIN Flag Count": 0,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 0,
            "URG Flag Count": 0,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,
            
            # Ratios and averages
            "Down/Up Ratio": 0.0,
            "Average Packet Size": 0.0,
            "Avg Fwd Segment Size": 0.0,
            "Avg Bwd Segment Size": 0.0
        }

        packets = []
        while not self.packet_queue.empty():
            packets.append(self.packet_queue.get_nowait())
            
        if not packets:
            return None
            
        self._update_features(packets, features)
        return features

    def _update_features(self, packets, features: Dict[str, float]):
        """Update feature dictionary based on packet"""
        for packet in packets:
            packet_time, packet = packet
            length = len(packet)
            is_forward = packet[IP].src < packet[IP].dst
            
            if is_forward:
                features["Fwd Packet Length Max"] = max(features["Fwd Packet Length Max"], length)
                features["Fwd Packet Length Min"] = min(features["Fwd Packet Length Min"], length)
            else:
                features["Bwd Packet Length Min"] = min(features["Bwd Packet Length Min"], length)

            features["Flow Bytes/s"] += length / self.analysis_interval
            features["Flow IAT Mean"] += packet_time - self.last_packet_time[is_forward]
            features["Flow IAT Min"] = min(features["Flow IAT Min"], packet_time - self.last_packet_time[is_forward])
            self.last_packet_time[is_forward] = packet_time
        
            self.packet_counts[is_forward] += 1
            
            fwd_count = max(self.packet_counts[True], 1)
            bwd_count = max(self.packet_counts[False], 1)
            
            features["Fwd IAT Total"] += packet_time - self.flow_start_time
            features["Fwd IAT Mean"] = features["Fwd IAT Total"] / fwd_count
            features["Fwd IAT Min"] = min(features["Fwd IAT Min"], packet_time - self.flow_start_time)
            features["Bwd IAT Total"] += packet_time - self.flow_start_time
            features["Bwd IAT Mean"] = features["Bwd IAT Total"] / bwd_count
            features["Bwd IAT Std"] = np.std([packet_time - self.flow_start_time - features["Fwd IAT Total"]])
            features["Bwd IAT Max"] = max(features["Bwd IAT Max"], packet_time - self.flow_start_time)
            features["Bwd IAT Min"] = min(features["Bwd IAT Min"], packet_time - self.flow_start_time)
            
            if TCP in packet:  # Only process TCP flags if it's a TCP packet
                tcp_flags = int(packet[TCP].flags)  # Convert FlagValue to int
                features["Fwd PSH Flags"] += (tcp_flags & 0x08) >> 3  # Convert to 0/1
                features["Bwd Header Length"] += len(packet[TCP])
                features["FIN Flag Count"] += (tcp_flags & 0x01)
                features["SYN Flag Count"] += (tcp_flags & 0x02) >> 1
                features["RST Flag Count"] += (tcp_flags & 0x04) >> 2
                features["PSH Flag Count"] += (tcp_flags & 0x08) >> 3
                features["ACK Flag Count"] += (tcp_flags & 0x10) >> 4
                features["URG Flag Count"] += (tcp_flags & 0x20) >> 5
                features["CWE Flag Count"] += (tcp_flags & 0x40) >> 6
                features["ECE Flag Count"] += (tcp_flags & 0x80) >> 7
            
            features["Fwd Packets/s"] = fwd_count / self.analysis_interval
            features["Bwd Packets/s"] = bwd_count / self.analysis_interval
            features["Min Packet Length"] = min(features["Min Packet Length"], length)
            features["Max Packet Length"] = max(features["Max Packet Length"], length)
            features["Packet Length Mean"] += length
            features["Down/Up Ratio"] = bwd_count / fwd_count
            features["Average Packet Size"] += length
            features["Avg Fwd Segment Size"] += length if is_forward else 0
            features["Avg Bwd Segment Size"] += length if not is_forward else 0
            features["Fwd Header Length"] += len(packet[IP])
            
        features["Packet Length Mean"] /= len(packets)
        features["Packet Length Std"] = np.sqrt(features["Packet Length Variance"] / len(packets))
        features["Packet Length Variance"] = features["Packet Length Std"] ** 2
        features["Average Packet Size"] /= len(packets)
        features["Avg Fwd Segment Size"] /= len(packets)
        features["Avg Bwd Segment Size"] /= len(packets)
        features["Fwd Header Length"] /= len(packets)
        features["Down/Up Ratio"] = min(max(features["Down/Up Ratio"], 0.0), 1.0)
        features["Fwd IAT Min"] = max(features["Fwd IAT Min"], 0.0)
        features["Bwd IAT Min"] = max(features["Bwd IAT Min"], 0.0)
        features["Fwd IAT Mean"] = max(features["Fwd IAT Mean"], 0.0)
        features["Bwd IAT Mean"] = max(features["Bwd IAT Mean"], 0.0)
        features["Bwd IAT Std"] = max(features["Bwd IAT Std"], 0.0)
        features["Fwd IAT Total"] = max(features["Fwd IAT Total"], 0.0)
        features["Bwd IAT Total"] = max(features["Bwd IAT Total"], 0.0)
        features["Fwd PSH Flags"] = min(max(features["Fwd PSH Flags"], 0), 1)
        features["Bwd Header Length"] = min(max(features["Bwd Header Length"], 0), 1460)
        features["Fwd Packets/s"] = max(features["Fwd Packets/s"], 0.0)
        features["Bwd Packets/s"] = max(features["Bwd Packets/s"], 0.0)
        features["Min Packet Length"] = min(max(features["Min Packet Length"], 0), 1460)
        features["Max Packet Length"] = max(max(features["Max Packet Length"], 0), 1460)
        features["Packet Length Mean"] = max(features["Packet Length Mean"], 0.0)
        features["Packet Length Std"] = max(features["Packet Length Std"], 0.0)
        features["Packet Length Variance"] = max(features["Packet Length Variance"], 0.0)
        features["FIN Flag Count"] = min(max(features["FIN Flag Count"], 0), 1)
        features["SYN Flag Count"] = min(max(features["SYN Flag Count"], 0), 1)
        features["RST Flag Count"] = min(max(features["RST Flag Count"], 0), 1)
        features["PSH Flag Count"] = min(max(features["PSH Flag Count"], 0), 1)
        features["ACK Flag Count"] = min(max(features["ACK Flag Count"], 0), 1)
        features["URG Flag Count"] = min(max(features["URG Flag Count"], 0), 1)
        features["CWE Flag Count"] = min(max(features["CWE Flag Count"], 0), 1)
        features["ECE Flag Count"] = min(max(features["ECE Flag Count"], 0), 1)
        features["Down/Up Ratio"] = max(features["Down/Up Ratio"], 0.0)
        features["Average Packet Size"] = max(features["Average Packet Size"], 0.0)
        features["Avg Fwd Segment Size"] = max(features["Avg Fwd Segment Size"], 0.0)
        features["Avg Bwd Segment Size"] = max(features["Avg Bwd Segment Size"], 0.0)
        features["Fwd Header Length"] = max(features["Fwd Header Length"], 0)
        
        return features 