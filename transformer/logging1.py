# ngfw_windows_real.py
import logging
import threading
import time
from datetime import datetime
from typing import Dict, Any

from scapy.all import conf, L3RawSocket, sniff, IP, TCP, Raw
from scapy.layers.http import HTTPRequest
from step1_transformer_model import WebAttackTransformer

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger("NGFW")

# Force Scapy to use raw sockets on Windows
conf.use_pcap = False
conf.L2socket = L3RawSocket

class WindowsNGFW:
    def __init__(self, interface="any"):
        self.interface = interface
        self.transformer = WebAttackTransformer()
        self.is_running = False
        self.stats = {
            'total': 0, 'blocked': 0, 'allowed': 0,
            'start': datetime.now()
        }

    def start(self):
        logger.info("Starting NGFW (real packet capture)...")
        self.is_running = True
        t = threading.Thread(target=self._sniff_loop, daemon=True)
        t.start()

    def stop(self):
        logger.info("Stopping NGFW...")
        self.is_running = False

    def _sniff_loop(self):
        sniff(
            iface=None if self.interface == "any" else self.interface,
            filter="tcp port 80 or tcp port 443",
            prn=self._process_packet,
            stop_filter=lambda p: not self.is_running,
            store=False
        )

    def _process_packet(self, packet):
        self.stats['total'] += 1
        if not packet.haslayer(HTTPRequest):
            return

        http = packet[HTTPRequest]
        method = http.Method.decode(errors='ignore')
        path = http.Path.decode(errors='ignore')
        request_str = f"{method} {path}"

        result = self.transformer.predict_attack(request_str, use_transformer=True)
        action = "BLOCK" if result['is_malicious'] else "ALLOW"
        if result['is_malicious']:
            self.stats['blocked'] += 1
        else:
            self.stats['allowed'] += 1

        logger.warning(
            f"{action} {request_str} | confidence={result['confidence']:.2f}"
        )

        if self.stats['total'] % 10 == 0:
            self.print_stats()

    def print_stats(self):
        elapsed = (datetime.now() - self.stats['start']).total_seconds()
        tps = self.stats['total'] / max(elapsed, 1)
        logger.info(
            f"Stats → Total: {self.stats['total']}, "
            f"Blocked: {self.stats['blocked']}, "
            f"Allowed: {self.stats['allowed']}, "
            f"Throughput: {tps:.1f} pkt/s"
        )

if __name__ == "__main__":
    ngfw = WindowsNGFW()
    try:
        ngfw.start()
        print("NGFW running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ngfw.stop()
        ngfw.print_stats()
        print("NGFW stopped.")
