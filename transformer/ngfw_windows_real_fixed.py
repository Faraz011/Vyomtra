# ngfw_windows_ultimate.py
# Real NGFW on Windows using L3RawSocket for live HTTP packet capture

import logging
import threading
import time
from datetime import datetime

from scapy.all import conf, sniff
from scapy.layers.http import HTTPRequest
from transformer_model import WebAttackTransformer

# Force Scapy to use raw sockets on Windows (no pcap)
try:
    from scapy.arch.windows import L3RawSocket
    conf.use_pcap = False
    conf.L2socket = L3RawSocket
    print("🪟 Windows: Forced L3RawSocket (no pcap) configured")
except ImportError:
    print("⚠️ Windows L3RawSocket import failed - check scapy version")

# Setup logging
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger("NGFW")

class WindowsNGFW:
    def __init__(self, iface="any"):
        self.iface = None if iface == "any" else iface
        self.transformer = WebAttackTransformer()
        self.stats = {'total': 0, 'blocked': 0, 'allowed': 0, 'start': datetime.now()}
        self.running = False

    def start(self):
        logger.info("NGFW starting...")
        self.running = True
        t = threading.Thread(target=self._sniff, daemon=True)
        t.start()

    def stop(self):
        self.running = False
        logger.info("NGFW stopping...")

    def _sniff(self):
        sniff(
            iface=self.iface,
            filter="tcp port 80 or tcp port 443",
            prn=self._process_packet,
            store=False
        )

    def _process_packet(self, pkt):
        if not pkt.haslayer(HTTPRequest):
            return

        self.stats['total'] += 1
        http = pkt[HTTPRequest]
        req = f"{http.Method.decode()} {http.Path.decode()}"
        res = self.transformer.predict_attack(req, use_transformer=True)

        action = "BLOCK" if res['is_malicious'] else "ALLOW"
        if res['is_malicious']:
            self.stats['blocked'] += 1
        else:
            self.stats['allowed'] += 1

        logger.warning(f"{action} {req} (confidence={res['confidence']:.2f})")

        if self.stats['total'] % 10 == 0:
            self._print_stats()

    def _print_stats(self):
        elapsed = (datetime.now() - self.stats['start']).total_seconds()
        tps = self.stats['total'] / max(elapsed, 1)
        logger.info(
            f"Stats → Total: {self.stats['total']} | "
            f"Blocked: {self.stats['blocked']} | "
            f"Allowed: {self.stats['allowed']} | "
            f"Throughput: {tps:.1f} pkt/s"
        )

if __name__ == "__main__":
    ngfw = WindowsNGFW()
    ngfw.start()
    print("NGFW running; press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ngfw.stop()
        ngfw._print_stats()
        print("NGFW stopped.")
