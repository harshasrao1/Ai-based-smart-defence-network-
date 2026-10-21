"""Bounded passive packet inspection. No NSL-KDD predictions are made here."""
from collections import deque
from datetime import datetime, timezone
import threading
import time
import uuid
from .rules import RuleDetector
from .storage import save_network_event

class PacketMonitor:
    def __init__(self, persist=False):
        self.rows = deque(maxlen=1000)
        self.lock = threading.Lock()
        self.sniffer = None
        self.error = None
        self.started = None
        self.count = 0
        self.detector = RuleDetector()
        self.alerts = deque(maxlen=1000)
        self.persist = persist

    @property
    def running(self):
        return bool(self.sniffer and self.sniffer.running)

    def receive(self, packet):
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        network = packet.getlayer(IP) or packet.getlayer(IPv6)
        if network is None:
            return
        transport = packet.getlayer(TCP) or packet.getlayer(UDP)
        record = {'timestamp': datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat(),
            'source_ip': network.src, 'destination_ip': network.dst,
            'protocol': 'TCP' if packet.haslayer(TCP) else 'UDP' if packet.haslayer(UDP) else str(getattr(network, 'proto', getattr(network, 'nh', 'other'))),
            'source_port': int(transport.sport) if transport else None,
            'destination_port': int(transport.dport) if transport else None,
            'packet_bytes': len(packet)}
        self.ingest(record)

    def ingest(self, record, observed_at=None, mode='Live'):
        record = dict(record)
        record.setdefault('event_id', str(uuid.uuid4()))
        record['mode'] = mode
        with self.lock:
            alerts = self.detector.observe(record, time.monotonic() if observed_at is None else observed_at)
            self.rows.append(record)
            self.alerts.extend(dict(a, mode=mode) for a in alerts)
            self.count += 1
            if self.persist:
                try:
                    save_network_event(record, alerts, mode)
                except Exception as exc:
                    self.error = f'History write failed: {exc}'
            return alerts

    def alert_snapshot(self):
        with self.lock:
            return list(self.alerts)

    def start(self, interface, duration=60):
        from scapy.all import AsyncSniffer
        self.stop()
        self.error = None
        with self.lock:
            self.detector = RuleDetector()
        self.started = time.monotonic()
        self.sniffer = AsyncSniffer(iface=interface, prn=self.receive, store=False)
        self.sniffer.start()
        threading.Thread(target=self._watch, args=(duration,), daemon=True).start()

    def _watch(self, duration=None):
        sniffer = self.sniffer
        if not sniffer:
            return
        try:
            sniffer.join(timeout=duration)
            if self.running:
                try:
                    sniffer.stop()
                except Exception:
                    pass
        except Exception as exc:
            self.error = str(exc)

    def stop(self):
        if self.running:
            try:
                self.sniffer.stop()
            except Exception as exc:
                self.error = str(exc)

    def snapshot(self):
        with self.lock:
            return list(self.rows)

def interfaces():
    from scapy.all import get_if_list
    raw_list = get_if_list()
    win_ifs = {}
    try:
        from scapy.arch.windows import get_windows_if_list
        for item in get_windows_if_list():
            guid = (item.get('guid') or '').strip('{}').lower()
            if guid:
                win_ifs[guid] = item
    except Exception:
        pass

    results = []
    for dev in raw_list:
        dev_str = str(dev)
        guid_match = dev_str.replace('\\Device\\NPF_', '').strip('{}').lower()
        info = win_ifs.get(guid_match)
        if info:
            name = info.get('name') or ''
            desc = info.get('description') or ''
            ips = [ip for ip in (info.get('ips') or []) if not ip.startswith('fe80:') and not ip.startswith('169.254.')]
            ip_str = f" ({', '.join(ips)})" if ips else ''
            label = f"{name}: {desc}{ip_str}" if name and desc else (name or desc or dev_str)
            active = bool(ips)
        elif 'loopback' in dev_str.lower():
            label = 'Npcap Loopback Adapter (127.0.0.1)'
            active = True
        else:
            label = dev_str
            active = False
        results.append({'id': dev_str, 'name': label, 'active': active})

    results.sort(key=lambda x: not x['active'])
    return results

def demo_packets():
    """Synthetic documentation addresses; replay is not a threat prediction."""
    return [{'timestamp': datetime.now(timezone.utc).isoformat(),
        'source_ip': f'192.0.2.{i % 5 + 1}', 'destination_ip': '198.51.100.10',
        'protocol': 'UDP' if i % 3 == 0 else 'TCP', 'source_port': 41000 + i,
        'destination_port': 53 if i % 3 == 0 else 443, 'packet_bytes': 64 + i * 19}
        for i in range(20)]
