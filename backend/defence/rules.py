"""Source-IP sliding-window rules, independent of the NSL-KDD classifiers."""
from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone
import math
import uuid

RULES = {
    'Port Scan': {'threshold': 8, 'window_seconds': 10, 'severity': 'High'},
    'High Traffic Rate': {'threshold': 100, 'window_seconds': 5, 'severity': 'Medium'},
}

class RuleDetector:
    """One alert per threshold crossing, independently for each source and rule.

    Windows include the exact left boundary. Clock must be nondecreasing.
    Rate buffers retain the latest 100 times, sufficient to test >=100.
    At most max_sources are tracked; evictions reset the evicted source's state.
    """
    def __init__(self, max_sources=4096):
        self.sources = OrderedDict()
        self.max_sources = max_sources
        self.last_time = -math.inf
        self.evicted_sources = 0

    def observe(self, record, now):
        if not math.isfinite(now) or now < self.last_time:
            raise ValueError('Rule observation clock must be finite and nondecreasing.')
        self.last_time = now
        source = str(record['source_ip'])
        # Idle sources no longer contribute to any window; discard to bound state.
        while self.sources and next(iter(self.sources.values()))['last'] < now - 10:
            self.sources.popitem(last=False)
        if source not in self.sources:
            if len(self.sources) >= self.max_sources:
                self.sources.popitem(last=False)
                self.evicted_sources += 1
            self.sources[source] = {'packets': deque(maxlen=100), 'ports': {}, 'active': set(), 'last': now}
        state = self.sources[source]
        self.sources.move_to_end(source)
        state['last'] = now
        packets, ports = state['packets'], state['ports']
        # Expire first, then rearm below-threshold rules before processing this packet.
        while packets and packets[0] < now - 5:
            packets.popleft()
        for port in [p for p, ts in ports.items() if ts < now - 10]:
            del ports[port]
        if len(packets) < 100:
            state['active'].discard('High Traffic Rate')
        if len(ports) < 8:
            state['active'].discard('Port Scan')
        packets.append(now)
        port = record.get('destination_port')
        if port is not None:
            port = int(port)
            if not 0 <= port <= 65535:
                raise ValueError('Destination port must be between 0 and 65535.')
            ports[port] = now
        matches = {'Port Scan': len(ports) >= 8, 'High Traffic Rate': len(packets) >= 100}
        alerts = []
        for name, matched in matches.items():
            if not matched or name in state['active']:
                continue
            state['active'].add(name)
            definition = RULES[name]
            evidence = {'unique_destination_ports': len(ports), 'destination_ports': sorted(ports)} if name == 'Port Scan' else {'at_least_packets': 100}
            alerts.append({'alert_id': str(uuid.uuid4()), 'timestamp': record['timestamp'],
                'source_ip': source, 'destination_ip': record.get('destination_ip'),
                'attack_type': name, 'severity': definition['severity'],
                'confidence': 'Threshold matched (rule-based; no probability)',
                'threshold': definition['threshold'], 'window_seconds': definition['window_seconds'],
                'evidence': evidence,
                'recommendation': 'Investigate contacted ports and exposed services.' if name == 'Port Scan' else 'Review traffic volume and service load; check for legitimate bursts before applying rate limits.'})
        return alerts

def simulation_packets(scenario):
    """Synthetic metadata only. No packets are transmitted or sockets opened."""
    base = datetime.now(timezone.utc)
    if scenario == 'Port Scan':
        count, spacing = 8, 0.2
    elif scenario == 'High Traffic Rate':
        count, spacing = 100, 0.04
    else:
        count, spacing = 20, 0.5
    return [{'timestamp': (base + timedelta(seconds=i * spacing)).isoformat(),
        'source_ip': '192.0.2.10', 'destination_ip': '198.51.100.20',
        'protocol': 'TCP', 'source_port': 45000 + i,
        'destination_port': 20 + i if scenario == 'Port Scan' else 443,
        'packet_bytes': 64, 'simulation_offset': i * spacing} for i in range(count)]
