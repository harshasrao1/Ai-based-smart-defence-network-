import uuid
import pytest
from defence.rules import RuleDetector, simulation_packets
from defence.capture import PacketMonitor
from defence.storage import save_network_event, network_history, network_counts


def packet(source='192.0.2.1', port=443):
    return {'event_id': str(uuid.uuid4()), 'timestamp': '2026-10-21T00:00:00+00:00',
        'source_ip': source, 'destination_ip': '198.51.100.1', 'protocol': 'TCP',
        'source_port': 45000, 'destination_port': port, 'packet_bytes': 64}


def test_scan_requires_eight_distinct_ports_per_source():
    detector = RuleDetector()
    for i in range(7):
        assert detector.observe(packet(port=20+i), i) == []
    # Repeating a port doesn't advance unique-port count.
    assert detector.observe(packet(port=20), 7) == []
    assert detector.observe(packet(source='192.0.2.2', port=90), 8) == []
    result = detector.observe(packet(port=90), 9)
    assert [a['attack_type'] for a in result] == ['Port Scan']
    assert result[0]['evidence']['unique_destination_ports'] == 8
    assert result[0]['confidence'].startswith('Threshold matched')
    # Sustained threshold match must not issue one alert per subsequent packet.
    assert detector.observe(packet(port=91), 9.1) == []


@pytest.mark.parametrize('last_time, expected', [(10, True), (10.0001, False)])
def test_scan_exact_window_boundary(last_time, expected):
    detector = RuleDetector()
    for i in range(7):
        detector.observe(packet(port=20+i), 0)
    alerts = detector.observe(packet(port=27), last_time)
    assert bool(alerts) is expected


@pytest.mark.parametrize('last_time, expected', [(5, True), (5.0001, False)])
def test_rate_exact_window_and_threshold(last_time, expected):
    detector = RuleDetector()
    for _ in range(99):
        assert detector.observe(packet(), 0) == []
    assert detector.observe(packet(source='192.0.2.2'), 1) == []
    result = detector.observe(packet(), last_time)
    assert bool(result) is expected
    if result:
        assert result[0]['attack_type'] == 'High Traffic Rate'
        assert result[0]['threshold'] == 100


def test_sustained_rate_suppressed_then_rearmed():
    detector = RuleDetector()
    output = []
    for i in range(150):
        output.extend(detector.observe(packet(), i * .01))
    assert len(output) == 1
    for i in range(99):
        assert detector.observe(packet(), 20+i*.01) == []
    assert len(detector.observe(packet(), 20.99)) == 1


@pytest.mark.parametrize('scenario, alerts', [('Port Scan', 1), ('High Traffic Rate', 1), ('Normal Traffic', 0)])
def test_simulation_uses_common_engine_without_packets(scenario, alerts):
    monitor = PacketMonitor()
    for record in simulation_packets(scenario):
        monitor.ingest(record, record['simulation_offset'], mode='Simulation')
    result = monitor.alert_snapshot()
    assert len(result) == alerts
    if alerts:
        assert result[0]['attack_type'] == scenario
        assert result[0]['mode'] == 'Simulation'


def test_ip_packet_without_transport_still_counts_for_rate():
    detector = RuleDetector()
    output = []
    for _ in range(100):
        output.extend(detector.observe(packet(port=None), 0))
    assert [a['attack_type'] for a in output] == ['High Traffic Rate']


def test_bounded_state_and_clock_validation():
    detector = RuleDetector(max_sources=2)
    for i in range(3):
        detector.observe(packet(source=f'192.0.2.{i}'), i)
    assert len(detector.sources) == 2
    assert detector.evicted_sources == 1
    with pytest.raises(ValueError): detector.observe(packet(), -1)
    with pytest.raises(ValueError): detector.observe(packet(), float('nan'))


def test_network_persistence_modes_and_idempotency(tmp_path):
    db = tmp_path/'network.sqlite3'
    detector = RuleDetector()
    for i in range(8):
        record = packet(port=20+i)
        alerts = detector.observe(record, i)
        save_network_event(record, alerts, 'Simulation', db)
        save_network_event(record, alerts, 'Simulation', db)
    assert len(network_history(path=db)) == 8
    assert len(network_history(kind='alerts', path=db)) == 1
    assert len(network_history(kind='alerts', mode='Live', path=db)) == 0
    assert len(network_history(kind='alerts', attack_type='Port Scan', path=db)) == 1
    assert len(network_history(search="' OR 1=1 --", path=db)) == 0
    assert network_counts(db)['Simulation'] == {'events': 8, 'alerts': 1}
    assert network_counts(db)['Live'] == {'events': 0, 'alerts': 0}
