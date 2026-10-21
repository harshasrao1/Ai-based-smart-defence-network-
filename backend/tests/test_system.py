from io import BytesIO
import json
import numpy as np
import pandas as pd
import pytest
from defence.data import read_records, validate_features, targets, ValidationError
from defence.model import train, load_bundle, predict, unknown_categories
from defence.schema import FEATURES, ATTACK_MAP
from defence.storage import save_predictions, history, summary
from scripts.make_demo import synthetic_records

@pytest.fixture
def sample():
    return synthetic_records(30, 101)

@pytest.fixture
def trained(tmp_path):
    training = synthetic_records(60, 12)
    testing = synthetic_records(20, 17)
    # Holdout-only category and extreme value must never enter training statistics.
    testing['service'] = 'test_only_service'
    testing['duration'] = 999999
    a, b = tmp_path / 'train.csv', tmp_path / 'test.csv'
    training.to_csv(a, index=False); testing.to_csv(b, index=False)
    bundle = train(a, b, tmp_path / 'models', trees=10)
    return bundle, tmp_path / 'models', training, testing

@pytest.mark.parametrize('columns', [41, 42, 43])
def test_original_formats(sample, columns):
    frame = sample.copy()
    if columns == 41:
        frame = frame[FEATURES]
    if columns == 43:
        frame['difficulty'] = 21
    data = read_records(BytesIO(frame.to_csv(index=False, header=False).encode()), require_labels=columns > 41)
    assert len(data) == len(sample)
    assert list(validate_features(data)) == FEATURES

@pytest.mark.parametrize('issue', ['missing', 'extra', 'nonnumeric', 'negative', 'infinite', 'rate', 'fraction', 'flag'])
def test_invalid_features_rejected(sample, issue):
    frame = sample.copy()
    if issue == 'missing': frame = frame.drop(columns='service')
    if issue == 'extra': frame['junk'] = 1
    if issue == 'nonnumeric': frame['duration'] = 'oops'
    if issue == 'negative': frame['src_bytes'] = -1
    if issue == 'infinite': frame['src_bytes'] = np.inf
    if issue == 'rate': frame['serror_rate'] = 1.1
    if issue == 'fraction': frame['count'] = 1.5
    if issue == 'flag': frame['land'] = 3
    with pytest.raises(ValidationError): validate_features(frame)

def test_unknown_label_and_malformed_csv(sample):
    sample['label'] = 'made_up_attack'
    with pytest.raises(ValidationError, match='Unknown attack'):
        read_records(BytesIO(sample.to_csv(index=False).encode()), True)
    with pytest.raises(ValidationError):
        read_records(BytesIO(b'broken,input\n1,2,3'))
    with pytest.raises(ValidationError): read_records(BytesIO(b''))

def test_taxonomy_includes_test_attacks():
    assert ATTACK_MAP['apache2'] == 'DoS'
    assert ATTACK_MAP['httptunnel'] == 'U2R'
    assert ATTACK_MAP['snmpguess'] == 'R2L'
    assert ATTACK_MAP['mscan'] == 'Probe'

def test_training_only_preprocessing_and_reload(trained):
    bundle, directory, training, testing = trained
    pre = bundle['binary'].named_steps['preprocess']
    assert pre.named_transformers_['numeric'].statistics_[0] == training.duration.median()
    enc = pre.named_transformers_['categorical'].named_steps['onehot']
    assert 'test_only_service' not in enc.categories_[1]
    loaded = load_bundle(directory)
    before, after = predict(bundle, testing), predict(loaded, testing)
    pd.testing.assert_frame_equal(before, after)
    # Reordering input columns must preserve predictions.
    pd.testing.assert_frame_equal(before, predict(loaded, testing[list(reversed(testing.columns))]))
    assert unknown_categories(loaded, testing) == {'service': ['test_only_service']}
    assert before.model_score.between(0, 1).all()
    assert (before.loc[before.status == 'Normal', 'category'] == 'Normal').all()
    assert (before.loc[before.status == 'Attack', 'category'] != 'Normal').all()
    # Real evaluation supports exactly the holdout population.
    assert np.array(bundle['metadata']['binary']['confusion_matrix']).sum() == len(testing)

def test_missing_values_imputed(trained):
    bundle, _, _, testing = trained
    testing.loc[0, 'duration'] = np.nan
    testing.loc[1, 'service'] = np.nan
    assert len(predict(bundle, testing)) == len(testing)

def test_model_errors_are_actionable(trained, tmp_path):
    _, directory, _, _ = trained
    with pytest.raises(ValidationError, match='No trained model'):
        load_bundle(tmp_path / 'absent')
    folder = directory / (directory / 'CURRENT').read_text()
    schema = json.loads((folder / 'schema.json').read_text())
    schema['features'] = ['wrong']
    (folder / 'schema.json').write_text(json.dumps(schema))
    with pytest.raises(ValidationError, match='schema'):
        load_bundle(directory)

def test_model_corruption(trained):
    _, directory, _, _ = trained
    folder = directory / (directory / 'CURRENT').read_text()
    with (folder / 'model.joblib').open('ab') as stream:
        stream.write(b'corrupt')
    with pytest.raises(ValidationError, match='integrity'):
        load_bundle(directory)

def test_database_idempotent_batch_filter_and_metadata(trained, tmp_path):
    bundle, _, _, testing = trained
    testing['source_ip'] = '192.0.2.9'
    result = predict(bundle, testing)
    db = tmp_path / 'history.sqlite3'
    assert save_predictions(result, testing, 'batch', 'unit', db) == len(testing)
    assert save_predictions(result, testing, 'batch', 'unit', db) == 0
    assert len(history(search='192.0.2.9', path=db)) == len(testing)
    assert len(history(search="' OR 1=1 --", path=db)) == 0
    total, normal, attack, _ = summary(db)
    assert total == len(testing) == normal + attack
    assert len(history(status='Attack', path=db)) == attack

def test_packet_metadata_and_buffer():
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
    except PermissionError:
        pytest.skip("Host denies Scapy network-interface enumeration; live capture requires local permissions")
    from defence.capture import PacketMonitor
    monitor = PacketMonitor()
    monitor.receive(IP(src='192.0.2.1', dst='198.51.100.1') / TCP(sport=12345, dport=443))
    monitor.receive(IPv6(src='2001:db8::1', dst='2001:db8::2') / TCP(sport=1234, dport=80))
    rows = monitor.snapshot()
    assert len(rows) == 2
    assert rows[0]['destination_port'] == 443
    assert rows[1]['source_ip'] == '2001:db8::1'
    assert 'category' not in rows[0]
    monitor.stop()
