"""Generate deterministic, explicitly synthetic fixtures; never a benchmark."""
from pathlib import Path
import json
import numpy as np
import pandas as pd
from defence.schema import FEATURES, RATES, BINARY_FLAGS, ATTACK_MAP
from defence.model import ROOT

def synthetic_records(count, seed):
    rng = np.random.default_rng(seed)
    records = []
    labels = ['normal', 'neptune', 'satan', 'guess_passwd', 'buffer_overflow']
    for i in range(count):
        label = labels[i % len(labels)]
        row = {feature: 0 for feature in FEATURES}
        row.update(duration=int(rng.integers(0, 150)), protocol_type=rng.choice(['tcp', 'udp', 'icmp']),
            service=rng.choice(['http', 'private', 'domain_u', 'ftp_data']), flag=rng.choice(['sf', 's0', 'rej']),
            src_bytes=int(rng.integers(0, 5000)), dst_bytes=int(rng.integers(0, 5000)),
            count=int(rng.integers(1, 200)), srv_count=int(rng.integers(1, 200)),
            dst_host_count=int(rng.integers(1, 256)), dst_host_srv_count=int(rng.integers(1, 256)))
        for name in RATES:
            row[name] = round(float(rng.random()), 2)
        for name in BINARY_FLAGS:
            row[name] = int(rng.integers(0, 2))
        # Deliberately simple signals to exercise a complete classification workflow.
        row['duration'] += (i % 5) * 300
        row['num_failed_logins'] = 3 if label == 'guess_passwd' else 0
        row['num_root'] = 4 if label == 'buffer_overflow' else 0
        row['label'] = label
        records.append(row)
    return pd.DataFrame(records)

def main():
    sample = ROOT / 'samples'; sample.mkdir(exist_ok=True)
    synthetic_records(250, 42).to_csv(sample / 'synthetic_train.csv', index=False)
    synthetic_records(75, 77).to_csv(sample / 'synthetic_test.csv', index=False)
    synthetic_records(10, 123)[FEATURES].to_csv(sample / 'prediction_sample.csv', index=False)
    (ROOT / 'docs').mkdir(exist_ok=True)
    (ROOT / 'docs' / 'attack_mapping.json').write_text(json.dumps(ATTACK_MAP, indent=2, sort_keys=True))
    (sample / 'README.md').write_text('These CSVs are generated synthetic fixtures, not NSL-KDD or captured attacks.\nThey test workflow functionality only. Do not use their scores as research results.\nRegenerate with: python -m scripts.make_demo\n')
    print('Synthetic samples generated.')

if __name__ == '__main__':
    main()
