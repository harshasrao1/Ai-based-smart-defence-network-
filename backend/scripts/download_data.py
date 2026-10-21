"""Restore the verified NSL-KDD mirror files listed in the bundled manifest."""
import hashlib
import json
from pathlib import Path
import urllib.request
from defence.model import ROOT
from defence.data import read_records

def main():
    manifest = json.loads((ROOT / 'data' / 'provenance.json').read_text())
    for name, info in manifest['files'].items():
        target = ROOT / 'data' / name
        if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == info['sha256']:
            print(f'{name}: checksum verified')
            continue
        print(f'Downloading {name} from documented public mirror...')
        request = urllib.request.Request(info['url'], headers={'User-Agent': 'SmartDefence-Academic/1.0'})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(50 * 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != info['sha256']:
            raise RuntimeError(f'{name}: checksum mismatch; no file replaced.')
        temporary = target.with_suffix('.download')
        temporary.write_bytes(data)
        try:
            if len(read_records(temporary, True)) != info['records']:
                raise RuntimeError(f'{name}: unexpected row count')
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
        print(f'{name}: saved and verified')

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        raise SystemExit(f'Dataset restoration failed: {exc}')
