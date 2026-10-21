import argparse
from pathlib import Path
from defence.data import read_records, ValidationError

def main():
    parser = argparse.ArgumentParser(description='Validate original NSL-KDD and export a named CSV.')
    parser.add_argument('input')
    parser.add_argument('output')
    args = parser.parse_args()
    try:
        data = read_records(args.input, require_labels=True)
        target = Path(args.output)
        if target.resolve() == Path(args.input).resolve():
            raise ValidationError('Use a different output path to preserve the source file.')
        target.parent.mkdir(parents=True, exist_ok=True)
        data.to_csv(target, index=False)
        print(f'Validated {len(data):,} records. Wrote {target}')
    except (ValidationError, OSError) as exc:
        parser.exit(1, f'Error: {exc}\n')

if __name__ == '__main__':
    main()
