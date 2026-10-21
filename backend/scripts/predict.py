import argparse
import uuid
from pathlib import Path
import pandas as pd
from defence.data import read_records, ValidationError
from defence.model import load_bundle, predict, unknown_categories
from defence.storage import save_predictions

def main():
    parser = argparse.ArgumentParser(description='Predict compatible NSL-KDD records.')
    parser.add_argument('input')
    parser.add_argument('--output', default='predictions.csv')
    parser.add_argument('--models', default='models')
    parser.add_argument('--save-history', action='store_true')
    args = parser.parse_args()
    try:
        if Path(args.input).resolve() == Path(args.output).resolve():
            raise ValidationError('Choose an output different from the input.')
        model = load_bundle(args.models)
        records = read_records(args.input)
        unknown = unknown_categories(model, records)
        if unknown:
            print('Warning: unseen categorical values encode as all-zero indicators:', unknown)
        result = predict(model, records)
        pd.concat([records.reset_index(drop=True), result], axis=1).to_csv(args.output, index=False)
        if args.save_history:
            save_predictions(result, records, str(uuid.uuid4()), 'CLI')
        print(f'Wrote {len(result)} predictions to {args.output}')
    except (ValidationError, OSError) as exc:
        parser.exit(1, f'Error: {exc}\n')

if __name__ == '__main__':
    main()
