import argparse
import json
from defence.model import train
from defence.data import ValidationError

def main():
    parser = argparse.ArgumentParser(description='Train binary and five-class Random Forest models.')
    parser.add_argument('--train', default='data/KDDTrain+.txt')
    parser.add_argument('--test', default='data/KDDTest+.txt')
    parser.add_argument('--output', default='models')
    parser.add_argument('--trees', type=int, default=150)
    args = parser.parse_args()
    try:
        bundle = train(args.train, args.test, args.output, args.trees,
                       lambda percent, message: print(f'{percent:3}% {message}', flush=True))
    except (ValidationError, OSError) as exc:
        parser.exit(1, f'Error: {exc}\n')
    print(json.dumps(bundle['metadata'], indent=2))

if __name__ == '__main__':
    main()
