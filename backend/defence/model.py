"""Leakage-safe Random Forest pipelines and versioned local model bundles."""
import hashlib
import json
import platform
import uuid
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from .schema import FEATURES, NUMERIC, CATEGORICAL, CLASSES, SCHEMA_VERSION, ADVICE
from .data import read_records, validate_features, targets, ValidationError

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODELS = ROOT / 'models'

def pipeline(trees=150):
    pre = ColumnTransformer([
        ('numeric', SimpleImputer(strategy='median', keep_empty_features=True), NUMERIC),
        ('categorical', Pipeline([
            ('missing', SimpleImputer(strategy='constant', fill_value='missing', keep_empty_features=True)),
            ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=True)),
        ]), CATEGORICAL),
    ])
    return Pipeline([('preprocess', pre), ('classifier', RandomForestClassifier(
        n_estimators=trees, class_weight='balanced_subsample', random_state=42, n_jobs=-1))])

def evaluate(y, predicted, labels):
    p, r, f, _ = precision_recall_fscore_support(y, predicted, average='weighted', zero_division=0)
    return {'accuracy': accuracy_score(y, predicted), 'precision_weighted': p, 'recall_weighted': r,
            'f1_weighted': f, 'labels': labels, 'confusion_matrix': confusion_matrix(y, predicted, labels=labels).tolist(),
            'per_class': classification_report(y, predicted, labels=labels, output_dict=True, zero_division=0)}

def train(train_path, test_path, output_dir=DEFAULT_MODELS, trees=150, progress=None):
    if not 10 <= trees <= 500:
        raise ValidationError('Choose between 10 and 500 trees.')
    notify = progress or (lambda value, message: None)
    notify(5, 'Reading and validating datasets')
    train_df, test_df = read_records(train_path, True), read_records(test_path, True)
    xtrain, xtest = validate_features(train_df), validate_features(test_df)
    # Deduplicate training only; preserve the official test distribution.
    kept = ~pd.concat([xtrain, train_df.label], axis=1).duplicated()
    train_df, xtrain = train_df.loc[kept], xtrain.loc[kept]
    ybinary, ycategory = targets(train_df)
    if set(ybinary) != {'Normal', 'Attack'}:
        raise ValidationError('Training needs both normal and attack records.')
    if set(ycategory) != set(CLASSES):
        raise ValidationError('Training needs examples from all five categories: ' + ', '.join(CLASSES))
    overlap = len(set(pd.util.hash_pandas_object(xtrain, index=False)) & set(pd.util.hash_pandas_object(xtest, index=False)))
    binary, category = pipeline(trees), pipeline(trees)
    notify(15, 'Training binary Random Forest')
    binary.fit(xtrain, ybinary)
    notify(50, 'Training attack-category Random Forest')
    category.fit(xtrain, ycategory)
    notify(85, 'Evaluating held-out testing file')
    test_binary, test_category = targets(test_df)
    metadata = {'schema_version': SCHEMA_VERSION, 'features': FEATURES, 'model_id': str(uuid.uuid4()),
        'created_at': datetime.now(timezone.utc).isoformat(), 'sklearn_version': sklearn.__version__,
        'python_version': platform.python_version(), 'trees': trees,
        'train_records': len(xtrain), 'test_records': len(xtest), 'training_duplicates_removed': int((~kept).sum()),
        'train_test_feature_overlap': overlap, 'train_name': Path(getattr(train_path, 'name', str(train_path))).name,
        'test_name': Path(getattr(test_path, 'name', str(test_path))).name,
        'training_class_counts': ycategory.value_counts().to_dict(),
        'binary': evaluate(test_binary, binary.predict(xtest), ['Normal', 'Attack']),
        'category': evaluate(test_category, category.predict(xtest), CLASSES)}
    bundle = {'binary': binary, 'category': category, 'metadata': metadata}
    metadata['workflow_category'] = evaluate(test_category, predict(bundle, test_df).category, CLASSES)
    destination = Path(output_dir)
    try:
        destination.mkdir(parents=True, exist_ok=True)
        test_file = destination / '.test_model_write'
        test_file.touch()
        test_file.unlink()
    except (OSError, PermissionError):
        destination = Path('/tmp/models')
        destination.mkdir(parents=True, exist_ok=True)
    # Publish complete files in a unique generation; pointer replacement is atomic.
    generation = destination / metadata['model_id']
    generation.mkdir(exist_ok=True)
    joblib.dump(bundle, generation / 'model.joblib')
    # Reopen before publishing the generation; verify serialization completed.
    reloaded = joblib.load(generation / 'model.joblib')
    if reloaded['metadata']['model_id'] != metadata['model_id']:
        raise ValidationError('Model write verification failed.')
    (generation / 'schema.json').write_text(json.dumps({'version': SCHEMA_VERSION, 'features': FEATURES, 'categorical': CATEGORICAL}, indent=2))
    (generation / 'metrics.json').write_text(json.dumps(metadata, indent=2))
    fingerprint = hashlib.sha256((generation / 'model.joblib').read_bytes()).hexdigest()
    (generation / 'sha256.txt').write_text(fingerprint)
    temp = destination / (metadata['model_id'] + '.tmp')
    temp.write_text(metadata['model_id'])
    temp.replace(destination / 'CURRENT')
    notify(100, 'Model saved')
    return bundle

def load_bundle(model_dir=DEFAULT_MODELS):
    directory = Path(model_dir)
    pointer = directory / 'CURRENT'
    if not pointer.exists():
        tmp_pointer = Path('/tmp/models/CURRENT')
        if tmp_pointer.exists():
            directory = Path('/tmp/models')
            pointer = tmp_pointer
        else:
            raise ValidationError('No trained model. Open Model Training or run python -m scripts.train.')
    identifier = pointer.read_text().strip()
    try:
        uuid.UUID(identifier)
    except ValueError as exc:
        raise ValidationError('Invalid model pointer. Retrain the model.') from exc
    folder = directory / identifier
    try:
        meta = json.loads((folder / 'metrics.json').read_text())
        schema = json.loads((folder / 'schema.json').read_text())
        if schema['features'] != FEATURES or schema['version'] != SCHEMA_VERSION:
            raise ValidationError('Model feature schema is incompatible. Retrain.')
        if meta['sklearn_version'] != sklearn.__version__:
            raise ValidationError(f"Model requires scikit-learn {meta['sklearn_version']}; installed {sklearn.__version__}. Retrain in this environment.")
        if hashlib.sha256((folder / 'model.joblib').read_bytes()).hexdigest() != (folder / 'sha256.txt').read_text().strip():
            raise ValidationError('Model integrity check failed. Retrain.')
        bundle = joblib.load(folder / 'model.joblib')
        if bundle['metadata'] != meta:
            raise ValidationError('Model metadata mismatch. Retrain.')
        for key in ('binary', 'category'):
            if list(bundle[key].feature_names_in_) != FEATURES:
                raise ValidationError('Model input feature mismatch. Retrain.')
        return bundle
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError(f'Cannot load local model: {exc}. Retrain using trusted data.') from exc

def unknown_categories(bundle, frame):
    clean = validate_features(frame)
    enc = bundle['binary'].named_steps['preprocess'].named_transformers_['categorical'].named_steps['onehot']
    return {name: sorted(set(clean[name].dropna()) - set(known)) for name, known in zip(CATEGORICAL, enc.categories_)
            if set(clean[name].dropna()) - set(known)}

def predict(bundle, frame):
    clean = validate_features(frame)
    binary = bundle['binary']
    status = binary.predict(clean)
    bprob = binary.predict_proba(clean)
    category = bundle['category']
    cprob = category.predict_proba(clean)
    attack_indices = [i for i, c in enumerate(category.classes_) if c != 'Normal']
    chosen = np.array(attack_indices)[cprob[:, attack_indices].argmax(axis=1)]
    categories = np.where(status == 'Normal', 'Normal', category.classes_[chosen])
    normal_index = list(category.classes_).index('Normal')
    cat_scores = np.where(status == 'Normal', cprob[:, normal_index], cprob[np.arange(len(frame)), chosen])
    output = pd.DataFrame({'status': status, 'category': categories,
        'model_score': bprob.max(axis=1), 'category_score': cat_scores})
    output['recommendation'] = output.category.map(ADVICE)
    output['model_id'] = bundle['metadata']['model_id']
    return output

def importance(bundle):
    model = bundle['binary']
    names = model.named_steps['preprocess'].get_feature_names_out()
    return pd.DataFrame({'Feature': names, 'Importance': model.named_steps['classifier'].feature_importances_}).sort_values('Importance', ascending=False)
