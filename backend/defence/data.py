"""Strict file parsing and feature validation shared by training and inference."""
from io import StringIO
from pathlib import Path
import numpy as np
import pandas as pd
from .schema import FEATURES, NUMERIC, CATEGORICAL, RATES, BINARY_FLAGS, METADATA, ATTACK_MAP

class ValidationError(ValueError):
    pass

def read_records(source, require_labels=False):
    try:
        if hasattr(source, 'getvalue'):
            raw = source.getvalue()
        elif hasattr(source, 'read'):
            raw = source.read()
        else:
            raw = Path(source).read_bytes()
        text = raw.decode('utf-8-sig') if isinstance(raw, bytes) else raw
        frame = pd.read_csv(StringIO(text), header=None, dtype=str, keep_default_na=False)
    except (OSError, UnicodeError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
        raise ValidationError(f'Cannot read CSV/text records: {exc}') from exc
    if frame.empty:
        raise ValidationError('The input contains no records.')
    first = [str(x).strip() for x in frame.iloc[0]]
    if 'duration' in first or 'protocol_type' in first:
        if len(set(first)) != len(first):
            raise ValidationError('Duplicate column names are not allowed.')
        frame = frame.iloc[1:].copy()
        frame.columns = first
    else:
        if frame.shape[1] not in (41, 42, 43):
            raise ValidationError('Headerless input must contain 41 features, optionally label and difficulty (42/43 columns).')
        frame.columns = FEATURES + (['label'] if frame.shape[1] >= 42 else []) + (['difficulty'] if frame.shape[1] == 43 else [])
    if frame.empty:
        raise ValidationError('The input has a header but no records.')
    frame = frame.reset_index(drop=True).replace(r'^\s*(?:\?|nan|NaN|NA|null)?\s*$', np.nan, regex=True)
    validate_features(frame)
    if require_labels:
        if 'label' not in frame or frame.label.isna().any():
            raise ValidationError('Every training/testing record needs an attack label.')
        labels = frame.label.astype(str).str.strip().str.lower().str.rstrip('.')
        unknown = sorted(set(labels) - set(ATTACK_MAP))
        if unknown:
            raise ValidationError(f'Unknown attack labels: {unknown}. See docs/attack_mapping.json.')
        frame['label'] = labels
    return frame

def validate_features(frame):
    missing = sorted(set(FEATURES) - set(frame.columns))
    extra = sorted(set(frame.columns) - set(FEATURES + ['label', 'difficulty'] + METADATA))
    if missing:
        raise ValidationError('Missing features: ' + ', '.join(missing))
    if extra:
        raise ValidationError('Unexpected columns: ' + ', '.join(extra))
    if frame.empty:
        raise ValidationError('No records supplied.')
    if frame.columns.duplicated().any():
        raise ValidationError('Duplicate columns are not allowed.')
    clean = frame[FEATURES].copy().replace(r'^\s*(?:\?|nan|NaN|NA|null)?\s*$', np.nan, regex=True)
    for name in NUMERIC:
        values = pd.to_numeric(clean[name], errors='coerce')
        invalid = clean[name].notna() & values.isna()
        if invalid.any() or np.isinf(values.to_numpy(dtype=float)).any():
            raise ValidationError(f'{name}: expected finite numeric values or empty cells.')
        if (values.dropna() < 0).any():
            raise ValidationError(f'{name}: negative values are invalid.')
        if name in RATES:
            if (values.dropna() > 1).any():
                raise ValidationError(f'{name}: rate must be between 0 and 1.')
        elif ((values.dropna() % 1) != 0).any():
            raise ValidationError(f'{name}: expected integer counts.')
        if name in BINARY_FLAGS and not values.dropna().isin([0, 1]).all():
            raise ValidationError(f'{name}: expected 0 or 1.')
        if name == 'su_attempted' and not values.dropna().isin([0, 1, 2]).all():
            raise ValidationError('su_attempted: expected 0, 1 or 2.')
        clean[name] = values.astype(float)
    for name in CATEGORICAL:
        clean[name] = clean[name].map(lambda v: str(v).strip().lower() if pd.notna(v) else np.nan)
    return clean

def targets(frame):
    category = frame.label.map(ATTACK_MAP)
    return category.where(category.eq('Normal'), 'Attack'), category

def missing_summary(frame):
    clean = validate_features(frame)
    return clean.isna().sum().rename('Missing').to_frame()
