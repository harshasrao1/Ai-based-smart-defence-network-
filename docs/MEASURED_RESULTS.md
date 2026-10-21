# Measured evaluation results

Model: `bd93f737-75cf-44f3-ab4b-50ab22eac2b5`
Created (UTC): 2026-10-21T03:37:02.466928+00:00
Scikit-learn: 1.8.0
Training records after deduplication: 125,973
Held-out test records: 22,544
Trees per model: 150
Removed training duplicates: 0
Distinct feature vectors shared by train/test: 654

These are measured on the original-format NSL-KDD files identified in data/provenance.json. No synthetic samples are used in this experiment. Test data is not used to fit preprocessing or classifiers.

| Task | Accuracy | Weighted precision | Weighted recall | Weighted F1 |
|---|---:|---:|---:|---:|
| binary | 77.1647% | 83.5399% | 77.1647% | 76.8473% |
| category | 74.0064% | 79.6047% | 74.0064% | 69.2328% |
| workflow_category | 75.8517% | 81.4548% | 75.8517% | 71.7891% |

`category` evaluates the independent five-class model. `workflow_category` evaluates the category displayed by the application after binary gating. The model scores in predictions are uncalibrated estimates.

## Independent category model: per-class results

| Category | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Normal | 63.7074% | 97.3947% | 77.0290% | 9711 |
| DoS | 96.1193% | 77.3800% | 85.7376% | 7458 |
| Probe | 85.9618% | 59.4382% | 70.2808% | 2421 |
| R2L | 87.5000% | 0.5084% | 1.0108% | 2754 |
| U2R | 50.0000% | 1.0000% | 1.9608% | 200 |

Rare attack categories have substantially weaker detection than frequent classes. Review class-level recall before drawing conclusions from overall accuracy. This historical benchmark is not a substitute for validation on current networks.

Complete confusion matrices and metrics are stored in the active models generation and downloadable in the app.
