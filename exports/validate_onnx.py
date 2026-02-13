#!/usr/bin/env python3
"""Validate ONNX model on CICIDS2017 dataset."""
import pickle, numpy as np, onnxruntime as ort
from pathlib import Path
import sys
sys.path.insert(0, '.')

with open('data/artifacts/scaler.pkl','rb') as f: scaler = pickle.load(f)
with open('data/artifacts/label_encoder.pkl','rb') as f: le = pickle.load(f)
with open('data/artifacts/feature_names.pkl','rb') as f: fnames = pickle.load(f)

sess = ort.InferenceSession('exports/sentinel.onnx')

from preprocessing.pipeline import load_cicids2017, clean_dataframe
df = load_cicids2017(Path('data'))
df = clean_dataframe(df)

label_col = [c for c in df.columns if 'label' in c.lower()][0]
X = df[[c for c in df.columns if c in fnames]].values
y_true = le.transform(df[label_col].str.strip().values)
X_scaled = scaler.transform(X)

rng = np.random.default_rng(42)
idx = rng.choice(len(X_scaled), size=10000, replace=False)
X_sample = X_scaled[idx].astype(np.float32)
y_sample = y_true[idx]

logits = sess.run(None, {'features': X_sample})[0]
preds = logits.argmax(axis=1)

acc = (preds == y_sample).mean()
print(f"ONNX validation accuracy (10K sample): {acc*100:.2f}%")
print(f"Total dataset size: {len(X):,}")
print(f"Features: {len(fnames)}")
print(f"Classes: {len(le.classes_)}")
print()

header = f"{'Class':<30} {'Correct':>8} {'Total':>8} {'Acc':>8}"
print(header)
print("-" * 58)

correct_by_class = {}
total_by_class = {}
for p, t in zip(preds, y_sample):
    cls = le.classes_[t]
    total_by_class[cls] = total_by_class.get(cls, 0) + 1
    if p == t:
        correct_by_class[cls] = correct_by_class.get(cls, 0) + 1

for cls in sorted(total_by_class.keys()):
    c = correct_by_class.get(cls, 0)
    t = total_by_class[cls]
    print(f"{cls:<30} {c:>8} {t:>8} {c/t*100:>7.2f}%")
