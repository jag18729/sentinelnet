#!/usr/bin/env python3
"""Export trained SentinelNet model to ONNX format."""

import sys, pickle
from pathlib import Path
import torch
import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
from models.sentinel_net import SentinelNet

# Paths
checkpoint = Path("checkpoints/best.pt")
artifacts = Path("data/artifacts")
output = Path("exports/sentinel.onnx")
output.parent.mkdir(exist_ok=True)

# Load artifacts for dimensions
with open(artifacts / "label_encoder.pkl", "rb") as f:
    le = pickle.load(f)
with open(artifacts / "feature_names.pkl", "rb") as f:
    feature_names = pickle.load(f)

input_dim = len(feature_names)
num_classes = len(le.classes_)
print(f"Input dim: {input_dim}, Classes: {num_classes}")
print(f"Classes: {list(le.classes_)}")

# Load model
model = SentinelNet(
    input_dim=input_dim,
    num_classes=num_classes,
    hidden_dim=128,
    num_layers=2,
    dropout=0.3,
)

ckpt = torch.load(checkpoint, map_location="cpu", weights_only=False)
model.load_state_dict(ckpt["model_state_dict"])
model.eval()
print(f"Loaded checkpoint: epoch {ckpt['epoch']}, val_acc {ckpt['val_acc']*100:.2f}%")

# Export
dummy = torch.randn(1, input_dim)
torch.onnx.export(
    model,
    dummy,
    str(output),
    export_params=True,
    opset_version=17,
    do_constant_folding=True,
    input_names=["features"],
    output_names=["logits"],
    dynamic_axes={"features": {0: "batch"}, "logits": {0: "batch"}},
)
print(f"Exported to {output} ({output.stat().st_size / 1024:.1f} KB)")

# Verify
import onnxruntime as ort
sess = ort.InferenceSession(str(output))
onnx_out = sess.run(None, {"features": dummy.numpy()})[0]
torch_out = model(dummy).detach().numpy()
diff = np.abs(onnx_out - torch_out).max()
print(f"ONNX vs PyTorch max diff: {diff:.8f}")
assert diff < 1e-5, f"Mismatch too large: {diff}"
print("✓ ONNX model verified - outputs match")
