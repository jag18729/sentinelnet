#!/usr/bin/env python3
"""
FastAPI inference server for SentinelNet.

Endpoints:
- POST /predict - Single prediction
- POST /predict/batch - Batch prediction
- GET /health - Health check
- GET /metrics - Prometheus metrics
"""

import hashlib
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
import pickle
import time

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import numpy as np
import onnxruntime as ort

# Prometheus metrics (optional)
try:
    from prometheus_client import Counter, Histogram, generate_latest
    PREDICTIONS_TOTAL = Counter('sentinelnet_predictions_total', 'Total predictions', ['prediction_class'])
    PREDICTION_LATENCY = Histogram('sentinelnet_prediction_latency_seconds', 'Prediction latency')
    METRICS_ENABLED = True
except ImportError:
    METRICS_ENABLED = False


@dataclass
class AppState:
    """Inference server state — loaded once at startup."""
    model: Optional[ort.InferenceSession] = None
    scaler: Optional[object] = None
    label_encoder: Optional[object] = None
    feature_names: Optional[list] = None


# Module-level aliases for backward compatibility (used by tests)
model = None
scaler = None
label_encoder = None
feature_names = None


def load_artifacts(model_path: Path, artifacts_path: Path) -> AppState:
    """Load model and preprocessing artifacts, return AppState."""
    # Load ONNX model
    if model_path.suffix != '.onnx':
        raise ValueError("Only ONNX models supported for inference")

    # Verify SHA256 checksum if available
    checksum_path = model_path.with_suffix(".onnx.sha256")
    if checksum_path.exists():
        expected_hash = checksum_path.read_text().split()[0]
        actual_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            raise RuntimeError(
                f"Model integrity check failed: expected {expected_hash[:16]}..., "
                f"got {actual_hash[:16]}..."
            )
        print(f"[✓] Model integrity verified (SHA256: {actual_hash[:16]}...)")

    _model = ort.InferenceSession(str(model_path))
    print(f"[✓] Loaded ONNX model: {model_path}")

    # Load scaler
    with open(artifacts_path / "scaler.pkl", "rb") as f:
        _scaler = pickle.load(f)

    # Load label encoder
    with open(artifacts_path / "label_encoder.pkl", "rb") as f:
        _label_encoder = pickle.load(f)

    # Load feature names
    with open(artifacts_path / "feature_names.pkl", "rb") as f:
        _feature_names = pickle.load(f)

    print(f"[✓] Loaded artifacts from {artifacts_path}")
    print(f"    Classes: {_label_encoder.classes_.tolist()}")
    print(f"    Features: {len(_feature_names)}")

    return AppState(
        model=_model,
        scaler=_scaler,
        label_encoder=_label_encoder,
        feature_names=_feature_names,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model and artifacts on startup, warm up ONNX session."""
    global model, scaler, label_encoder, feature_names
    model_path = Path(os.getenv("MODEL_PATH", "models/sentinel.onnx"))
    artifacts_path = Path(os.getenv("ARTIFACTS_PATH", "data/artifacts"))

    if model_path.exists() and artifacts_path.exists():
        state = load_artifacts(model_path, artifacts_path)
        app.state.app_state = state

        # Keep module-level aliases in sync
        model = state.model
        scaler = state.scaler
        label_encoder = state.label_encoder
        feature_names = state.feature_names

        # Validate feature dimensions match ONNX model input
        expected_dim = state.model.get_inputs()[0].shape[1]
        if expected_dim is not None and len(state.feature_names) != expected_dim:
            raise RuntimeError(
                f"Feature dimension mismatch: {len(state.feature_names)} feature names "
                f"but ONNX model expects {expected_dim} inputs"
            )

        # Warm up ONNX session to avoid cold-start latency
        dummy = np.zeros((1, len(state.feature_names)), dtype=np.float32)
        dummy = state.scaler.transform(dummy).astype(np.float32)
        input_name = state.model.get_inputs()[0].name
        state.model.run(None, {input_name: dummy})
        print("[✓] ONNX session warmed up")
    else:
        app.state.app_state = AppState()
        print(f"[!] Model or artifacts not found. Endpoints will fail.")
        print(f"    MODEL_PATH={model_path} (exists={model_path.exists()})")
        print(f"    ARTIFACTS_PATH={artifacts_path} (exists={artifacts_path.exists()})")

    yield


app = FastAPI(
    title="SentinelNet API",
    description="Network Intrusion Detection with Adversarial Robustness",
    version="0.1.0",
    lifespan=lifespan,
)


class PredictionRequest(BaseModel):
    """Single prediction request."""
    features: List[float]


class BatchPredictionRequest(BaseModel):
    """Batch prediction request."""
    samples: List[List[float]]


class PredictionResponse(BaseModel):
    """Prediction response."""
    prediction: str
    confidence: float
    class_id: int
    probabilities: Optional[dict] = None


class BatchPredictionResponse(BaseModel):
    """Batch prediction response."""
    predictions: List[PredictionResponse]
    latency_ms: float


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "classes": label_encoder.classes_.tolist() if label_encoder else None,
    }


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    if not METRICS_ENABLED:
        raise HTTPException(status_code=501, detail="Metrics not enabled")
    from fastapi.responses import Response
    return Response(content=generate_latest(), media_type="text/plain")


@app.post("/predict", response_model=PredictionResponse)
async def predict(request: PredictionRequest):
    """Single prediction endpoint."""
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    start = time.time()

    # Preprocess
    features = np.array(request.features).reshape(1, -1)
    features = scaler.transform(features).astype(np.float32)

    # Inference
    input_name = model.get_inputs()[0].name
    outputs = model.run(None, {input_name: features})
    logits = outputs[0][0]

    # Post-process
    probs = np.exp(logits) / np.exp(logits).sum()  # Softmax
    class_id = int(np.argmax(probs))
    confidence = float(probs[class_id])
    prediction = label_encoder.inverse_transform([class_id])[0]

    # Metrics
    if METRICS_ENABLED:
        PREDICTIONS_TOTAL.labels(prediction_class=str(prediction)).inc()
        PREDICTION_LATENCY.observe(time.time() - start)

    return PredictionResponse(
        prediction=str(prediction),
        confidence=confidence,
        class_id=class_id,
        probabilities={
            str(label_encoder.inverse_transform([i])[0]): float(p)
            for i, p in enumerate(probs)
        },
    )


@app.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(request: BatchPredictionRequest):
    """Batch prediction endpoint."""
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    start = time.time()

    # Preprocess
    features = np.array(request.samples).astype(np.float32)
    features = scaler.transform(features)

    # Inference
    input_name = model.get_inputs()[0].name
    outputs = model.run(None, {input_name: features})
    logits = outputs[0]

    # Post-process
    predictions = []
    for i, sample_logits in enumerate(logits):
        probs = np.exp(sample_logits) / np.exp(sample_logits).sum()
        class_id = int(np.argmax(probs))
        predictions.append(PredictionResponse(
            prediction=str(label_encoder.inverse_transform([class_id])[0]),
            confidence=float(probs[class_id]),
            class_id=class_id,
        ))

    latency_ms = (time.time() - start) * 1000

    return BatchPredictionResponse(
        predictions=predictions,
        latency_ms=latency_ms,
    )


def main():
    """Run the server."""
    import uvicorn
    uvicorn.run(
        "inference.serve:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("RELOAD", "false").lower() == "true",
    )


if __name__ == "__main__":
    main()
