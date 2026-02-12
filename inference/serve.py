#!/usr/bin/env python3
"""
FastAPI inference server for SentinelNet.

Endpoints:
- POST /predict - Single prediction
- POST /predict/batch - Batch prediction
- GET /health - Health check
- GET /metrics - Prometheus metrics
"""

import os
from pathlib import Path
from typing import List, Optional
import pickle
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import numpy as np
import onnxruntime as ort

# Prometheus metrics (optional)
try:
    from prometheus_client import Counter, Histogram, generate_latest
    PREDICTIONS_TOTAL = Counter('sentinelnet_predictions_total', 'Total predictions', ['class'])
    PREDICTION_LATENCY = Histogram('sentinelnet_prediction_latency_seconds', 'Prediction latency')
    METRICS_ENABLED = True
except ImportError:
    METRICS_ENABLED = False

app = FastAPI(
    title="SentinelNet API",
    description="Network Intrusion Detection with Adversarial Robustness",
    version="0.1.0",
)

# Global model and artifacts
model = None
scaler = None
label_encoder = None
feature_names = None


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


def load_artifacts(model_path: Path, artifacts_path: Path):
    """Load model and preprocessing artifacts."""
    global model, scaler, label_encoder, feature_names
    
    # Load ONNX model
    if model_path.suffix == '.onnx':
        model = ort.InferenceSession(str(model_path))
        print(f"[✓] Loaded ONNX model: {model_path}")
    else:
        raise ValueError("Only ONNX models supported for inference")
    
    # Load scaler
    with open(artifacts_path / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    
    # Load label encoder
    with open(artifacts_path / "label_encoder.pkl", "rb") as f:
        label_encoder = pickle.load(f)
    
    # Load feature names
    with open(artifacts_path / "feature_names.pkl", "rb") as f:
        feature_names = pickle.load(f)
    
    print(f"[✓] Loaded artifacts from {artifacts_path}")
    print(f"    Classes: {label_encoder.classes_.tolist()}")
    print(f"    Features: {len(feature_names)}")


@app.on_event("startup")
async def startup():
    """Load model on startup."""
    model_path = Path(os.getenv("MODEL_PATH", "models/sentinel.onnx"))
    artifacts_path = Path(os.getenv("ARTIFACTS_PATH", "data/artifacts"))
    
    if model_path.exists() and artifacts_path.exists():
        load_artifacts(model_path, artifacts_path)
    else:
        print(f"[!] Model or artifacts not found. Endpoints will fail.")
        print(f"    MODEL_PATH={model_path} (exists={model_path.exists()})")
        print(f"    ARTIFACTS_PATH={artifacts_path} (exists={artifacts_path.exists()})")


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
        PREDICTIONS_TOTAL.labels(class_=prediction).inc()
        PREDICTION_LATENCY.observe(time.time() - start)
    
    return PredictionResponse(
        prediction=prediction,
        confidence=confidence,
        class_id=class_id,
        probabilities={
            label_encoder.inverse_transform([i])[0]: float(p)
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
            prediction=label_encoder.inverse_transform([class_id])[0],
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
