"""Tests for the FastAPI inference server."""

import pytest
import numpy as np
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from sklearn.preprocessing import LabelEncoder, StandardScaler

from inference.serve import app, PredictionRequest, PredictionResponse


@pytest.fixture
def mock_artifacts():
    """Set up mock model and artifacts for testing."""
    import inference.serve as serve_module

    # Mock ONNX session
    mock_session = MagicMock()
    logits = np.array([[0.1, 0.8, 0.1]], dtype=np.float32)
    mock_session.run.return_value = [logits]
    mock_session.get_inputs.return_value = [MagicMock(name="features")]

    # Real scaler
    scaler = StandardScaler()
    scaler.fit(np.random.randn(50, 78))

    # Real label encoder
    le = LabelEncoder()
    le.fit(["BENIGN", "DoS", "Probe"])

    # Inject into module globals
    serve_module.model = mock_session
    serve_module.scaler = scaler
    serve_module.label_encoder = le
    serve_module.feature_names = [f"feat_{i}" for i in range(78)]

    yield

    # Cleanup
    serve_module.model = None
    serve_module.scaler = None
    serve_module.label_encoder = None
    serve_module.feature_names = None


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


class TestHealthEndpoint:

    def test_health_no_model(self, client):
        import inference.serve as serve_module
        serve_module.model = None
        serve_module.label_encoder = None
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["model_loaded"] is False

    def test_health_with_model(self, client, mock_artifacts):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["model_loaded"] is True
        assert len(data["classes"]) == 3


class TestPredictEndpoint:

    def test_predict_returns_200(self, client, mock_artifacts):
        features = np.random.randn(78).tolist()
        resp = client.post("/predict", json={"features": features})
        assert resp.status_code == 200

    def test_predict_response_fields(self, client, mock_artifacts):
        features = np.random.randn(78).tolist()
        resp = client.post("/predict", json={"features": features})
        data = resp.json()
        assert "prediction" in data
        assert "confidence" in data
        assert "class_id" in data
        assert "probabilities" in data

    def test_predict_confidence_range(self, client, mock_artifacts):
        features = np.random.randn(78).tolist()
        resp = client.post("/predict", json={"features": features})
        data = resp.json()
        assert 0 <= data["confidence"] <= 1

    def test_predict_no_model_returns_503(self, client):
        import inference.serve as serve_module
        serve_module.model = None
        features = np.random.randn(78).tolist()
        resp = client.post("/predict", json={"features": features})
        assert resp.status_code == 503


class TestBatchPredictEndpoint:

    def test_batch_predict(self, client, mock_artifacts):
        import inference.serve as serve_module
        # Override mock to return batch results
        logits = np.array([[0.1, 0.8, 0.1], [0.7, 0.2, 0.1]], dtype=np.float32)
        serve_module.model.run.return_value = [logits]

        samples = np.random.randn(2, 78).tolist()
        resp = client.post("/predict/batch", json={"samples": samples})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["predictions"]) == 2
        assert "latency_ms" in data

    def test_batch_no_model_returns_503(self, client):
        import inference.serve as serve_module
        serve_module.model = None
        samples = np.random.randn(2, 78).tolist()
        resp = client.post("/predict/batch", json={"samples": samples})
        assert resp.status_code == 503


class TestPydanticModels:

    def test_prediction_request(self):
        req = PredictionRequest(features=[0.1] * 78)
        assert len(req.features) == 78

    def test_prediction_response(self):
        resp = PredictionResponse(
            prediction="BENIGN",
            confidence=0.95,
            class_id=0,
        )
        assert resp.prediction == "BENIGN"
        assert resp.probabilities is None
