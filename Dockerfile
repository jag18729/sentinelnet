FROM python:3.12-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir     fastapi==0.128.8     uvicorn==0.40.0     onnxruntime==1.24.1     numpy==2.4.2     scikit-learn==1.8.0     pydantic==2.12.5     prometheus_client==0.21.1

# Copy application
COPY inference/ ./inference/
COPY models/ ./models/

ENV MODEL_PATH=/app/models/sentinel.onnx
ENV PYTHONPATH=/app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3     CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "inference.serve:app", "--host", "0.0.0.0", "--port", "8000"]
