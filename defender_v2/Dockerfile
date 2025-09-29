FROM python:3.11-slim

# Install small build deps (kept minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install required python packages
RUN pip install --no-cache-dir flask scikit-learn pandas numpy

CMD ["python", "/app/defender_v2.py"]
