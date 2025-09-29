FROM python:3.11-slim

# system deps (kept minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# install python deps
RUN pip install --no-cache-dir flask

# keep container editable via mounted volume; default command runs attacker.py
# when you develop, put attacker.py into ./attacker on host (mounted to /app)
CMD ["python", "/app/attacker_v2.py"]
