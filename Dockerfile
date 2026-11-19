FROM python:3.13-slim-trixie
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY lab.py native_kem.py ./
ENTRYPOINT ["python", "/app/lab.py"]
