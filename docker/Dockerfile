FROM python:3.11-slim

# 1. System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# 2. Python deps
WORKDIR /app
COPY docker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3. Code + ABI
COPY docker/oracle_runner.py .
COPY abi/contract_abi.json  ./abi/

# 4. Environment defaults
ENV SAPPHIRE_TESTNET_RPC_URL=https://testnet.sapphire.oasis.io \
    ABI_PATH=/app/abi/contract_abi.json \
    PYTHONUNBUFFERED=1

# 5. Entrypoint
ENTRYPOINT ["python", "/app/oracle_runner.py"]
