# ──────────────────────────────────────────────────────────────
#  Flashback Encryptor Oracle  –  Dockerfile
#  • Python 3.11 slim
#  • Installs requirements.txt
#  • Copies oracle script + ABI
#  • Entrypoint runs encryptor_oracle.py
# ──────────────────────────────────────────────────────────────
FROM python:3.11-slim

# 1. System deps (certs & curl only)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# 2. Python deps
WORKDIR /app
COPY oracle/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# 3. Oracle code + ABI
COPY oracle/src/EncryptorOracle.py .
COPY oracle/src/RoflUtility.py .
COPY oracle/src/ContractUtility.py .
COPY oracle/src/Encryptor.json .

# 4. Environment defaults (override at runtime)
ENV PYTHONUNBUFFERED=1 \
    SAPPHIRE_RPC=https://testnet.sapphire.oasis.io \
    CHAIN_ID=23295 \
    GAS_PRICE_GWEI=0.5

# 5. Entrypoint
ENTRYPOINT ["python", "/app/EncryptorOracle.py"]
