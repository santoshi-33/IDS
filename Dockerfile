# Streamlit IDS app — Render / any container host
FROM python:3.12-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY ids ./ids
COPY scripts ./scripts
COPY README.md .

# Render sets PORT; default for local docker run
ENV PORT=8501
EXPOSE 8501

CMD streamlit run app/streamlit_app.py \
    --server.port=${PORT} \
    --server.address=0.0.0.0 \
    --server.headless=true \
    --browser.gatherUsageStats=false
