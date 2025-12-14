FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ./main.py
COPY templates ./templates

ENV BOOTSTRAP_DNS_NAME=hay.honse.farm \
    REFRESH_INTERVAL=300 \
    BIND_HOST=0.0.0.0 \
    BIND_PORT=8080

EXPOSE 8080
CMD ["python", "main.py"]
