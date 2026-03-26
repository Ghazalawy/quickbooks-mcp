FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY quickbooks_mcp_server_prod.py .

RUN mkdir -p /app/data /app/logs

EXPOSE 8765

CMD ["python", "quickbooks_mcp_server_prod.py", "--proxy-headers"]
