# ShareDesk: web UI for Samba shares, NFS exports and folder permissions on a Linux file server.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SHAREDESK_DATA_DIR=/data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sharedesk ./sharedesk
RUN useradd --uid 1000 --create-home sharedesk \
 && mkdir -p /data /config \
 && chown sharedesk:sharedesk /data

USER sharedesk
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["uvicorn", "sharedesk.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
