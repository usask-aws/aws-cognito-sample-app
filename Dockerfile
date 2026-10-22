FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE 8080

# 1 worker (single instance, in-memory guardrails), threads for stream concurrency.
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", \
     "--timeout", "120", "app.wsgi:app"]
