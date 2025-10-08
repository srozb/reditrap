FROM python:3.12-alpine

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

RUN addgroup -S honeypot \
    && adduser -S -G honeypot honeypot

COPY reditrap.py /app/

RUN mkdir -p /data \
    && chown -R honeypot:honeypot /data

USER honeypot

EXPOSE 6379

ENTRYPOINT ["python3", "/app/reditrap.py"]
CMD ["--host", "0.0.0.0", "--port", "6379", "--log-file", "/data/redis-honeypot-events.ndjson"]
