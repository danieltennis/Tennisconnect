FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps (bcrypt heeft soms libffi nodig)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Persistente DB-folder
RUN mkdir -p /app/db
VOLUME ["/app/db"]

ENV PORT=5000
EXPOSE 5000

# Init de DB bij eerste start, daarna gunicorn met 2 workers
CMD ["sh","-c","python -c 'from app import init_db; init_db()' && gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 --threads 4 --timeout 60 app:app"]
