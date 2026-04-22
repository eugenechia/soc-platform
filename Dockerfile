FROM python:3.12-slim

# weasyprint runtime libs (Cairo, Pango, GDK-Pixbuf) + font packages
RUN apt-get update && apt-get install -y \
    ca-certificates \
    fonts-liberation \
    fonts-freefont-ttf \
    libcairo2 \
    libfontconfig1 \
    libgdk-pixbuf-2.0-0 \
    libglib2.0-0 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

RUN mkdir -p /app/data/logos /app/data/reports

EXPOSE 5060

# --workers 1 is load-bearing: APScheduler keeps state in-process.
# More workers = duplicate scheduled runs. Do NOT change without switching
# to Container Apps Jobs or an external scheduler.
CMD ["gunicorn", \
     "--workers", "1", \
     "--threads", "4", \
     "--bind", "0.0.0.0:5060", \
     "--timeout", "360", \
     "app:app"]
