FROM python:3.13.2-slim-bookworm

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y \
    chromium chromium-driver \
    fonts-liberation \
    libatk-bridge2.0-0 \
    libgbm1 \
    libgtk-3-0 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxcb1 \
    libxrandr2 \
    libasound2 \
    libpangocairo-1.0-0 \
    libnss3 \
    libpango-1.0-0 \
    libatk1.0-0 \
    libcups2 \
    libjpeg62-turbo \
    libxss1 \
    libxtst6 \
    && rm -rf /var/lib/apt/lists/*

ENV CHROMIUM_PATH=/usr/bin/chromium
ENV CHROMEDRIVER_PATH=/usr/bin/chromedriver

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN groupadd -g 1001 appuser && \
    useradd -u 1001 -g appuser -m -d /usr/src/app -s /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /usr/src/app

USER appuser

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--threads=4", "-k", "gevent", "app:app"]
