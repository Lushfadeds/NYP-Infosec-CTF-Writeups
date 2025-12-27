FROM python:3.13-alpine AS build

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.13-alpine AS runtime

WORKDIR /app

ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

USER appuser

COPY --from=build /opt/venv /opt/venv
COPY . .
ENV PATH="/opt/venv/bin:$PATH"

EXPOSE 6767

CMD ["gunicorn", "--bind", "0.0.0.0:6767", "-k", "gevent", "app:app"]
