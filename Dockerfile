FROM python:3-slim AS builder
ADD . /app
WORKDIR /app
RUN python -m pip install --upgrade pip && \
	pip install --target=/app -r requirements.txt

FROM gcr.io/distroless/python3-debian10
COPY --from=builder /app /app
WORKDIR /app
ENV LANG=C.UTF-8
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH /app
ENTRYPOINT ["python", "/app/main.py"]
