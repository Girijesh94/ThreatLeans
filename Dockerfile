FROM node:22-bookworm-slim AS frontend
WORKDIR /ui
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 THREATLEANS_HOST=0.0.0.0 THREATLEANS_DATA_DIR=/app/data
WORKDIR /app
COPY backend/ ./backend/
RUN pip install --no-cache-dir './backend[dense,postgres]' && useradd --uid 10001 --create-home threatleans
COPY --from=frontend /ui/dist ./frontend/dist
RUN mkdir -p data/runtime data/raw data/index data/models && chown -R threatleans:threatleans /app
USER threatleans
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"
CMD ["threatleans", "serve"]
