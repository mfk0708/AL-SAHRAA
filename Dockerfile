FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
COPY wheels* /wheels/
RUN if [ -d /wheels/linux-x64 ] && [ "$(uname -m)" = "x86_64" ]; then pip install --no-cache-dir --no-index --find-links /wheels/linux-x64 -r requirements.txt; \
    else pip install --no-cache-dir -r requirements.txt; fi && rm -rf /wheels
COPY cat_server ./cat_server
COPY web ./web
COPY sample ./sample
COPY cat.env.example README.md ./
RUN useradd -m cat && mkdir -p /data && chown cat /data
USER cat
ENV CAT_DATA_DIR=/data CAT_HOST=0.0.0.0 CAT_PORT=8000
EXPOSE 8000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health')"
CMD ["python", "-m", "cat_server.run", "--env", "/app/cat.env"]
