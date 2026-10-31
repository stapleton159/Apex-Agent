# APEX — container image
#
#   docker build -t apex .
#   docker run --rm -p 127.0.0.1:5002:5002 \
#     -e OPENROUTER_API_KEY=sk-or-v1-... \
#     -v "$PWD/workspace:/app/workspace" apex
#
# The key is passed at run time, never baked into the image.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=5002 \
    BIND_HOST=0.0.0.0 \
    APEX_WORKSPACE=/app/workspace

WORKDIR /app

# curl/ca-certificates keep the shell-oriented tools inside the loop useful;
# git is needed by the GitHub-clone capability.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates git \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/workspace

EXPOSE 5002

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

CMD ["python", "scriptai2.py"]
