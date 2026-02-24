# -----------------------------------------------------------------------
# Cybereason EDR MCP Server – Dockerfile
# -----------------------------------------------------------------------
FROM python:3.12-slim AS base

# 非rootユーザーで実行
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

WORKDIR /app

# 依存関係を先にインストール（キャッシュ効率化）
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# アプリケーションコードをコピー
COPY server.py cybereason_client.py ./

# 非rootユーザーに切り替え
USER appuser

# stdio トランスポートを使用するため EXPOSE は不要
# MCP ホスト（Claude Desktop / claude CLI）が stdin/stdout で接続する

ENTRYPOINT ["python", "server.py"]
