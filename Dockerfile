# 1. ベースイメージの指定 (軽量なPythonイメージ)
FROM python:3.9-slim

# 2. コンテナ内の作業ディレクトリを作成
WORKDIR /app

# 3. ローカルのファイルをコンテナにコピー
# (現在は空でも、将来コードを入れた時に役立ちます)
COPY . .

# 4. セキュリティスキャンのテスト用に、あえて古いパッケージを入れる例
# (スキャン結果に反応が出るようにするためのサンプルです)
RUN apt-get update && apt-get install -y curl

# 5. 実行コマンド
CMD ["python", "-c", "print('Hello, Sysdig Scan!')"]
