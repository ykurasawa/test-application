# Cybereason EDR MCP Server

Cybereason EDRのアラート（Malop）をClaudeで分析するためのMCPサーバーです。

## 提供ツール

| ツール名 | 説明 |
|---|---|
| `get_alerts` | 未対応アラート（Malop）の一覧取得 |
| `get_malop_details` | 特定Malopの詳細情報取得 |
| `get_affected_machines` | Malopに関連する影響マシン一覧 |
| `update_alert_status` | Malopのステータス更新 |

## セットアップ

### 1. 環境変数の設定

```bash
cp .env.example .env
# .env を編集して認証情報を入力
```

```env
CYBEREASON_URL=https://jpn-sales-demo2.cybereason.net
CYBEREASON_USERNAME=your-username@example.com
CYBEREASON_PASSWORD=your-password
CYBEREASON_VERIFY_SSL=true
```

### 2. Dockerイメージのビルド

```bash
docker compose build
```

### 3. Claude Desktop / claude CLI への登録

#### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "cybereason": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--env-file", "/absolute/path/to/cybereason-mcp/.env",
        "cybereason-mcp:latest"
      ]
    }
  }
}
```

#### claude CLI (`.mcp.json` / `mcp add`)

```bash
claude mcp add cybereason \
  docker run --rm -i --env-file /absolute/path/to/.env cybereason-mcp:latest
```

## ローカル開発（Docker なし）

```bash
pip install -r requirements.txt
cp .env.example .env   # 認証情報を設定
python server.py
```

## アーキテクチャ

```
Claude (MCP Host)
    │  stdin / stdout
    ▼
server.py          ← MCPサーバー（ツール定義・ルーティング）
    │  HTTP セッション
    ▼
cybereason_client.py  ← REST APIクライアント（セッション認証・自動再ログイン）
    │  HTTPS
    ▼
Cybereason テナント
```

### 認証フロー

1. 初回ツール呼び出し時に `/rest/login` へ POST してセッションCookieを取得
2. 以降のリクエストはCookieを自動付与
3. 401 レスポンスを受けた場合は自動で再ログインしてリトライ

## ステータス値

| 値 | 意味 |
|---|---|
| `TODO` | 未対応（デフォルト） |
| `OPEN` | 対応中 |
| `UNREAD` | 未読 |
| `CLOSED` | クローズ済み |
| `FP` | 誤検知（False Positive） |
