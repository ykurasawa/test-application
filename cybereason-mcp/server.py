"""
Cybereason EDR – MCP Server
Exposes Cybereason alert management as MCP tools for Claude.
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any

from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    TextContent,
    Tool,
)

from cybereason_client import CybereasonClient

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("cybereason-mcp")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

load_dotenv()

BASE_URL = os.environ.get("CYBEREASON_URL", "https://jpn-sales-demo2.cybereason.net")
USERNAME = os.environ.get("CYBEREASON_USERNAME", "")
PASSWORD = os.environ.get("CYBEREASON_PASSWORD", "")
VERIFY_SSL = os.environ.get("CYBEREASON_VERIFY_SSL", "true").lower() != "false"

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS: list[Tool] = [
    Tool(
        name="get_alerts",
        description=(
            "Cybereasonから未対応アラート（Malop）の一覧を取得します。"
            " status_filter で絞り込み可能（デフォルトは TODO のみ）。"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "status_filter": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["TODO", "OPEN", "UNREAD", "CLOSED", "FP"],
                    },
                    "description": (
                        "取得するアラートのステータスリスト。"
                        " 省略時は ['TODO'] （未対応のみ）。"
                    ),
                    "default": ["TODO"],
                },
                "limit": {
                    "type": "integer",
                    "description": "取得件数の上限（デフォルト 25、最大 1000）。",
                    "default": 25,
                    "minimum": 1,
                    "maximum": 1000,
                },
            },
        },
    ),
    Tool(
        name="get_malop_details",
        description=(
            "指定した Malop ID の詳細情報（攻撃手法、IOC、タイムライン等）を取得します。"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "malop_id": {
                    "type": "string",
                    "description": (
                        "対象 Malop の GUID。"
                        " 例: '11.2345678901234567890'"
                    ),
                }
            },
            "required": ["malop_id"],
        },
    ),
    Tool(
        name="get_affected_machines",
        description="指定した Malop に関連する影響マシンの一覧を取得します。",
        inputSchema={
            "type": "object",
            "properties": {
                "malop_id": {
                    "type": "string",
                    "description": "対象 Malop の GUID。",
                }
            },
            "required": ["malop_id"],
        },
    ),
    Tool(
        name="update_alert_status",
        description=(
            "Malop のステータスを更新します。"
            " 対応済みクローズや誤検知（FP）マークなどに使用します。"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "malop_id": {
                    "type": "string",
                    "description": "対象 Malop の GUID。",
                },
                "status": {
                    "type": "string",
                    "enum": ["TODO", "OPEN", "UNREAD", "CLOSED", "FP"],
                    "description": (
                        "新しいステータス。"
                        " TODO=未対応, OPEN=対応中, CLOSED=クローズ, FP=誤検知。"
                    ),
                },
                "comment": {
                    "type": "string",
                    "description": "ステータス変更時のコメント（任意）。",
                },
            },
            "required": ["malop_id", "status"],
        },
    ),
]

# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

app = Server("cybereason-mcp")
_client: CybereasonClient | None = None


def get_client() -> CybereasonClient:
    """Return a lazily-initialised, authenticated Cybereason client."""
    global _client
    if _client is None:
        if not USERNAME or not PASSWORD:
            raise RuntimeError(
                "CYBEREASON_USERNAME および CYBEREASON_PASSWORD 環境変数を設定してください。"
            )
        _client = CybereasonClient(
            base_url=BASE_URL,
            username=USERNAME,
            password=PASSWORD,
            verify_ssl=VERIFY_SSL,
        )
        _client.login()
        logger.info("Cybereason クライアント初期化完了: %s", BASE_URL)
    return _client


def _json_text(data: Any) -> TextContent:
    """Serialize data as pretty-printed JSON TextContent."""
    return TextContent(
        type="text",
        text=json.dumps(data, ensure_ascii=False, indent=2),
    )


# ---------------------------------------------------------------------------
# MCP handlers
# ---------------------------------------------------------------------------


@app.list_tools()
async def list_tools(_: ListToolsRequest) -> ListToolsResult:  # type: ignore[name-defined]
    return ListToolsResult(tools=TOOLS)


@app.call_tool()
async def call_tool(request: CallToolRequest) -> CallToolResult:  # type: ignore[name-defined]
    name = request.params.name
    args: dict[str, Any] = request.params.arguments or {}

    logger.info("ツール呼び出し: %s  引数: %s", name, args)

    try:
        client = get_client()

        if name == "get_alerts":
            result = await asyncio.to_thread(
                client.get_alerts,
                status_filter=args.get("status_filter"),
                limit=args.get("limit", 25),
            )

        elif name == "get_malop_details":
            malop_id: str = args["malop_id"]
            result = await asyncio.to_thread(client.get_malop_details, malop_id)

        elif name == "get_affected_machines":
            malop_id = args["malop_id"]
            result = await asyncio.to_thread(client.get_affected_machines, malop_id)

        elif name == "update_alert_status":
            result = await asyncio.to_thread(
                client.update_alert_status,
                malop_id=args["malop_id"],
                status=args["status"],
                comment=args.get("comment"),
            )

        else:
            raise ValueError(f"未知のツール: {name}")

        return CallToolResult(content=[_json_text(result)])

    except Exception as exc:
        logger.exception("ツール '%s' の実行中にエラーが発生しました", name)
        error_payload = {
            "error": type(exc).__name__,
            "message": str(exc),
        }
        return CallToolResult(
            content=[_json_text(error_payload)],
            isError=True,
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    logger.info("Cybereason MCP サーバーを起動します (stdio トランスポート)")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
