"""
MiMo Chatbot Web Server

A lightweight FastAPI server that:
1. Serves the chatbot frontend (static files)
2. Proxies chat requests to a mimo_relay (OpenAI-compatible) backend
3. Stores conversation history in a local JSON file

Usage:
    python -m chatbot.server --relay-url http://localhost:8800 --port 9000
"""

import argparse
import json
import os
import time
import uuid
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles

RELAY_URL = os.environ.get("MIMO_RELAY_URL", "http://localhost:8800")
DATA_DIR = Path(__file__).parent / "data"
CONVERSATIONS_FILE = DATA_DIR / "conversations.json"

app = FastAPI(title="MiMo Chatbot")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── conversation persistence ────────────────────────────────────


def _load_conversations() -> dict:
    if CONVERSATIONS_FILE.exists():
        return json.loads(CONVERSATIONS_FILE.read_text(encoding="utf-8"))
    return {}


def _save_conversations(data: dict):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CONVERSATIONS_FILE.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )


# ── API routes ──────────────────────────────────────────────────


@app.get("/api/conversations")
async def list_conversations():
    convos = _load_conversations()
    result = []
    for cid, cdata in convos.items():
        result.append(
            {
                "id": cid,
                "title": cdata.get("title", "New Conversation"),
                "created_at": cdata.get("created_at", 0),
                "updated_at": cdata.get("updated_at", 0),
                "message_count": len(cdata.get("messages", [])),
            }
        )
    result.sort(key=lambda x: x["updated_at"], reverse=True)
    return result


@app.post("/api/conversations")
async def create_conversation(request: Request):
    body = await request.json()
    cid = str(uuid.uuid4())[:8]
    now = time.time()
    convos = _load_conversations()
    convos[cid] = {
        "title": body.get("title", "New Conversation"),
        "created_at": now,
        "updated_at": now,
        "messages": [],
        "model": body.get("model", "mimo-v2.5-pro"),
    }
    _save_conversations(convos)
    return {"id": cid, **convos[cid]}


@app.get("/api/conversations/{conversation_id}")
async def get_conversation(conversation_id: str):
    convos = _load_conversations()
    if conversation_id not in convos:
        raise HTTPException(404, "Conversation not found")
    return {"id": conversation_id, **convos[conversation_id]}


@app.delete("/api/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str):
    convos = _load_conversations()
    if conversation_id not in convos:
        raise HTTPException(404, "Conversation not found")
    del convos[conversation_id]
    _save_conversations(convos)
    return {"ok": True}


@app.post("/api/chat")
async def chat(request: Request):
    body = await request.json()
    conversation_id = body.get("conversation_id")
    user_message = body.get("message", "")
    model = body.get("model", "mimo-v2.5-pro")
    enable_thinking = body.get("enable_thinking", False)

    if not user_message.strip():
        raise HTTPException(400, "Empty message")

    convos = _load_conversations()

    # auto-create conversation if needed
    if not conversation_id or conversation_id not in convos:
        conversation_id = str(uuid.uuid4())[:8]
        now = time.time()
        convos[conversation_id] = {
            "title": user_message[:30],
            "created_at": now,
            "updated_at": now,
            "messages": [],
            "model": model,
        }

    conv = convos[conversation_id]

    # append user message
    conv["messages"].append(
        {"role": "user", "content": user_message, "timestamp": time.time()}
    )
    conv["updated_at"] = time.time()

    # auto-title from first message
    if len(conv["messages"]) == 1:
        conv["title"] = user_message[:30]

    _save_conversations(convos)

    # build OpenAI messages payload
    openai_messages = [
        {"role": m["role"], "content": m["content"]} for m in conv["messages"]
    ]

    # call mimo_relay
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{RELAY_URL}/v1/chat/completions",
                json={
                    "model": model,
                    "messages": openai_messages,
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(502, f"Relay error: {e.response.status_code}")
    except httpx.RequestError as e:
        raise HTTPException(502, f"Cannot reach relay: {e}")

    assistant_content = data["choices"][0]["message"]["content"]

    # save assistant reply
    convos = _load_conversations()
    conv = convos[conversation_id]
    conv["messages"].append(
        {"role": "assistant", "content": assistant_content, "timestamp": time.time()}
    )
    conv["updated_at"] = time.time()
    _save_conversations(convos)

    return {
        "conversation_id": conversation_id,
        "message": {
            "role": "assistant",
            "content": assistant_content,
        },
        "model": model,
    }


@app.get("/api/models")
async def list_models():
    """Proxy model list from relay, fallback to defaults."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{RELAY_URL}/v1/models")
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {
        "data": [
            {"id": "mimo-v2.5-pro", "name": "MiMo-v2.5-Pro"},
            {"id": "mimo-v2-flash", "name": "MiMo-v2-Flash"},
            {"id": "mimo-v2-pro", "name": "MiMo-v2-Pro"},
        ]
    }


@app.get("/api/health")
async def health():
    relay_ok = False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{RELAY_URL}/health")
            relay_ok = resp.status_code == 200
    except Exception:
        pass
    return {"status": "ok", "relay_connected": relay_ok, "relay_url": RELAY_URL}


# ── static files ────────────────────────────────────────────────

STATIC_DIR = Path(__file__).parent / "static"


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ── entry point ─────────────────────────────────────────────────


def main():
    global RELAY_URL
    import uvicorn

    parser = argparse.ArgumentParser(description="MiMo Chatbot Server")
    parser.add_argument("--port", "-p", type=int, default=9000)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument(
        "--relay-url",
        default=RELAY_URL,
        help="mimo_relay proxy URL (default: http://localhost:8800)",
    )
    args = parser.parse_args()

    RELAY_URL = args.relay_url

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
