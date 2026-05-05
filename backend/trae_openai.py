"""Trae → OpenAI-compatible API adapter.

Reverse-engineered from the Trae Android client (com.bytedance.trae.cn).
Exposes ``/v1/chat/completions`` and ``/v1/models`` so any OpenAI SDK
client can talk to the Trae backend transparently.

Environment variables
---------------------
TRAE_BASE_URL      Base URL of the Trae API gateway
                   (default ``https://trae-api-cn.mchost.guru``)
TRAE_TOKEN         Long-lived ``x-ide-token`` JWT obtained from the
                   Trae mobile / desktop client.
TRAE_APP_ID        X-App-Id header value
                   (default ``6eefa01c-1036-4c7e-9ca5-d891f63bfcd8``)
TRAE_AGENT_TYPE    Default agent type
                   (default ``solo_work_remote``)
TRAE_TIMEOUT       HTTP timeout in seconds (default ``120``)
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx
from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

logger = logging.getLogger("trae-openai")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TRAE_BASE_URL = os.environ.get(
    "TRAE_BASE_URL", "https://trae-api-cn.mchost.guru"
).rstrip("/")
TRAE_TOKEN = os.environ.get("TRAE_TOKEN", "")
TRAE_APP_ID = os.environ.get(
    "TRAE_APP_ID", "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
)
TRAE_AGENT_TYPE = os.environ.get("TRAE_AGENT_TYPE", "solo_work_remote")
TRAE_TIMEOUT = float(os.environ.get("TRAE_TIMEOUT", "120"))

# Endpoint templates (reverse-engineered from captured traffic)
_EP_TASK_CREATE = "/api/solo_hub/v1/conversations/tasks/create"
_EP_EVENTS = "/api/solo_hub/v1/chat_sessions/{task_id}/events"
_EP_SEND_MSG = (
    "/api/solo_hub/v1/conversations/{conversation_id}/messages"
)

# Default query-string parameters that the Android client appends.
_DEFAULT_QS: Dict[str, str] = {
    "device_platform": "android",
    "os": "android",
    "aid": "943841",
    "app_name": "trae",
    "version_code": "2",
    "version_name": "0.0.2",
    "channel": "local_test",
}

# Model name → Trae model_name mapping.  The Trae backend accepts an
# empty string (auto) or specific model identifiers.
_MODEL_MAP: Dict[str, str] = {
    "trae": "",
    "trae-auto": "",
    "deepseek": "deepseek",
    "doubao": "doubao",
    "claude-3.5-sonnet": "claude-3-5-sonnet",
    "gpt-4o": "gpt-4o",
}

# ---------------------------------------------------------------------------
# Pydantic schemas (OpenAI-compatible)
# ---------------------------------------------------------------------------


class ChatMessage(BaseModel):
    role: str
    content: str
    name: Optional[str] = None


class ChatRequest(BaseModel):
    model: str = Field(default="trae-auto")
    messages: List[ChatMessage]
    temperature: Optional[float] = Field(default=None)
    max_tokens: Optional[int] = Field(default=None)
    stream: Optional[bool] = Field(default=False)
    # Extra – pass an existing Trae conversation_id to continue a chat.
    conversation_id: Optional[str] = Field(default=None)


class _Choice(BaseModel):
    index: int = 0
    message: ChatMessage
    finish_reason: Optional[str] = "stop"


class _DeltaChoice(BaseModel):
    index: int = 0
    delta: Dict[str, str]
    finish_reason: Optional[str] = None


class _Usage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[_Choice]
    usage: _Usage


class ModelEntry(BaseModel):
    id: str
    object: str = "model"
    created: int = 0
    owned_by: str = "trae"


class ModelsResponse(BaseModel):
    object: str = "list"
    data: List[ModelEntry]


# ---------------------------------------------------------------------------
# Trae HTTP helpers
# ---------------------------------------------------------------------------


def _build_headers(token: str) -> Dict[str, str]:
    """Construct the header dict expected by the Trae gateway."""
    return {
        "Content-Type": "application/json; charset=UTF-8",
        "x-ide-token": token,
        "X-App-Id": TRAE_APP_ID,
        "X-App-Version-Code": "20260310",
        "x-ttnet-req-biz-id": "send_message",
        "User-Agent": (
            "com.bytedance.trae.cn/2 "
            "(Linux; U; Android 16; zh_CN_#Hans; "
            "Build/UKQ1.231108.001; Cronet/TTNetVersion:32cd75b8)"
        ),
        "Accept-Encoding": "gzip, deflate",
    }


def _build_query_content(text: str) -> str:
    """Encode user text into the ``query`` JSON array the Trae API expects."""
    return json.dumps(
        [{"data": {"content": text}, "type": "text"}],
        ensure_ascii=False,
    )


def _resolve_token(authorization: Optional[str]) -> str:
    """Return a usable Trae token from the request or the env default."""
    if authorization:
        # Accept ``Bearer <token>`` – the token here is the Trae JWT.
        if authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        return authorization.strip()
    if TRAE_TOKEN:
        return TRAE_TOKEN
    raise HTTPException(
        status_code=401,
        detail=(
            "Missing Trae token.  Pass it via the Authorization header "
            "(Bearer <x-ide-token>) or set the TRAE_TOKEN env var."
        ),
    )


def _resolve_model(model: str) -> str:
    """Map an OpenAI-style model name to a Trae model_name string."""
    return _MODEL_MAP.get(model, model)


# ---------------------------------------------------------------------------
# Core Trae interaction
# ---------------------------------------------------------------------------


async def _create_task(
    client: httpx.AsyncClient,
    token: str,
    conversation_id: Optional[str],
    user_text: str,
    model_name: str,
) -> Dict[str, Any]:
    """POST …/conversations/tasks/create – start a new Trae task.

    Returns the JSON body on success or raises HTTPException.
    """
    cid = conversation_id or uuid.uuid4().hex
    body = {
        "auto_create_project": False,
        "cli_type": "remote",
        "conversation_id": cid,
        "mode": "work",
        "origin": "mobile",
        "initial_message": {
            "agent_type": TRAE_AGENT_TYPE,
            "content": [],
            "model_selection_strategy": "auto" if not model_name else "manual",
            "model_name": model_name,
            "query": _build_query_content(user_text),
        },
    }
    url = f"{TRAE_BASE_URL}{_EP_TASK_CREATE}"
    headers = _build_headers(token)
    resp = await client.post(
        url, json=body, headers=headers, params=_DEFAULT_QS,
    )
    if resp.status_code != 200:
        logger.error("Trae tasks/create %s: %s", resp.status_code, resp.text)
        raise HTTPException(
            status_code=502,
            detail=f"Trae API returned {resp.status_code}: {resp.text[:500]}",
        )
    data = resp.json()
    if data.get("code") != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Trae API error: {data.get('message', 'unknown')}",
        )
    return data["data"]


async def _stream_events(
    client: httpx.AsyncClient,
    token: str,
    task_id: str,
) -> AsyncIterator[str]:
    """Connect to the Trae SSE endpoint and yield raw text chunks.

    The Trae gateway pushes ``text/event-stream`` lines.  We look for
    ``data:`` frames whose JSON payload contains assistant text fragments.
    """
    url = f"{TRAE_BASE_URL}{_EP_EVENTS.format(task_id=task_id)}"
    headers = _build_headers(token)
    headers["Accept"] = "text/event-stream"

    async with client.stream(
        "GET", url, headers=headers, params=_DEFAULT_QS, timeout=TRAE_TIMEOUT
    ) as resp:
        if resp.status_code != 200:
            body = await resp.aread()
            logger.error("SSE connect %s: %s", resp.status_code, body[:300])
            return
        async for line in resp.aiter_lines():
            if not line.startswith("data:"):
                continue
            raw = line[5:].strip()
            if not raw or raw == "[DONE]":
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue
            # Several observed payload shapes:
            #   {"type":"answer","content":"…"}
            #   {"event":"message","data":{"content":"…"}}
            #   {"content":"…","type":"text"}
            text_chunk = (
                payload.get("content")
                or (payload.get("data") or {}).get("content")
                or ""
            )
            if text_chunk:
                yield text_chunk


async def _collect_full_response(
    client: httpx.AsyncClient,
    token: str,
    task_id: str,
) -> str:
    """Consume the SSE stream and return the full assistant text."""
    parts: List[str] = []
    async for chunk in _stream_events(client, token, task_id):
        parts.append(chunk)
    return "".join(parts)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(tags=["Trae OpenAI-compatible"])


@router.get("/v1/models")
async def list_models() -> ModelsResponse:
    """Return the list of models that can be requested."""
    entries = [
        ModelEntry(id=name, created=0, owned_by="trae")
        for name in _MODEL_MAP
    ]
    return ModelsResponse(data=entries)


@router.post("/v1/chat/completions")
async def chat_completions(
    body: ChatRequest,
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Any:
    """OpenAI-compatible ``/v1/chat/completions`` endpoint.

    * Non-streaming: returns a full ``ChatResponse``.
    * Streaming: returns an SSE ``text/event-stream`` response whose
      ``data:`` lines match the OpenAI streaming format.
    """
    token = _resolve_token(authorization)
    model_name = _resolve_model(body.model)

    # Build a single prompt from the message list.
    # Trae accepts one query string; we concatenate system + user messages.
    prompt_parts: List[str] = []
    for msg in body.messages:
        if msg.role == "system":
            prompt_parts.append(f"[System] {msg.content}")
        elif msg.role == "user":
            prompt_parts.append(msg.content)
        elif msg.role == "assistant":
            prompt_parts.append(f"[Assistant] {msg.content}")
    user_text = "\n\n".join(prompt_parts) if prompt_parts else ""

    if not user_text:
        raise HTTPException(status_code=400, detail="No message content")

    async with httpx.AsyncClient(timeout=TRAE_TIMEOUT) as client:
        # 1. Create a task (and implicitly a conversation if needed).
        task_data = await _create_task(
            client, token, body.conversation_id, user_text, model_name,
        )
        task_id = task_data.get("task_id", "")
        conversation_id = (
            task_data.get("conversation", {}).get("id")
            or body.conversation_id
            or ""
        )
        message_id = task_data.get("message_id", uuid.uuid4().hex)

        if body.stream:
            return _sse_response(
                client, token, task_id, body.model, message_id,
            )

        # 2. Non-streaming – consume the full SSE stream.
        full_text = await _collect_full_response(client, token, task_id)
        if not full_text:
            full_text = (
                f"Task accepted (id={task_id}).  "
                "The Trae backend is processing; streaming is "
                "recommended for real-time output."
            )

        return ChatResponse(
            id=f"chatcmpl-{message_id}",
            created=int(time.time()),
            model=body.model,
            choices=[
                _Choice(
                    message=ChatMessage(role="assistant", content=full_text),
                    finish_reason="stop",
                )
            ],
            usage=_Usage(
                prompt_tokens=len(user_text),
                completion_tokens=len(full_text),
                total_tokens=len(user_text) + len(full_text),
            ),
        )


def _sse_response(
    client: httpx.AsyncClient,
    token: str,
    task_id: str,
    model: str,
    message_id: str,
) -> StreamingResponse:
    """Wrap the Trae SSE stream as an OpenAI-format SSE response."""

    async def _generate() -> AsyncIterator[str]:
        async for chunk in _stream_events(client, token, task_id):
            data = {
                "id": f"chatcmpl-{message_id}",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [
                    {"index": 0, "delta": {"content": chunk}, "finish_reason": None}
                ],
            }
            yield f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
        # Final [DONE] sentinel
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post(
    "/v1/conversations/{conversation_id}/messages",
    summary="Send a follow-up message to an existing Trae conversation",
)
async def send_message(
    conversation_id: str,
    body: ChatRequest,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Low-level proxy: forward a message to an existing Trae conversation."""
    token = _resolve_token(authorization)
    model_name = _resolve_model(body.model)
    user_text = ""
    for msg in reversed(body.messages):
        if msg.role == "user":
            user_text = msg.content
            break
    if not user_text:
        raise HTTPException(status_code=400, detail="No user message")

    async with httpx.AsyncClient(timeout=TRAE_TIMEOUT) as client:
        task_data = await _create_task(
            client, token, conversation_id, user_text, model_name,
        )
    return {
        "conversation_id": conversation_id,
        "task_id": task_data.get("task_id"),
        "message_id": task_data.get("message_id"),
        "accepted": task_data.get("accepted", True),
    }


@router.get("/v1/trae/health")
async def trae_health() -> Dict[str, Any]:
    """Quick connectivity check against the Trae gateway."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{TRAE_BASE_URL}/",
                headers={"User-Agent": "trae-openai-health/1"},
            )
        reachable = resp.status_code < 500
    except Exception:
        reachable = False
    return {
        "trae_base_url": TRAE_BASE_URL,
        "reachable": reachable,
        "token_configured": bool(TRAE_TOKEN),
    }
