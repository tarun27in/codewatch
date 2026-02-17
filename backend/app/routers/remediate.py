"""AI-powered security remediation endpoint."""

import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import httpx

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["remediate"])

SYSTEM_PROMPT = """You are a senior security engineer performing a code review. Analyze the security finding below and provide:

1. **Impact Assessment** — What is the real-world risk? What can an attacker do?
2. **Specific Code Fix** — Show the exact code change needed (before/after). Use markdown code blocks.
3. **Step-by-Step Remediation** — Numbered list of actions to fix this.
4. **Prevention** — How to prevent this class of issue in the future (tooling, processes, etc.).

Be specific and actionable. Reference the file path and line number. Use markdown formatting."""


class RemediateRequest(BaseModel):
    provider: str  # "anthropic", "openai", "google"
    api_key: str
    model: str
    node: dict[str, Any]
    source_context: Optional[str] = None


class RemediateResponse(BaseModel):
    remediation: str


def _build_user_prompt(node: dict[str, Any], source_context: Optional[str]) -> str:
    parts = [
        f"**Finding**: {node.get('label', 'Unknown')}",
        f"**Type**: {node.get('node_type', 'unknown')}",
        f"**Severity**: {node.get('severity', 'unknown')}",
    ]
    if node.get("description"):
        parts.append(f"**Description**: {node['description']}")
    if node.get("file_path"):
        loc = node["file_path"]
        if node.get("line_number"):
            loc += f":{node['line_number']}"
        parts.append(f"**Location**: `{loc}`")

    metadata = node.get("metadata", {})
    if metadata:
        meta_str = ", ".join(f"{k}={v}" for k, v in metadata.items() if k != "source")
        if meta_str:
            parts.append(f"**Metadata**: {meta_str}")

    if source_context:
        parts.append(f"\n**Source Code Context**:\n```\n{source_context}\n```")

    return "\n".join(parts)


async def _call_anthropic(api_key: str, model: str, user_prompt: str) -> str:
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 2048,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_prompt}],
            },
        )
        if resp.status_code != 200:
            detail = resp.json().get("error", {}).get("message", resp.text)
            raise HTTPException(status_code=resp.status_code, detail=f"Anthropic API error: {detail}")
        data = resp.json()
        return data["content"][0]["text"]


async def _call_openai(api_key: str, model: str, user_prompt: str) -> str:
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 2048,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            },
        )
        if resp.status_code != 200:
            detail = resp.json().get("error", {}).get("message", resp.text)
            raise HTTPException(status_code=resp.status_code, detail=f"OpenAI API error: {detail}")
        data = resp.json()
        return data["choices"][0]["message"]["content"]


async def _call_google(api_key: str, model: str, user_prompt: str) -> str:
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            params={"key": api_key},
            headers={"Content-Type": "application/json"},
            json={
                "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                "contents": [{"parts": [{"text": user_prompt}]}],
                "generationConfig": {"maxOutputTokens": 2048},
            },
        )
        if resp.status_code != 200:
            detail = resp.json().get("error", {}).get("message", resp.text)
            raise HTTPException(status_code=resp.status_code, detail=f"Google API error: {detail}")
        data = resp.json()
        candidates = data.get("candidates", [])
        if not candidates:
            raise HTTPException(status_code=500, detail="No response from Google API")
        return candidates[0]["content"]["parts"][0]["text"]


@router.post("/remediate", response_model=RemediateResponse)
async def ai_remediate(req: RemediateRequest):
    """Get AI-powered remediation advice for a security finding."""
    user_prompt = _build_user_prompt(req.node, req.source_context)

    try:
        if req.provider == "anthropic":
            text = await _call_anthropic(req.api_key, req.model, user_prompt)
        elif req.provider == "openai":
            text = await _call_openai(req.api_key, req.model, user_prompt)
        elif req.provider == "google":
            text = await _call_google(req.api_key, req.model, user_prompt)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown provider: {req.provider}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI remediation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    return RemediateResponse(remediation=text)
