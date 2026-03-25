"""
main.py — PII-Safe service: FastAPI middleware + MCP server in one process.

Both interfaces share the same core sanitize() function from sanitizer.py.
The FastMCP server is mounted onto FastAPI as a sub-application, so a single
`uvicorn main:app` starts everything.

Interfaces:
  - MCP tool:        POST /mcp  (for AI agents — explicit tool call)
  - REST endpoint:   POST /sanitize  (direct HTTP access)
  - HTTP middleware:  transparent — opt-in via X-PII-Safe-Context header
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Request
from fastmcp import FastMCP
from pydantic import BaseModel
from typing import Literal

from policy import load_policy
from sanitizer import sanitize, SanitizeResult

# ---------------------------------------------------------------------------
# Load policy once at startup — shared by all interfaces
# ---------------------------------------------------------------------------

POLICY_PATH = Path(__file__).parent / "policy.yaml"
policy_config = load_policy(POLICY_PATH)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class PIISafeRequest(BaseModel):
    content: str
    content_type: Literal["text", "json", "log"] = "text"
    operation: str = "analysis"        # maps to a policy context
    session_id: str = "default"
    policy_id: str | None = None       # reserved for multi-policy support


class AuditEntryOut(BaseModel):
    entity_type: str
    original_span: tuple[int, int]
    action: str
    replacement: str | None
    confidence: float


class PIISafeResponse(BaseModel):
    sanitized_content: str
    risk_score: float
    entities_found: list[AuditEntryOut]
    token_map_ref: str | None
    audit_id: str


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="PII-Safe",
    description="Privacy Guard for Agentic AI & MCP Workflows",
    version="0.1.0-poc",
)


# --- REST endpoint ---

@app.post("/sanitize", response_model=PIISafeResponse)
async def sanitize_endpoint(req: PIISafeRequest) -> PIISafeResponse:
    """Sanitize PII in text according to the policy for the given operation context."""
    result: SanitizeResult = sanitize(
        text=req.content,
        context=req.operation,
        policy=policy_config,
        session_id=req.session_id,
    )
    return PIISafeResponse(
        sanitized_content=result.sanitized_content,
        risk_score=result.risk_score,
        entities_found=[
            AuditEntryOut(
                entity_type=e.entity_type,
                original_span=e.original_span,
                action=e.action,
                replacement=e.replacement,
                confidence=e.confidence,
            )
            for e in result.entities_found
        ],
        token_map_ref=result.token_map_ref,
        audit_id=result.audit_id,
    )


# --- Transparent HTTP middleware ---
# Opt-in: send header  X-PII-Safe-Context: analysis  (or export, storage, etc.)
# Sanitizes all top-level string values in JSON request bodies before they
# reach any downstream handler.

@app.middleware("http")
async def pii_middleware(request: Request, call_next):
    pii_context = request.headers.get("X-PII-Safe-Context")
    if not pii_context:
        # Header absent — pass through unchanged
        return await call_next(request)

    body_bytes = await request.body()
    try:
        body = json.loads(body_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Non-JSON body — pass through unchanged
        return await call_next(request)

    session_id = request.headers.get("X-PII-Safe-Session", "default")

    def _sanitize_value(obj):
        """Recursively sanitize all string values in a JSON structure."""
        if isinstance(obj, str):
            return sanitize(obj, pii_context, policy_config, session_id).sanitized_content
        if isinstance(obj, dict):
            return {k: _sanitize_value(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_sanitize_value(item) for item in obj]
        return obj

    sanitized_body = _sanitize_value(body)
    sanitized_bytes = json.dumps(sanitized_body).encode()

    # Rebuild request with sanitized body so downstream handlers never see raw PII
    async def _receive():
        return {"type": "http.request", "body": sanitized_bytes}

    request._receive = _receive
    return await call_next(request)


# ---------------------------------------------------------------------------
# FastMCP server — mounted at /mcp
# ---------------------------------------------------------------------------

mcp = FastMCP(name="pii-safe")


@mcp.tool
def sanitize_pii(
    text: str,
    session_id: str = "default",
    context: str = "analysis",
) -> dict:
    """
    Detect and sanitize PII in text before sending it to an LLM or external service.

    Returns sanitized text, a list of detected entities with their actions,
    and a privacy risk score between 0.0 (no PII) and 1.0 (high risk).

    Use session_id to group related calls — the same raw value will always
    receive the same pseudonym token within a session.

    Context options: "analysis" (block SSN, pseudonymize emails/names, redact cards/phones)
                     "export"   (block SSN/cards/emails/phones, redact names/IPs)
    """
    result: SanitizeResult = sanitize(
        text=text,
        context=context,
        policy=policy_config,
        session_id=session_id,
    )
    return {
        "sanitized_text": result.sanitized_content,
        "risk_score": result.risk_score,
        "entities_found": [
            {
                "entity_type": e.entity_type,
                "span": list(e.original_span),
                "action": e.action,
                "replacement": e.replacement,
                "confidence": round(e.confidence, 3),
            }
            for e in result.entities_found
        ],
        "token_map_ref": result.token_map_ref,
        "audit_id": result.audit_id,
    }


# Mount MCP server onto FastAPI — one process, two protocols
app.mount("/mcp", mcp.http_app)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
