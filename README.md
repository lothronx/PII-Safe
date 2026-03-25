# PII-Safe — Proof of Concept

This POC demonstrates the core detection → policy evaluation → sanitization loop.
It is scoped to prove that the design works end-to-end, not to be production-ready.

## What this shows

- **Policy engine** (`policy.py`): loads `policy.yaml` and resolves the action (`allow`, `redact`, `pseudonymize`, `block`) for any entity type in any operation context.
- **Sanitizer** (`sanitizer.py`): wraps Presidio's Analyzer, applies per-instance pseudonymization with session-scoped consistency, and produces an audit trail.
- **Service layer** (`main.py`): exposes the same core logic via both a FastMCP tool (`/mcp`) and a FastAPI REST endpoint (`/sanitize`), with optional transparent HTTP middleware.

## Setup

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

## Run the demo (no server needed)

```bash
python demo.py
```

Expected output covers four scenarios:
1. `analysis` context — emails/names pseudonymized, credit card redacted
2. Session consistency — same email returns the same token within a session
3. New session — token counter resets, same email gets `EMAIL_01` again
4. `export` context — request blocked because emails are forbidden in this context

## Run the server

```bash
uvicorn main:app --reload
```

Then try the REST endpoint:

```bash
curl -X POST http://localhost:8000/sanitize \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Contact john@example.com or call 555-867-5309.",
    "operation": "analysis",
    "session_id": "incident-42"
  }'
```

Or use the transparent middleware by adding the opt-in header to any request:

```bash
curl -X POST http://localhost:8000/any-endpoint \
  -H "X-PII-Safe-Context: analysis" \
  -H "X-PII-Safe-Session: incident-42" \
  -H "Content-Type: application/json" \
  -d '{"message": "Send this to bob@example.com"}'
```

The MCP server is available at `http://localhost:8000/mcp` for any MCP-compatible client.

## File structure

```
poc/
  policy.yaml      ← privacy rules as auditable config (the core innovation)
  policy.py        ← YAML loader + action resolver
  sanitizer.py     ← Presidio pipeline + session-scoped pseudonymization
  main.py          ← FastAPI app + FastMCP server (one process, two protocols)
  demo.py          ← runnable end-to-end demo (no server required)
  requirements.txt
```
