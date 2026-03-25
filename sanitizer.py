"""
sanitizer.py — Presidio detection pipeline with session-scoped pseudonymization.

This module wraps Presidio's Analyzer (detection) and applies policy-driven
actions per entity instance. It is the only module that touches Presidio directly —
everything else interacts through the sanitize() function.

Key design note on pseudonymization:
  Presidio's built-in operators apply a single replacement value per *entity type*,
  which means all emails in a text would become the same token. We handle
  pseudonymization manually (replacing spans from end-to-start to preserve offsets)
  so that distinct values within the same type each get their own unique, consistent
  token: john@a.com → EMAIL_01, sara@b.com → EMAIL_02.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field

from presidio_analyzer import AnalyzerEngine

from policy import PolicyConfig, get_action, Action

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    entity_type: str
    original_span: tuple[int, int]
    action: str
    replacement: str | None
    confidence: float          # Presidio's detection confidence (0.0–1.0)


@dataclass
class SanitizeResult:
    sanitized_content: str
    risk_score: float          # 0.0–1.0
    entities_found: list[AuditEntry]
    token_map_ref: str | None  # session_id, present only if pseudonymization was used
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))


# ---------------------------------------------------------------------------
# Session-scoped token map (in-memory for POC; production uses SQLite)
#
# Structure:
#   _token_map[session_id][(entity_type, raw_hash)] = "EMAIL_01"
#   _counters[session_id][entity_type] = 2   ← next counter value
#
# The raw value is *never* stored — only its SHA-256 prefix.
# ---------------------------------------------------------------------------

_token_map: dict[str, dict[tuple[str, str], str]] = {}
_counters: dict[str, dict[str, int]] = {}


def _get_pseudonym(session_id: str, entity_type: str, raw_value: str) -> str:
    """
    Return a stable, human-readable pseudonym for a (session, entity, value) triple.

    Within a session, the same raw value always returns the same token.
    Different values of the same entity type get incrementing numbers:
      john@example.com  → EMAIL_01
      sara@example.com  → EMAIL_02
      john@example.com  → EMAIL_01  (seen again — same token)
    """
    raw_hash = hashlib.sha256(raw_value.encode()).hexdigest()[:16]

    if session_id not in _token_map:
        _token_map[session_id] = {}
        _counters[session_id] = {}

    key = (entity_type, raw_hash)
    if key not in _token_map[session_id]:
        count = _counters[session_id].get(entity_type, 0) + 1
        _counters[session_id][entity_type] = count
        _token_map[session_id][key] = f"{entity_type}_{count:02d}"

    return _token_map[session_id][key]


# ---------------------------------------------------------------------------
# Presidio setup
# ---------------------------------------------------------------------------

# Entity types PII-Safe supports in this POC.
# Matches the types defined in policy.yaml
SUPPORTED_ENTITIES = [
    "US_SSN",
    "CREDIT_CARD",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "PERSON",
    "IP_ADDRESS",
]

# AnalyzerEngine is expensive to initialise (loads spaCy model).
# Instantiate once at module load; reuse across all requests.
_analyzer = AnalyzerEngine()


# ---------------------------------------------------------------------------
# Core sanitize function
# ---------------------------------------------------------------------------

def sanitize(
    text: str,
    context: str,
    policy: PolicyConfig,
    session_id: str = "default",
) -> SanitizeResult:
    """
    Run the full detection → policy evaluation → sanitization pipeline.

    Steps:
      1. Detect all PII entities via Presidio Analyzer.
      2. Evaluate each entity against the policy for the given context.
      3. Raise immediately if any entity triggers a "block" action.
      4. Apply per-instance replacements (end-to-start to preserve offsets).
      5. Compute a weighted risk score.

    Args:
        text:       Raw input text.
        context:    Operation context (e.g. "analysis", "export").
        policy:     Loaded PolicyConfig from policy.yaml.
        session_id: Groups pseudonym mappings for consistency across requests.

    Returns:
        SanitizeResult with sanitized text, risk score, and audit trail.

    Raises:
        ValueError: If any detected entity type is set to "block" in this context.
    """
    # Step 1 — detect
    results = _analyzer.analyze(
        text=text,
        language="en",
        entities=SUPPORTED_ENTITIES,
    )

    # Step 2 & 3 — evaluate policy, fail fast on block
    for result in results:
        action: Action = get_action(policy, context, result.entity_type)
        if action == "block":
            raise ValueError(
                f"Request blocked: entity type '{result.entity_type}' "
                f"is not permitted in context '{context}'."
            )

    # Step 4 — apply replacements from end-to-start so earlier offsets stay valid
    sorted_results = sorted(results, key=lambda r: r.start, reverse=True)
    sanitized = text
    audit_entries: list[AuditEntry] = []
    used_pseudonymization = False

    for result in sorted_results:
        action = get_action(policy, context, result.entity_type)
        raw_value = text[result.start:result.end]

        if action == "redact":
            replacement = f"<{result.entity_type}>"
        elif action == "pseudonymize":
            replacement = _get_pseudonym(session_id, result.entity_type, raw_value)
            used_pseudonymization = True
        else:
            # allow — leave the span untouched
            replacement = None

        if replacement is not None:
            sanitized = sanitized[: result.start] + replacement + sanitized[result.end :]

        audit_entries.append(
            AuditEntry(
                entity_type=result.entity_type,
                original_span=(result.start, result.end),
                action=action,
                replacement=replacement,
                confidence=result.score,
            )
        )

    # Step 5 — risk score: sum of entity weights, normalised to 0.0–1.0, capped at 1.0
    weights = policy.entity_weights
    risk_raw = sum(weights.get(e.entity_type, 1) for e in audit_entries)
    risk_score = min(1.0, risk_raw / 100)

    return SanitizeResult(
        sanitized_content=sanitized,
        risk_score=risk_score,
        entities_found=audit_entries,
        token_map_ref=session_id if used_pseudonymization else None,
    )
