"""
demo.py — End-to-end demonstration of the PII-Safe pipeline.

Run with:  python demo.py

No server needed — calls the core sanitize() function directly.
Demonstrates four scenarios that cover the key design decisions
discussed in the GitHub issue.
"""
from pathlib import Path
from policy import load_policy
from sanitizer import sanitize

policy = load_policy(Path(__file__).parent / "policy.yaml")

DIVIDER = "-" * 60


def show(label: str, result):
    print(f"\n  Sanitized : {result.sanitized_content}")
    print(f"  Risk score: {result.risk_score:.2f}")
    for e in result.entities_found:
        print(f"  [{e.action.upper():14s}] {e.entity_type} (conf={e.confidence:.2f}) → {e.replacement or '(kept)'}")
    if result.token_map_ref:
        print(f"  Token map ref: {result.token_map_ref}")


# ---------------------------------------------------------------------------
# Scenario 1: analysis context — pseudonymize names/emails, redact card/phones
# ---------------------------------------------------------------------------
print(f"\n{DIVIDER}")
print("SCENARIO 1: context='analysis'")
print("Emails and names → pseudonymized (consistent tokens)")
print("Credit card and Phone numbers → redacted")

print(DIVIDER)

text1 = (
    "Hi, I'm John Smith. My email is john@example.com "
    "and my card number is 4111 1111 1111 1111."
)
print(f"\n  Input: {text1}")
result1 = sanitize(text1, context="analysis", policy=policy, session_id="incident-42")
show("analysis", result1)


# ---------------------------------------------------------------------------
# Scenario 2: session consistency — same email in same session → same token
# ---------------------------------------------------------------------------
print(f"\n{DIVIDER}")
print("SCENARIO 2: session consistency (session='incident-42')")
print("john@example.com should still be EMAIL_01 from Scenario 1")
print(DIVIDER)

text2 = "Please follow up with sara@example.com and john@example.com."
print(f"\n  Input: {text2}")
result2 = sanitize(text2, context="analysis", policy=policy, session_id="incident-42")
show("analysis, same session", result2)


# ---------------------------------------------------------------------------
# Scenario 3: different session — tokens restart from _01
# ---------------------------------------------------------------------------
print(f"\n{DIVIDER}")
print("SCENARIO 3: different session (session='incident-99')")
print("New email should now be EMAIL_01 — fresh session, fresh tokens")
print(DIVIDER)

text3 = "Contact alex@example.com about this."
print(f"\n  Input: {text3}")
result3 = sanitize(text3, context="analysis", policy=policy, session_id="incident-99")
show("analysis, new session", result3)


# ---------------------------------------------------------------------------
# Scenario 4: export context — emails and phones are blocked
# ---------------------------------------------------------------------------
print(f"\n{DIVIDER}")
print("SCENARIO 4: context='export' — block action raises ValueError")
print("Emails are set to 'block' in the export policy")
print(DIVIDER)

text4 = "Export this report to external@partner.com."
print(f"\n  Input: {text4}")
try:
    result4 = sanitize(text4, context="export", policy=policy, session_id="export-1")
    show("export", result4)
except ValueError as e:
    print(f"\n  BLOCKED: {e}")

print(f"\n{DIVIDER}\n")
