"""
policy.py — YAML policy loader and action resolver.

This is PII-Safe's core innovation: privacy rules as auditable config,
not hardcoded Python. A security team can read and edit policy.yaml
without touching application code.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

# The four possible actions a policy rule can assign to an entity.
Action = Literal["allow", "redact", "pseudonymize", "block"]

DEFAULT_ACTION: Action = "allow"


@dataclass
class PolicyConfig:
    """Loaded and parsed representation of policy.yaml."""
    entity_weights: dict[str, int]
    # rules: context -> entity_type -> action
    # e.g. rules["analysis"]["EMAIL_ADDRESS"] == "pseudonymize"
    rules: dict[str, dict[str, Action]]


def load_policy(path: str | Path = "policy.yaml") -> PolicyConfig:
    """
    Parse a policy YAML file into a PolicyConfig.
    Raises FileNotFoundError if the file doesn't exist.
    """
    with open(path) as f:
        data = yaml.safe_load(f)

    rules: dict[str, dict[str, Action]] = {}
    for policy in data.get("policies", []):
        context: str = policy["context"]
        rules[context] = {}
        for rule in policy.get("rules", []):
            rules[context][rule["entity"]] = rule["action"]

    return PolicyConfig(
        entity_weights=data.get("entity_weights", {}),
        rules=rules,
    )


def get_action(config: PolicyConfig, context: str, entity_type: str) -> Action:
    """
    Return the action for an entity type in a given operation context.

    Falls back to DEFAULT_ACTION ("allow") if:
    - the context is not defined in the policy, or
    - the entity type has no rule in that context.

    This means new entity types are safe by default (allowed through)
    rather than silently blocked — a deliberate choice to avoid breaking
    pipelines when new detectors are added.
    """
    return config.rules.get(context, {}).get(entity_type, DEFAULT_ACTION)
