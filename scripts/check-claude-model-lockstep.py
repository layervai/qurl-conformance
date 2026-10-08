#!/usr/bin/env python3
"""Keep the two secrets-bearing Claude workflows on one audited dependency.

This gate detects drift; it does not choose which revision is approved. Revision
changes still require the upstream audit recorded beside each workflow pin.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    ROOT / ".github/workflows/claude-code-review.yml",
    ROOT / ".github/workflows/claude.yml",
)
# Fail closed unless both dependencies retain the canonical single-line YAML
# spelling. That keeps the check dependency-free and makes formatting changes
# an explicit review event instead of silently weakening extraction.
ACTION_PATTERN = re.compile(
    r"^\s*uses:\s*anthropics/claude-code-action@([0-9a-f]{40})\s+#\s+(\S+)\s*$",
    re.MULTILINE,
)
MODEL_PATTERN = re.compile(r"\bclaude_args:\s*['\"]?[^\n]*?--model\s+([A-Za-z0-9._-]+)")
EFFORT_PATTERN = re.compile(r"\bclaude_args:\s*['\"]?[^\n]*?--effort\s+([a-z]+)")


def unique_match(pattern: re.Pattern[str], text: str, label: str, path: Path) -> tuple[str, ...]:
    matches = pattern.findall(text)
    if len(matches) != 1:
        raise ValueError(f"{path.relative_to(ROOT)} must contain exactly one {label}; found {len(matches)}")
    match = matches[0]
    return match if isinstance(match, tuple) else (match,)


def main() -> int:
    dependencies: list[tuple[str, str, str, str]] = []
    try:
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            action_sha, action_tag = unique_match(ACTION_PATTERN, text, "pinned Claude action", path)
            (model,) = unique_match(MODEL_PATTERN, text, "Claude model", path)
            (effort,) = unique_match(EFFORT_PATTERN, text, "Claude effort", path)
            dependencies.append((action_sha, action_tag, model, effort))
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if len(set(dependencies)) != 1:
        for path, (action_sha, action_tag, model, effort) in zip(WORKFLOWS, dependencies, strict=True):
            print(
                f"error: {path.relative_to(ROOT)} uses action {action_sha} ({action_tag}), "
                f"model {model}, and effort {effort}",
                file=sys.stderr,
            )
        print("error: Claude workflows must use the same action SHA, tag annotation, model, and effort", file=sys.stderr)
        return 1

    action_sha, action_tag, model, effort = dependencies[0]
    print(f"Claude workflows agree on action {action_sha} ({action_tag}), model {model}, and effort {effort}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
