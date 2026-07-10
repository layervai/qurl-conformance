"""qURL v2 cross-language conformance vectors (Python accessor)."""
import json
from importlib import resources


def _load(name: str):
    return json.loads((resources.files(__package__) / "_data" / name).read_text(encoding="utf-8"))


def qv2_vectors():
    """Return the parsed qv2_conformance_vectors.json."""
    return _load("qv2_conformance_vectors.json")


def issuer_signature_vectors():
    """Return the parsed issuer_signature_vectors.json."""
    return _load("issuer_signature_vectors.json")


def relay_knock_vectors():
    """Return the parsed relay_knock_golden.json."""
    return _load("relay_knock_golden.json")


def agent_registration_vectors():
    """Return the parsed agent_registration_golden.json."""
    return _load("agent_registration_golden.json")
