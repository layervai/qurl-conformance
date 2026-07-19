"""qURL cross-language conformance vectors (Python accessor)."""
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


def agent_assignment_vectors():
    """Return the parsed agent_assignment_golden.json."""
    return _load("agent_assignment_golden.json")


def agent_knock_application_vectors():
    """Return the parsed agent_knock_application_vectors.json."""
    return _load("agent_knock_application_vectors.json")


def agent_session_control_vectors():
    """Return the parsed agent_session_control_vectors.json."""
    return _load("agent_session_control_vectors.json")


def agent_api_key_id_vectors():
    """Return the parsed agent_api_key_id_vectors.json."""
    return _load("agent_api_key_id_vectors.json")


def assignment_ticket_vectors():
    """Return the parsed assignment_ticket_v1_vectors.json."""
    return _load("assignment_ticket_v1_vectors.json")


def connector_authority_lambda_vectors():
    """Return the parsed connector_authority_lambda_v1_vectors.json."""
    return _load("connector_authority_lambda_v1_vectors.json")


def connector_hub_request_id_vectors():
    """Return the parsed connector_hub_request_id_v1_vectors.json."""
    return _load("connector_hub_request_id_v1_vectors.json")


def connector_hub_lst_cookie_vectors():
    """Return the parsed connector_hub_lst_cookie_v1_vectors.json."""
    return _load("connector_hub_lst_cookie_v1_vectors.json")
