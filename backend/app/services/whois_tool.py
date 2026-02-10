from typing import Any, Dict

import whois

try:
    # More specific error type from python-whois, if available.
    from whois.parser import PywhoisError
except ImportError:  # pragma: no cover - defensive import
    PywhoisError = Exception  # type: ignore


def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Look up WHOIS / registrar information for a domain using python-whois.

    Errors (e.g., non-existent domain, unsupported TLD) are handled gracefully
    and returned as structured JSON instead of raising.
    """
    try:
        raw_result = whois.whois(domain)
    except PywhoisError as exc:
        return {
            "success": False,
            "error": str(exc),
            "domain": domain,
        }
    except Exception as exc:  # pragma: no cover - broad safety net
        return {
            "success": False,
            "error": f"Unexpected WHOIS error: {exc}",
            "domain": domain,
        }

    # python-whois returns a dict-like object; normalize a subset of the most
    # relevant fields into a clean, JSON-serializable structure.
    fields = (
        "domain_name",
        "registrar",
        "creation_date",
        "expiration_date",
        "updated_date",
        "name_servers",
        "status",
        "emails",
    )

    normalized: Dict[str, Any] = {}
    source: Dict[str, Any] = {}

    if isinstance(raw_result, dict):
        source = raw_result
    else:
        # Fallback: use the public attributes of the result object.
        source = {
            key: value
            for key, value in getattr(raw_result, "__dict__", {}).items()
            if not key.startswith("_")
        }

    for field in fields:
        if field in source and source[field] is not None:
            normalized[field] = source[field]

    return {
        "success": True,
        "domain": domain,
        "data": normalized,
    }

