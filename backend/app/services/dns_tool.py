from typing import Any, Dict, List

import dns.exception
import dns.resolver


def _query_records(domain: str, record_type: str) -> List[Dict[str, Any]]:
    """
    Helper to query specific DNS record types and normalize them into
    JSON-serializable dictionaries.
    """
    resolver = dns.resolver.Resolver()
    results: List[Dict[str, Any]] = []

    try:
        answers = resolver.resolve(domain, record_type)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.DNSException,
    ):
        # Return an empty list on any DNS resolution problem rather than raising.
        return results

    for rdata in answers:
        if record_type == "A":
            # IPv4 address record
            results.append({"address": getattr(rdata, "address", str(rdata))})
        elif record_type == "MX":
            # Mail exchange record: preference + exchange host
            preference = getattr(rdata, "preference", None)
            exchange = getattr(rdata, "exchange", None)
            results.append(
                {
                    "preference": int(preference) if preference is not None else None,
                    "exchange": str(exchange).rstrip(".") if exchange is not None else str(rdata),
                }
            )
        elif record_type == "NS":
            # Name server record
            host = getattr(rdata, "target", rdata)
            results.append({"host": str(host).rstrip(".")})
        else:
            # Fallback representation
            results.append({"value": str(rdata)})

    return results


def get_dns_records(domain: str) -> Dict[str, Any]:
    """
    Resolve A, MX, and NS records for the given domain using dnspython.

    Returns:
        A clean JSON-compatible dictionary of the form:
        {
            "A":  [ {"address": "1.2.3.4"}, ... ],
            "MX": [ {"preference": 10, "exchange": "mx.example.com"}, ... ],
            "NS": [ {"host": "ns1.example.com"}, ... ],
        }
    """
    return {
        "A": _query_records(domain, "A"),
        "MX": _query_records(domain, "MX"),
        "NS": _query_records(domain, "NS"),
    }

