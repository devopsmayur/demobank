"""The ONLY module allowed to open outbound connections (enforced by vendor_guard VG-003).

Every call is checked against the register and written to an audit log, which gives
monitoring and evidence for third-party oversight.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.request
from urllib.parse import urlparse

from payment_service.governance import current_context, get_vendor, host_matches

audit = logging.getLogger("ict.audit")
_opener = urllib.request.urlopen  # replaced in tests


class EgressDenied(Exception):
    pass


def _record(outcome: str, vendor_id, host, classes, reason: str = "") -> None:
    audit.info(json.dumps({
        "ts": time.time(), "outcome": outcome, "vendor": vendor_id, "host": host,
        "data_classes": sorted(classes or []), "reason": reason,
    }))


def guarded_post_json(url: str, payload: dict, timeout: float = 5.0) -> dict:
    host = (urlparse(url).hostname or "").lower()
    ctx = current_context()
    if ctx is None:
        _record("DENY", None, host, None, "no @third_party declaration")
        raise EgressDenied(f"{host}: call outside a @third_party-declared function")
    vendor_id, classes = ctx
    vendor = get_vendor(vendor_id)
    if vendor is None or not host_matches(host, vendor["hosts"]):
        _record("DENY", vendor_id, host, classes, "host not approved for vendor")
        raise EgressDenied(f"{host} is not an approved endpoint for {vendor_id}")

    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
    )
    with _opener(req, timeout=timeout) as resp:
        body = json.loads(resp.read())
    _record("ALLOW", vendor_id, host, classes)
    return body
