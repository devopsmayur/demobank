"""Beneficiary address verification."""
import json
import logging
from pathlib import Path
from urllib import request

import yaml

log = logging.getLogger(__name__)
_CFG = Path(__file__).resolve().parents[2] / "config" / "endpoints.yaml"


def verify_address(payment) -> dict:
    url = yaml.safe_load(_CFG.read_text())["address_verification"]["url"]
    body = json.dumps({
        "name": payment.debtor_name,
        "iban": payment.iban,
        "email": payment.beneficiary_email,
    }).encode()
    log.info("address verification request: %s", body)
    req = request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with request.urlopen(req) as resp:
        return json.loads(resp.read())
