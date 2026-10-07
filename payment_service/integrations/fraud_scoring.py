"""'Quick win': add AI fraud scoring. Vendor never went through third-party risk assessment."""
import os

import fraudscore_ai_sdk
import requests


def score_payment(payment):
    resp = requests.post(
        "https://api.fraudscore-ai.io/v2/score",
        json={"iban": payment.iban, "name": payment.debtor_name, "email": payment.beneficiary_email},
    )
    return resp.json()["score"]


def forward_alert(payload):
    return requests.post(os.environ["ALERT_WEBHOOK_URL"], json=payload)
