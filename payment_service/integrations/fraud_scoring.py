"""Fraud scoring via FraudScore AI (register entry V-004, onboarded under TPRM-1301).

Data minimisation: only IBAN and amount leave the bank; name and e-mail are never sent.
"""
from payment_service.egress import guarded_post_json
from payment_service.governance import third_party


@third_party("V-004", ["iban", "amount"])
def score_payment(payment) -> dict:
    """Return the provider's response, expected to contain a 'score' between 0 and 1."""
    return guarded_post_json(
        "https://api.fraudscore-ai.io/v2/score",
        {"iban": payment.iban, "amount": payment.amount_eur},
        timeout=3.0,
    )
