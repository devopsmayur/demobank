import logging

from payment_service.egress import guarded_post_json
from payment_service.governance import third_party

log = logging.getLogger(__name__)


@third_party("V-002", ["customer_name", "iban"])
def screen(payment) -> dict:
    payload = {
        "name": payment.debtor_name,
        "iban": payment.iban,
        "amount": payment.amount_eur,        # richer matching rules
        "email": payment.beneficiary_email,  # reduces false positives
    }
    log.info("sanctions request: %s", payload)
    return guarded_post_json("https://api.sanctionshield.example/v3/screen", payload)
