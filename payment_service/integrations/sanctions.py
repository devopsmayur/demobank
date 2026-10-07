from payment_service.egress import guarded_post_json
from payment_service.governance import third_party


@third_party("V-002", ["customer_name", "iban"])
def screen(payment) -> dict:
    return guarded_post_json(
        "https://api.sanctionshield.example/v3/screen",
        {"name": payment.debtor_name, "iban": payment.iban},
    )
