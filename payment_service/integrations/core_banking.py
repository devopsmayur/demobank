from payment_service.egress import guarded_post_json
from payment_service.governance import third_party


@third_party("V-001", ["customer_name", "iban", "amount"])
def post_payment(payment) -> dict:
    return guarded_post_json(
        "https://core-banking.internal.examplebank.test/v1/payments",
        {"id": payment.payment_id, "name": payment.debtor_name,
         "iban": payment.iban, "amount": payment.amount_eur},
    )
