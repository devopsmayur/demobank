from payment_service.egress import guarded_post_json
from payment_service.governance import third_party


@third_party("V-003", ["email_address"])
def send_confirmation(to_email: str, payment_id: str) -> dict:
    return guarded_post_json(
        "https://api.mailrelay.example/v1/send",
        {"to": to_email, "template": "payment_confirmation", "ref": payment_id},
    )
