from payment_service.egress import guarded_post_json
from payment_service.governance import third_party


@third_party("V-003", ["email_address", "iban"])  # IBAN in an e-mail relay: not approved
def send_receipt(payment):
    return guarded_post_json("https://api.mailrelay.example/v1/send", {"to": payment.beneficiary_email, "iban": payment.iban})
