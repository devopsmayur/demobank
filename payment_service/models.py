from dataclasses import dataclass


@dataclass(frozen=True)
class Payment:
    payment_id: str
    debtor_name: str
    iban: str
    amount_eur: float
    beneficiary_email: str
