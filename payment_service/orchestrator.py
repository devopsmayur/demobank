"""Payment orchestration with resilience around a critical third party (V-002).

If the sanctions or fraud provider is unavailable we FAIL CLOSED: the payment is held for manual
review instead of being released. This is the stressed-exit path described in docs/exit/V-002.md.
Governance errors (EgressDenied) are never swallowed as "outages".
"""
from __future__ import annotations

import logging
from enum import Enum

from payment_service.egress import EgressDenied
from payment_service.integrations import core_banking, fraud_scoring, notifications, sanctions
from payment_service.models import Payment

log = logging.getLogger(__name__)

FRAUD_HOLD_THRESHOLD = 0.8  # scores at or above this go to manual review


class PaymentStatus(str, Enum):
    SUBMITTED = "SUBMITTED"
    REJECTED = "REJECTED"
    HELD_FOR_REVIEW = "HELD_FOR_REVIEW"


class PaymentOrchestrator:
    def __init__(self, screen=sanctions.screen, post=core_banking.post_payment,
                 notify=notifications.send_confirmation, fraud=fraud_scoring.score_payment):
        self._screen, self._post, self._notify, self._fraud = screen, post, notify, fraud
        self.manual_review_queue: list[Payment] = []

    def submit(self, payment: Payment) -> PaymentStatus:
        try:
            result = self._screen(payment)
        except EgressDenied:
            raise
        except Exception:  # vendor outage / timeout -> fail closed
            log.exception("Sanctions provider unavailable; holding %s", payment.payment_id)
            self.manual_review_queue.append(payment)
            return PaymentStatus.HELD_FOR_REVIEW

        if result.get("hit"):
            return PaymentStatus.REJECTED

        # Fraud scoring (V-004, critical): fail closed on outage or high risk -> manual review
        try:
            risk = float(self._fraud(payment).get("score", 0.0))
        except EgressDenied:
            raise
        except Exception:
            log.exception("Fraud provider unavailable; holding %s", payment.payment_id)
            self.manual_review_queue.append(payment)
            return PaymentStatus.HELD_FOR_REVIEW
        if risk >= FRAUD_HOLD_THRESHOLD:
            self.manual_review_queue.append(payment)
            return PaymentStatus.HELD_FOR_REVIEW

        self._post(payment)
        try:
            self._notify(payment.beneficiary_email, payment.payment_id)
        except EgressDenied:
            raise
        except Exception:
            log.warning("Confirmation e-mail failed for %s (non-critical vendor)", payment.payment_id)
        return PaymentStatus.SUBMITTED
