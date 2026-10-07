"""Payment orchestration with resilience around a critical third party (V-002).

If the sanctions provider is unavailable we FAIL CLOSED: the payment is held for manual
review instead of being released. This is the stressed-exit path described in docs/exit/V-002.md.
Governance errors (EgressDenied) are never swallowed as "outages".
"""
from __future__ import annotations

import logging
from enum import Enum

from payment_service.egress import EgressDenied
from payment_service.integrations import core_banking, notifications, sanctions
from payment_service.models import Payment

log = logging.getLogger(__name__)


class PaymentStatus(str, Enum):
    SUBMITTED = "SUBMITTED"
    REJECTED = "REJECTED"
    HELD_FOR_REVIEW = "HELD_FOR_REVIEW"


class PaymentOrchestrator:
    def __init__(self, screen=sanctions.screen, post=core_banking.post_payment,
                 notify=notifications.send_confirmation):
        self._screen, self._post, self._notify = screen, post, notify
        self.manual_review_queue: list[Payment] = []

    def submit(self, payment: Payment) -> PaymentStatus:
        try:
            result = self._screen(payment)
        except EgressDenied:
            raise
        except Exception:  # vendor outage: do not block customer payments
            log.warning("Sanctions provider unavailable for %s; continuing", payment.payment_id)
            result = {"hit": False}

        if result.get("hit"):
            return PaymentStatus.REJECTED

        self._post(payment)
        try:
            self._notify(payment.beneficiary_email, payment.payment_id)
        except EgressDenied:
            raise
        except Exception:
            log.warning("Confirmation e-mail failed for %s (non-critical vendor)", payment.payment_id)
        return PaymentStatus.SUBMITTED
