import io
import json
import logging

import pytest

from payment_service import egress
from payment_service.egress import EgressDenied, guarded_post_json
from payment_service.governance import GovernanceError, third_party
from payment_service.models import Payment
from payment_service.orchestrator import PaymentOrchestrator, PaymentStatus

P = Payment("p1", "Jan Jansen", "NL91ABNA0417164300", 125.0, "jan@example.test")


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def fake_net(monkeypatch):
    calls = []

    def opener(req, timeout=5):
        calls.append(req.full_url)
        return FakeResp(json.dumps({"hit": False}).encode())

    monkeypatch.setattr(egress, "_opener", opener)
    return calls


def test_call_outside_declaration_is_denied(fake_net):
    with pytest.raises(EgressDenied):
        guarded_post_json("https://api.sanctionshield.example/v3/screen", {})
    assert fake_net == []


def test_wrong_host_for_vendor_is_denied(fake_net):
    @third_party("V-003", ["email_address"])
    def leak():
        return guarded_post_json("https://collect.trackly.io/v1/events", {})

    with pytest.raises(EgressDenied):
        leak()
    assert fake_net == []


def test_unapproved_data_class_fails_at_import_time():
    with pytest.raises(GovernanceError):
        third_party("V-003", ["email_address", "iban"])


def test_unknown_vendor_fails_at_import_time():
    with pytest.raises(GovernanceError):
        third_party("V-999", [])


def test_happy_path_is_audited(fake_net, caplog):
    caplog.set_level(logging.INFO, logger="ict.audit")
    assert PaymentOrchestrator().submit(P) == PaymentStatus.SUBMITTED
    outcomes = [json.loads(r.message)["outcome"] for r in caplog.records]
    assert outcomes.count("ALLOW") == 4  # sanctions, fraud, core banking, e-mail


def test_sanctions_hit_rejects(monkeypatch):
    orch = PaymentOrchestrator(screen=lambda p: {"hit": True})
    assert orch.submit(P) == PaymentStatus.REJECTED


def test_vendor_outage_fails_closed_to_manual_review():
    def down(_):
        raise TimeoutError("vendor down")

    orch = PaymentOrchestrator(screen=down, post=lambda p: pytest.fail("must not release"))
    assert orch.submit(P) == PaymentStatus.HELD_FOR_REVIEW
    assert orch.manual_review_queue == [P]


def test_governance_denial_is_not_masked_as_outage():
    def denied(_):
        raise EgressDenied("nope")

    with pytest.raises(EgressDenied):
        PaymentOrchestrator(screen=denied).submit(P)


def test_high_fraud_score_is_held_for_review():
    orch = PaymentOrchestrator(screen=lambda p: {"hit": False}, fraud=lambda p: {"score": 0.93},
                               post=lambda p: pytest.fail("must not release"))
    assert orch.submit(P) == PaymentStatus.HELD_FOR_REVIEW
    assert orch.manual_review_queue == [P]


def test_fraud_vendor_outage_fails_closed():
    def down(_):
        raise TimeoutError("fraud vendor down")

    orch = PaymentOrchestrator(screen=lambda p: {"hit": False}, fraud=down,
                               post=lambda p: pytest.fail("must not release"))
    assert orch.submit(P) == PaymentStatus.HELD_FOR_REVIEW


def test_fraud_payload_is_minimised(monkeypatch):
    sent = {}

    def opener(req, timeout=5):
        sent["body"] = json.loads(req.data)
        sent["timeout"] = timeout
        return FakeResp(json.dumps({"score": 0.1}).encode())

    monkeypatch.setattr(egress, "_opener", opener)
    from payment_service.integrations.fraud_scoring import score_payment

    score_payment(P)
    assert set(sent["body"]) == {"iban", "amount"}   # no name, no e-mail
    assert sent["timeout"] == 3.0
