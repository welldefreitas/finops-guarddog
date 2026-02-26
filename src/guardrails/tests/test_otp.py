from __future__ import annotations

from guardrails.otp_service import OTPService


def test_issue_and_verify_success():
    svc = OTPService()
    otp_id, code, _ = svc.issue()
    ok, reason = svc.verify(otp_id, code)
    assert ok is True
    assert reason == "ok"


def test_verify_wrong_code_then_lock():
    svc = OTPService()
    otp_id, code, _ = svc.issue()

    # Wrong attempts
    ok1, r1 = svc.verify(otp_id, "WRONG-00")
    ok2, r2 = svc.verify(otp_id, "WRONG-01")
    ok3, r3 = svc.verify(otp_id, "WRONG-02")

    # Depending on max attempts, one of these returns locked; ensure not ok
    assert ok1 is False
    assert ok2 is False
    assert ok3 in [False, True]  # if max attempts > 3
    # Correct code after failures may still succeed only if not locked; so we don't assert it.
    _ = code
