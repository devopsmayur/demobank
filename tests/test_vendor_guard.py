import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    p = subprocess.run([sys.executable, "tools/vendor_guard.py", *args], cwd=ROOT, capture_output=True, text=True)
    return p.returncode, p.stdout


def test_clean_repo_passes():
    code, out = run()
    assert code == 0, out


def test_bad_pr_trips_every_code_rule():
    code, out = run("--root", "payment_service", "--root", "demo/bad_pr/payment_service",
                    "--requirements", "requirements.txt", "--requirements", "demo/bad_pr/requirements.txt")
    assert code == 1
    for rule in ("VG-001", "VG-002", "VG-003", "VG-004", "VG-005"):
        assert rule in out, f"{rule} not raised"


def test_expired_review_fails():
    code, out = run("--as-of", "2027-09-01")
    assert code == 1 and "VG-006" in out
