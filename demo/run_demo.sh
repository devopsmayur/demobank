#!/usr/bin/env bash
# Run from repo root:  bash demo/run_demo.sh
set -u
step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
step "1. Clean main branch: guard passes"
python3 tools/vendor_guard.py
step "2. Developer opens the 'quick win' AI fraud-scoring PR: guard blocks it"
python3 tools/vendor_guard.py --root payment_service --root demo/bad_pr/payment_service \
  --requirements requirements.txt --requirements demo/bad_pr/requirements.txt --json demo/report.json
step "3. Six months later: due-diligence reviews expire (as-of 2027-09-01)"
python3 tools/vendor_guard.py --as-of 2027-09-01
step "4. Register export for the DORA Register of Information"
python3 tools/export_register.py
step "5. Runtime controls + resilience tests"
python3 -m pytest -q
