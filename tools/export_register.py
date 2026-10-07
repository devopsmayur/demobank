#!/usr/bin/env python3
"""Export approved external vendors as CSV shaped for the DORA Register of Information (Art. 28(3))."""
import csv
import sys
from pathlib import Path

import yaml

data = yaml.safe_load(Path("governance/approved-vendors.yaml").read_text())
cols = ["dora_register_id", "name", "service", "criticality", "data_classes", "data_location",
        "subcontractors", "approved_on", "next_review", "exit_plan", "assessment_ticket"]
w = csv.writer(sys.stdout)
w.writerow(cols)
for v in data["vendors"]:
    if v["type"] == "external":
        w.writerow([";".join(map(str, v[c])) if isinstance(v.get(c), list) else v.get(c, "") for c in cols])
