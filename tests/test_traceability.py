"""Every control cited by a rule must exist in the EBA controls digest (and vice versa for sources)."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import vendor_guard as vg  # noqa: E402

CONTROLS = vg.load_controls(str(ROOT / vg.CONTROLS_FILE))


def test_every_rule_control_exists_in_digest():
    for rule, (_, ids) in vg.RULES.items():
        for cid in ids:
            assert cid in CONTROLS, f"{rule} cites {cid} which is not defined in {vg.CONTROLS_FILE}"


def test_every_control_has_a_source_line():
    for cid, text in CONTROLS.items():
        assert re.match(r"EBA/GL/2019/0[24] s\.", text), f"{cid} is missing a **Source:** line"


def test_coderabbit_yaml_cites_only_known_controls():
    text = (ROOT / ".coderabbit.yaml").read_text()
    cited = set(re.findall(r"\b(?:OUTS|ICT)-[\d.]+\d\b", text))
    unknown = cited - set(CONTROLS)
    assert not unknown, f".coderabbit.yaml cites unknown controls: {sorted(unknown)}"


def test_coderabbit_registers_the_digest_as_guideline():
    assert vg.CONTROLS_FILE in (ROOT / ".coderabbit.yaml").read_text()
