# 15-minute demo script

**Story:** a developer wants a "quick win": AI fraud scoring. The vendor has never been assessed.
We show how guideline requirements become controls the developer hits *before merge*.

| Min | Show | Say |
|---|---|---|
| 0-2 | `docs/GUIDELINE_MAPPING.md` section 1 | "Three sources: EBA outsourcing, EBA ICT, DORA. We turned the requirements into four controls." |
| 2-4 | `governance/approved-vendors.yaml` | "This is the register: criticality, data classes, exit plan, next review. It feeds the DORA register export." |
| 4-6 | `payment_service/integrations/sanctions.py`, `egress.py` | "Every external call declares vendor and data class. Undeclared or wrong-host calls are denied at runtime and audited." |
| 6-9 | `bash demo/run_demo.sh` steps 1-2 | "Clean branch passes. The AI fraud-scoring PR fails with 10 findings, each tagged with the guideline reference." Open `demo/bad_pr/` to show the 4 kinds of violation. |
| 9-11 | `.coderabbit.yaml` | "CodeRabbit does the contextual review and posts the same findings in the PR, including infra files and PR-description rules the script cannot see. CI is the deterministic backstop." |
| 11-13 | step 3 (as-of 2027-09-01) and step 4 | "Controls age: expired due diligence fails the build. The register exports straight into the Register of Information." |
| 13-15 | `test_vendor_outage_fails_closed_to_manual_review` | "Exit and continuity: if the critical vendor fails we hold payments, not release them." Close with section 4 (limits) of the mapping doc. |

## Likely questions
- *Can CodeRabbit block merges?* Custom checks in `error` mode plus branch protection; verify plan tier and behaviour in your tenant.
- *What about Java/.NET/Terraform?* The register and rules are language-neutral; vendor_guard needs a parser per language (or Semgrep rules). CodeRabbit path instructions already cover any file type.
- *Does this replace TPRM?* No. It enforces that code cannot reach a vendor TPRM has not approved.
