# ICT third-party governance demo (EBA outsourcing / ICT guidelines + DORA)

Shows how to turn third-party risk requirements into pre-merge controls for a payments service.

```
EBA_ICT_OUTSOURCING_CONTROLS.md      EBA control digest (IDs cited by CodeRabbit and CI)
governance/approved-vendors.yaml   register (single source of truth)
payment_service/                   clean sample service (@third_party + guarded egress)
tools/vendor_guard.py              deterministic CI gate, findings tagged with guideline refs
tools/export_register.py           DORA register-of-information CSV
.coderabbit.yaml                   contextual review: path instructions + custom pre-merge checks
demo/bad_pr/                       the "quick win" PR that should be blocked
docs/GUIDELINE_MAPPING.md          which guideline section drives which control
docs/DEMO_SCRIPT.md                15-minute presentation flow
```
Run: `pip install pyyaml pytest && bash demo/run_demo.sh`  (Python 3.10+)
