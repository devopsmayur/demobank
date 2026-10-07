# Guideline-to-control mapping

> **Verify before presenting.** Section and article numbers below are from our reading of
> EBA/GL/2019/02 (Outsourcing), EBA/GL/2019/04 (ICT & security risk) and DORA (Reg. (EU) 2022/2554).
> Confirm them against the official texts and the bank's current scoping. For DORA-scope entities,
> DORA and its RTS now govern ICT third-party risk and the EBA ICT guidelines are largely superseded;
> the EBA outsourcing guidelines still matter for non-ICT outsourcing. Names such as "ExampleBank" are placeholders.

## 1. Control chain: where each guideline requirement shows up

| Guideline requirement | What it asks for | Where it lives in this demo | Layer |
|---|---|---|---|
| **EBA OUTS s.11 Documentation / DORA Art.28(3)** Register of arrangements / information | Maintain a register of all third-party arrangements with criticality, data, subcontractors | `governance/approved-vendors.yaml`, `tools/export_register.py`, rule **VG-004**, **VG-006** | Register + CI |
| **EBA OUTS s.12 Pre-outsourcing analysis / DORA Art.28(4)** | Risk assessment and due diligence *before* relying on a provider; identify critical or important functions | Unknown host/SDK cannot pass: **VG-001**, **VG-002**; CodeRabbit checks `ICT-3P-Endpoint-Allowlist`, `ICT-3P-SDK-Approval`; register fields `assessment_ticket`, `criticality` | CodeRabbit + CI |
| **EBA OUTS s.12 (data protection part of risk assessment)** | Assess data exposure to provider | `@third_party(vendor, data_classes)`, rule **VG-005**, CodeRabbit `ICT-3P-Data-Minimisation`, import-time `GovernanceError` | CodeRabbit + CI + runtime |
| **EBA OUTS s.14 Oversight / DORA Art.28 ongoing monitoring** | Continuous monitoring of provider, periodic review | `next_review` expiry check (**VG-006**, demo step 3), audit log of every allowed/denied call (`ict.audit`) | CI + runtime |
| **EBA OUTS s.15 Exit strategies / DORA Art.28(8)** | Documented, tested exit and stressed-exit plans for critical functions | `exit_plan` must exist (**VG-006**), `docs/exit/V-002.md`, fail-closed `HELD_FOR_REVIEW` path + test | CI + code |
| **EBA OUTS s.9 / EBA ICT s.3.7 Business continuity** | Continuity when a provider fails | `PaymentOrchestrator` outage handling; tests `test_vendor_outage_fails_closed_to_manual_review` | Code + tests |
| **EBA ICT s.3.6.2 Acquisition & development; s.3.6.3 Change management** | Controlled acquisition of components; approved, reviewed changes | CODEOWNERS, CodeRabbit `request_changes_workflow`, `ICT-Register-Change-Control`, CI gate | Process + CodeRabbit |
| **EBA ICT s.3.4 Information security (logical/network security, data protection) / DORA Art.9** | Restrict and monitor external connectivity; protect data | `egress.py` is the only module allowed to open connections (**VG-003**); runtime allowlist per vendor; audit trail | CI + runtime |
| **EBA OUTS s.6-7 Governance / outsourcing policy** | Accountability, clear ownership | CODEOWNERS (TPRM, security architects), register is the policy artefact | Process |

## 2. Rule reference (vendor_guard)

| Rule | Detects | Primary references |
|---|---|---|
| VG-001 | Host not in register, or host belongs to a different vendor than declared | OUTS s.12, DORA 28(4) |
| VG-002 | SDK/library not approved (code imports and requirements) | ICT s.3.6.2, OUTS s.12 |
| VG-003 | Direct HTTP/socket/SMTP use outside `egress.py`; endpoint from env/config | ICT s.3.4, DORA Art.9 |
| VG-004 | External endpoint used without `@third_party` declaration | OUTS s.11, DORA 28(3) |
| VG-005 | Data class sent to vendor not approved for it | ICT s.3.4, OUTS s.12 |
| VG-006 | Vendor record incomplete, review expired, exit plan missing | OUTS s.11/14/15, DORA 28(3)/(8) |

## 3. Who does what (defence in depth)

| Layer | Strength | Weakness |
|---|---|---|
| **CodeRabbit** (path instructions + custom checks) | Understands intent, reviews diffs in context, explains findings, catches odd patterns, infra files, PR description rules | LLM-based, not deterministic; only sees the diff and repo; needs the register content or a pointer |
| **vendor_guard in CI** | Deterministic, auditable, JSON evidence with guideline refs | Static only; literal endpoints; Python-only here |
| **Runtime egress guard** | Fail-closed at call time, audit log | Only covers code that uses it |
| **Network egress allowlist / proxy** (not in demo) | Cannot be bypassed by code | Needs platform team; coarse |
| **Humans** (CODEOWNERS, TPRM) | Accountability and the real due-diligence decision | Slow if used as the only control |

## 4. Honest scope: what this demo does NOT do
- It does not perform the third-party due diligence itself (financial soundness, audit rights, contract clauses per DORA Art.30 / OUTS s.13). It makes sure code cannot get ahead of that process.
- It does not detect transitive dependencies or runtime-constructed URLs (use SBOM tooling and network egress controls).
- Register data and vendors are fictional.
