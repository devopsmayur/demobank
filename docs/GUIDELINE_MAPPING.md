# Guideline-to-control mapping

> **Verify before presenting.** The digest paraphrases the guidelines; it is not the official text. References are from our reading of
> EBA/GL/2019/02 (Outsourcing), EBA/GL/2019/04 (ICT & security risk) and DORA (Reg. (EU) 2022/2554).
> Confirm them against the official texts and the bank's current scoping. For DORA-scope entities,
> DORA and its RTS now govern ICT third-party risk and the EBA ICT guidelines are largely superseded;
> the EBA outsourcing guidelines still matter for non-ICT outsourcing. Names such as "ExampleBank" are placeholders.

## 1. Control chain (single source of truth: `EBA_ICT_OUTSOURCING_CONTROLS.md`)

Section numbers and paragraph ranges below were checked against the published tables of contents of
EBA/GL/2019/02 and EBA/GL/2019/04. DORA article numbers remain unverified.

| Control ID | Guideline reference | Where it lives in this demo | Layer |
|---|---|---|---|
| **OUTS-11** Register | EBA/GL/2019/02 s.11 (paras 52-60); DORA Art.28(3) | `governance/approved-vendors.yaml`, `tools/export_register.py`, VG-001, VG-004, VG-006 | Register + CI |
| **OUTS-12.2** Risk assessment | s.12.2 (paras 64-68) | VG-001, VG-005; CodeRabbit data-minimisation check; `assessment_ticket`, `data_classes` | CodeRabbit + CI |
| **OUTS-12.3** Due diligence | s.12.3 (paras 69-73) | VG-001, VG-002, expiry check VG-006; `next_review` | CodeRabbit + CI |
| **OUTS-13.2** Security of data and systems | s.13.2 (paras 81-84) | VG-005, `@third_party` data classes, `data_location` | CI + runtime |
| **OUTS-14** Oversight | s.14 (paras 100-105) | `ict.audit` log, review expiry (VG-006) | Runtime + CI |
| **OUTS-15** Exit | s.15 (paras 106-108); DORA Art.28(8) | `exit_plan` file required (VG-006), fail-closed `HELD_FOR_REVIEW` path | CI + code |
| **OUTS-09 / ICT-3.5** Continuity, operations | EBA/GL/2019/02 s.9 (paras 48-49); EBA/GL/2019/04 s.3.5 (paras 50-60) | Timeouts, fail-closed orchestrator, `ICT-Vendor-Resilience` check | CodeRabbit + tests |
| **ICT-3.3.3** Classification | EBA/GL/2019/04 s.3.3.3 (paras 17-21) | Data-class taxonomy in the register, VG-005 | CI + runtime |
| **ICT-3.4.2** Logical security | s.3.4.2 (paras 31-32) | `egress.py` is the only outbound path (VG-003), per-vendor host allowlist | CI + runtime |
| **ICT-3.4.5** Security monitoring | s.3.4.5 (paras 38-40) | Audit log of allow and deny decisions | Runtime |
| **ICT-3.6.2** Acquisition and development | s.3.6.2 (paras 67-74) | Approved libraries and SDKs (VG-002) | CodeRabbit + CI |
| **ICT-3.6.3** Change management | s.3.6.3 (paras 75-76) | CODEOWNERS, `request_changes_workflow`, `ICT-Register-Change-Control` | Process + CodeRabbit |

## 2. Rule reference (vendor_guard)

| Rule | Detects | Controls cited |
|---|---|---|
| VG-001 | Host not in register, or host belongs to a different vendor than declared | OUTS-12.2, OUTS-12.3, OUTS-11 |
| VG-002 | SDK/library not approved (code imports and requirements) | ICT-3.6.2, OUTS-12.3 |
| VG-003 | Direct HTTP/socket/SMTP use outside `egress.py`; endpoint from env/config | ICT-3.4.2, ICT-3.4.5 |
| VG-004 | External endpoint used without `@third_party` declaration | OUTS-11 |
| VG-005 | Data class sent to vendor not approved for it | ICT-3.3.3, OUTS-13.2, OUTS-12.2 |
| VG-006 | Vendor record incomplete, review expired, exit plan missing | OUTS-11, OUTS-14, OUTS-15 |

`tests/test_traceability.py` fails the build if any rule or the CodeRabbit config cites a control ID that
does not exist in the digest.

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
