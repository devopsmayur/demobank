# EBA ICT & Outsourcing Guidelines – Control Digest for Code Review

> **What this file is.** An internal, paraphrased digest of the requirements in
> **EBA/GL/2019/02** (Guidelines on outsourcing arrangements) and **EBA/GL/2019/04**
> (Guidelines on ICT and security risk management), organised as reviewable controls with stable IDs.
> It is **not** the official text and is not legal advice. Always read the source documents.
>
> **Verification status.** Section titles and paragraph ranges were checked against the published
> tables of contents of both guidelines. The wording below is our own summary. DORA cross-references
> (Regulation (EU) 2022/2554) were written from memory and must be verified before external use.
> For DORA-scope entities, DORA and its RTS now govern ICT third-party risk; these controls remain a
> useful baseline and still apply to non-ICT outsourcing.
>
> **How it is used.**
> - `.coderabbit.yaml` registers this file as a review guideline and tells CodeRabbit to cite control IDs.
> - `tools/vendor_guard.py` reads the **Source** line of each control below and prints it with every finding.
> - `tests/test_traceability.py` fails the build if a rule cites a control ID that is missing here.
>
> **Citation format for reviewers and tools:** `<CONTROL-ID> (<guideline> s.<section>, paras <range>) – see EBA_ICT_OUTSOURCING_CONTROLS.md`
>
> **Official sources:** EBA Guidelines on outsourcing arrangements (EBA/GL/2019/02) and EBA Guidelines on
> ICT and security risk management (EBA/GL/2019/04), published on eba.europa.eu. Check the EBA site for
> the current consolidated versions.

---

# Part A – Outsourcing (EBA/GL/2019/02)

### OUTS-04 — Identify critical or important functions
- **Source:** EBA/GL/2019/02 s.4 (paras 29-31)
- **Requirement:** Decide whether the outsourced function is critical or important, because the strictest controls apply to those.
- **Reviewer signals:** A new vendor in a payment, screening, authentication or ledger path with no `criticality` recorded in the register.
- **Repo evidence:** `criticality` field in `governance/approved-vendors.yaml`.
- **DORA cross-ref (verify):** Art. 28(4)(a).

### OUTS-07 — Outsourcing policy and ownership
- **Source:** EBA/GL/2019/02 s.7 (paras 41-44)
- **Requirement:** A documented policy with clear responsibilities for the outsourcing lifecycle.
- **Reviewer signals:** Vendor-register or integration changes that bypass the owning teams.
- **Repo evidence:** `.github/CODEOWNERS`, the register as the policy artefact.

### OUTS-09 — Business continuity for outsourced services
- **Source:** EBA/GL/2019/02 s.9 (paras 48-49)
- **Requirement:** Continuity plans must cover failure or disruption of an outsourced service.
- **Reviewer signals:** Outbound vendor calls without timeouts; removal of retries, fallbacks or the fail-closed path for a critical vendor; code that releases a payment when a control vendor is unavailable (fail-open); tests that assert fail-closed behaviour being deleted or rewritten to match a weaker behaviour; raised timeouts.
- **Repo evidence:** `PaymentOrchestrator` fail-closed handling and its tests.

### OUTS-11 — Register of outsourcing arrangements
- **Source:** EBA/GL/2019/02 s.11 (paras 52-60)
- **Requirement:** Keep an up-to-date register of all outsourcing arrangements, distinguishing critical or important ones, with supporting documentation retained for ended arrangements.
- **Reviewer signals:** Any new external host, SDK or service not in the register; an external call not declared with `@third_party`; register entries missing required fields.
- **Repo evidence:** `governance/approved-vendors.yaml`, `tools/export_register.py`, `@third_party` declarations.
- **DORA cross-ref (verify):** Art. 28(3) register of information.

### OUTS-12.2 — Risk assessment before outsourcing
- **Source:** EBA/GL/2019/02 s.12.2 (paras 64-68)
- **Requirement:** Assess the risks of an arrangement before entering it, including sensitivity of the data and impact of disruption.
- **Reviewer signals:** New data fields or data classes sent to a vendor; a new vendor integration with no linked assessment ticket.
- **Repo evidence:** `assessment_ticket`, `data_classes` in the register.
- **DORA cross-ref (verify):** Art. 28(4)(c).

### OUTS-12.3 — Due diligence on the provider
- **Source:** EBA/GL/2019/02 s.12.3 (paras 69-73)
- **Requirement:** Confirm the provider is suitable before contracting, and not only at onboarding.
- **Reviewer signals:** Integration code or dependencies for a provider that has no approved register entry; register entries whose `next_review` has passed.
- **Repo evidence:** `approved_on`, `next_review`, `assessment_ticket` in the register.
- **DORA cross-ref (verify):** Art. 28(4)(d).

### OUTS-13.1 — Sub-outsourcing of critical or important functions
- **Source:** EBA/GL/2019/02 s.13.1 (paras 76-80)
- **Requirement:** Know and control the subcontractors that a critical or important provider relies on.
- **Reviewer signals:** A vendor entry for a critical function with no `subcontractors` information.
- **Repo evidence:** `subcontractors` in the register.

### OUTS-13.2 — Security of data and systems
- **Source:** EBA/GL/2019/02 s.13.2 (paras 81-84)
- **Requirement:** Data and systems exposed to a provider must be protected, with security requirements set for the arrangement and the data location understood.
- **Reviewer signals:** Sensitive fields (IBAN, name, e-mail, address, account identifiers) in vendor payloads or application logs beyond what is approved, even when the @third_party declaration itself looks correct; unencrypted transport; new data location or region.
- **Repo evidence:** `data_classes`, `data_location`, per-vendor data-class check in `@third_party`.

### OUTS-14 — Ongoing oversight of outsourced functions
- **Source:** EBA/GL/2019/02 s.14 (paras 100-105)
- **Requirement:** Monitor the provider's performance and risk on an ongoing basis.
- **Reviewer signals:** Removal of logging or audit trail for external calls; stale register reviews.
- **Repo evidence:** `ict.audit` log in `payment_service/egress.py`, `next_review` check.

### OUTS-15 — Exit strategies
- **Source:** EBA/GL/2019/02 s.15 (paras 106-108)
- **Requirement:** Documented and feasible exit plans for critical or important outsourced functions, including stressed exit.
- **Reviewer signals:** A critical vendor without an `exit_plan` file; code that hard-couples the business flow to one provider with no manual or alternative route.
- **Repo evidence:** `docs/exit/*.md`, `HELD_FOR_REVIEW` path in the orchestrator.
- **DORA cross-ref (verify):** Art. 28(8).

---

# Part B – ICT and security risk management (EBA/GL/2019/04)

### ICT-3.3.3 — Classification and risk assessment of information assets
- **Source:** EBA/GL/2019/04 s.3.3.3 (paras 17-21)
- **Requirement:** Classify information and ICT assets by criticality and sensitivity, and assess risk accordingly.
- **Reviewer signals:** Data of a higher classification flowing to a system or vendor approved only for lower classes.
- **Repo evidence:** `data_classes` taxonomy in the register, `@third_party(..., [data classes])`.

### ICT-3.4.2 — Logical security
- **Source:** EBA/GL/2019/04 s.3.4.2 (paras 31-32)
- **Requirement:** Restrict access to data and systems, including electronic access by applications, to the minimum required for the service.
- **Reviewer signals:** Direct use of HTTP, socket or SMTP clients outside the approved egress module; endpoints taken from environment variables or config files; widening of a vendor's hosts or data classes; infrastructure rules that open egress to 0.0.0.0/0.
- **Repo evidence:** `payment_service/egress.py` as the only outbound path, per-vendor host allowlist.
- **DORA cross-ref (verify):** Art. 9.

### ICT-3.4.5 — Security monitoring
- **Source:** EBA/GL/2019/04 s.3.4.5 (paras 38-40)
- **Requirement:** Monitor for anomalies and security events so they can be detected and handled.
- **Reviewer signals:** New outbound destinations that would not appear in the audit log; removal of audit logging.
- **Repo evidence:** `ict.audit` logger records allow and deny decisions.

### ICT-3.5 — ICT operations management
- **Source:** EBA/GL/2019/04 s.3.5 (paras 50-60)
- **Requirement:** Run ICT operations on documented processes with monitoring, and handle incidents and problems systematically.
- **Reviewer signals:** Missing timeouts and error handling on external calls; swallowed exceptions that hide vendor failures or governance denials.
- **Repo evidence:** Orchestrator error handling, `EgressDenied` is never treated as an outage.

### ICT-3.6.2 — ICT systems acquisition and development
- **Source:** EBA/GL/2019/04 s.3.6.2 (paras 67-74)
- **Requirement:** A risk-based process for acquiring, developing and maintaining ICT systems, with security requirements defined before acquisition.
- **Reviewer signals:** New third-party libraries or SDKs that are not on the approved list; unpinned or unreviewed dependencies.
- **Repo evidence:** `libraries` and vendor `sdk` entries in the register, requirements check.

### ICT-3.6.3 — ICT change management
- **Source:** EBA/GL/2019/04 s.3.6.3 (paras 75-76)
- **Requirement:** Changes to ICT systems are recorded, assessed, tested and approved before release.
- **Reviewer signals:** Control changes (register, egress module, governance code) without the expected approvers or ticket reference.
- **Repo evidence:** `.github/CODEOWNERS`, branch protection, `ICT-Register-Change-Control` check.

### ICT-3.7 — Business continuity management
- **Source:** EBA/GL/2019/04 s.3.7
- **Requirement:** Continuity and response plans for ICT disruption, including dependencies on third parties.
- **Reviewer signals:** As OUTS-09.
- **Repo evidence:** As OUTS-09.
