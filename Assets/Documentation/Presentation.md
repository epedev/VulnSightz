# VulnSight

**Modular Web Vulnerability Assessment Tool**
INSA Summer Camp · Graduation Project

| Group Member | ID |
|---|---|
| Kenean Amare Eshetu | CTC-4837-26 |
| Kenneti Hailu Dange | CTC-535-26 |
| Kidsit Ephrem Zemede | CTC-6744-26 |
| Firaol Mustefa Gossa | CTC-4301-26 |
| Alazar Elias Digafe | CTC-631-26 |

---

## The Problem: Security checks live in separate scripts

- **Results are hard to compare**: Each script reports in its own shape.
- **Unclear which checks ran**: A skipped check looks like a clean result.
- **Evidence is stored unevenly**: Reviewers cannot trace a finding back.
- **Limitations go unexplained**: Readers over-trust the output.

VulnSight brings **reconnaissance, detection, and reporting** behind one command-line interface, so each stage can be studied on its own.

---

## Aim and Objectives: One tool, three jobs

Design a modular, command-line tool that supports controlled security testing and produces structured, reviewable findings for education.

- **Run**: A command-line entry point, a project file that records authorization, and loopback-first scope rules.
- **Detect**: Selected checks for XSS, SQL injection, command injection, access control, and security hygiene, fed by a crawler.
- **Report**: One finding format with deduplication, redaction, CVSS context, and JSON, HTML, Markdown, and PDF output.

---

## Architecture: How it is built

1. **CLI and project file**: Commands, options, authorization record
2. **Scope controls**: Loopback first; external targets need explicit approval
3. **Crawler**: Same-origin pages and input points, within limits
4. **Detection modules**: XSS, SQL injection, command injection, access control, hygiene
5. **Reporting**: Normalize, deduplicate, redact, add risk context, write reports

---

## One Scan, Step by Step: From command to report

| Step | Stage | Description |
|---|---|---|
| 01 | Configure | CLI and project file |
| 02 | Validate | Target and scope rules |
| 03 | Crawl | Build the crawl map |
| 04 | Detect | Five selected modules |
| 05 | Combine | One set of results |
| 06 | Normalize | Classify, dedupe, redact |
| 07 | Add context | Risk and remediation |
| 08 | Report | JSON, HTML, Markdown, PDF* |

\* PDF output is optional and needs an installed backend.

---

## Detection Modules: Five bounded checks

| Module | What it does |
|---|---|
| **XSS** | Marker reflection, context analysis, optional browser check |
| **SQL injection** | Auth-bypass behavior and database error signatures |
| **Command injection** | Controlled output marker in the response |
| **Access control** | IDOR-style routes checked with test identities |
| **Security hygiene** | Headers, cookie flags, CSRF tokens, open redirects |

A hit is an indicator to review, **not proof of exploitability**.

---

## Reporting: Every finding answers three questions

- **Severity**: How serious could the issue be in context?
- **Confidence**: How strong is the evidence that the behavior is relevant?
- **Verification**: Confirmed, probable, or still a candidate?

Pipeline: Normalize → Classify → Deduplicate → Redact → Add risk context

CVSS v3.1 is added only when a defensible vector exists. Otherwise the finding stays unscored rather than getting invented metrics.

---

## Running It: Four commands, one workflow

```bash
$ vulnsight doctor
$ vulnsight init-project \
  -o myproject.json \
  --target http://127.0.0.1:5001 \
  --name "Local Training Lab"
$ vulnsight scan --project myproject.json
$ vulnsight compare \
  --current reports/findings.json \
  --baseline fixtures/secure_baseline_findings.json \
  --output reports
```

- **Loopback first**: Start with a local target such as `http://127.0.0.1:5001`.
- **Authorization is recorded**: The project file needs `authorization.authorized_by` filled in before a scan.
- **Bring your own target**: We do not ship a vulnerable app; you supply an authorized one.

---

## Validation and Coverage: How we checked our work

**Test suites cover:** CLI, Project config, Scope rules, Orchestrator, Comparison, Crawler, XSS, SQL injection, Command injection, Access control, Misconfiguration, Reporting

```bash
$ python -m pytest
```

`[N] passed` · `[N] skipped` · `[N] failed` — Run on [date], Python [version]

**OWASP mapping:** Top 10:2025, with a 2021 continuity mapping.

A zero count means no matching finding within the configured scope. It does not mean the category is safe.

---

## Limitations: What we state up front

- **Bounded coverage**: Detectors target selected patterns and known application behaviors.
- **False and missed hits**: Heuristics can flag inert behavior or miss stateful, authenticated, or JavaScript-driven issues.
- **Crawler reach**: Unlinked, authenticated-only, or dynamic routes may never be tested.
- **Access control**: The scanner cannot infer every intended authorization rule.
- **Partial runs**: Skipped or failed modules reduce coverage and are disclosed in the report.
- **Optional bundled lab**: `vulnerable-target-app/` is included for training; operators may also bring their own authorized target.

---

## Read Results With Care

# No findings does not mean secure.

Check the module status, the coverage limits, and the evidence before drawing conclusions. A scanner only reports on what it tests and the scope it reaches.

---

## Where It Fits: We do not replace the established tools

- **OWASP ZAP**: Mature open-source testing platform with a broader ecosystem.
- **Burp Scanner**: Part of an established professional testing workflow.
- **Nikto**: Web-server assessment with configuration and file checks.
- **OWASP WSTG**: A testing methodology and reference, not a scanner.

> **Our value:** A compact Python implementation that students can read and explain end to end.
> We have not run a formal benchmark, so we claim no accuracy or speed advantage.

---

## Next Steps: What we would build next

### Cover more
- Integration tests across representative local targets
- More detector coverage, with each check's scope kept explicit
- Authenticated crawling and stateful workflows
- Stronger schema validation between modules and reports

### Prove and maintain
- Repeatable benchmarks with published comparisons
- Per-module limitation and compatibility notes
- Continuous integration for tests, formatting, packaging, and doc links
- Ongoing review of report rendering and redaction

---

## Thank you

*VulnSight · INSA Summer Camp · Group 3*
