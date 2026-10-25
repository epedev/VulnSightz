# VulnSight — Project Documentation (Group 3)

**Project:** VulnSight — Modular Web Vulnerability Assessment Tool · **Type:** INSA Summer Camp Graduation Project · **Version:** 0.2.0 · **License:** MIT

## 1. Executive Summary

VulnSight is a Python command-line tool that we, Group 3, built to run selected web-application security checks against a target that the operator owns or is explicitly authorized to assess. It combines reconnaissance, selected vulnerability-detection modules, finding normalization, risk context, and report generation in one workflow.

We developed it as our INSA Summer Camp graduation project (version 0.2.0, Python 3.10+, MIT license). Its main value is educational: it shows how separate scanner modules can cooperate, how their observations become a common finding format, and how technical results can be presented for review and remediation.

We want to be clear about what VulnSight is not. It is not a complete penetration-testing platform, and it cannot guarantee that an application is secure. We did not include a deliberately vulnerable target website, so the operator must prepare a local lab or provide another explicitly authorized target. We recommend starting with a loopback target such as `http://127.0.0.1:5000`.

## 2. Background and Problem Statement

A web-security assessment involves several distinct tasks: discovering reachable pages, identifying input points, testing selected vulnerability classes, recording evidence, assessing risk, removing duplicate findings, and producing a report that developers can act on.

When these tasks are done with disconnected scripts, results are hard to compare, it is unclear which checks actually ran, evidence is stored inconsistently, and limitations go unexplained. This is a particular problem in an academic setting, where the implementation itself should be understandable and reviewable.

We built VulnSight to address this workflow problem. We brought selected checks and reporting stages together behind one command-line interface, and we separated reconnaissance, detection, orchestration, and reporting so each component can be studied and maintained on its own.

## 3. Project Aim and Objectives

### 3.1 Aim

Our aim was to design and implement a modular, command-line web vulnerability assessment tool that supports controlled security testing and produces structured, reviewable findings for educational use.

### 3.2 Objectives

To meet that aim, we set out to:

- Provide a command-line entry point for configuring and running assessments.
- Record target and authorization information in a project configuration file.
- Discover same-origin pages and input points through a crawler.
- Implement selected checks for cross-site scripting (XSS), SQL injection, operating-system command injection, access-control weaknesses, and selected security-hygiene issues.
- Convert module output into a common reporting structure.
- Add deduplication, classification, remediation guidance, redaction, and CVSS-related risk context where the available evidence supports them.
- Produce machine-readable and human-readable assessment artifacts.
- Support a secure-baseline comparison workflow for controlled demonstrations.
- Provide tests, fixtures, architecture notes, and module-specific documentation.
- Make scope restrictions, uncertainty, and limitations visible, rather than presenting automated results as a security guarantee.

## 4. Scope

We drew the scope deliberately narrow, so that what VulnSight claims matches what it actually does.

### 4.1 Included capabilities

- Project-file creation and validation.
- Loopback-first target-scope enforcement.
- Same-origin reconnaissance and crawl-map generation.
- Selected XSS, SQL injection, command-injection, access-control, and security-hygiene checks.
- A shared finding model and a reporting pipeline.
- Severity classification and CVSS v3.1-related processing where applicable.
- Deduplication that preserves finding provenance.
- HTML, Markdown, and JSON report generation, with optional PDF output depending on installed dependencies and available backends.
- OWASP Top 10:2025 mapping, with a 2021 continuity mapping in the reporting documentation and implementation.
- A command-line comparison of current findings against a baseline finding set.
- Unit, safety, smoke, and optional integration-test files.

### 4.2 Out of scope

VulnSight is not designed to:

- Replace a full manual penetration test, secure code review, or professional security assessment.
- Guarantee detection of every vulnerability or certify that a target is secure.
- Understand every application's business logic, role model, authentication flow, or authorization policy.
- Test every OWASP category comprehensively.
- Include or deploy a deliberately vulnerable target application.
- Authorize scanning of a system merely because the crawler discovered it.
- Serve as a production-grade security assurance platform without additional validation and hardening.

## 5. Intended Users and Use Cases

We designed VulnSight for students, educators, and developers working in controlled security-learning environments, or performing explicitly authorized assessments.

Typical use cases are:

1. Running a scan against a deliberately prepared local training application.
2. Demonstrating how crawler output feeds the detection modules.
3. Reviewing how a raw module observation becomes a normalized finding.
4. Comparing findings from a current run with a secure-baseline fixture.
5. Inspecting HTML or Markdown reports and reviewing suggested remediation.
6. Studying module boundaries, test cases, scope controls, and reporting behavior as part of cybersecurity education.

## 6. System Architecture

We organized VulnSight as a modular Python repository, coordinated by the `vulnsight` command-line interface and orchestrator. A scan flows through these stages:

1. The operator configures the run through the CLI and a project configuration file.
2. The tool validates the target and applies scope rules.
3. Reconnaissance builds a crawl map, or the operator supplies an existing one.
4. The selected detection modules (XSS, SQL injection, command injection, access control, security hygiene) run against the discovered inputs.
5. Their observations are combined into one set of module results.
6. The reporting layer normalizes, classifies, deduplicates, and redacts the findings.
7. Risk context and remediation guidance are added.
8. The tool writes JSON, HTML, and Markdown reports, plus PDF when a backend is installed.

### 6.1 Main architectural layers

**Command-line interface (`vulnsight/`).** Parses commands and options, checks project configuration, builds the scan configuration, invokes the orchestrator, and presents status and error information.

**Project and scope controls (`vulnsight/project.py`, `vulnsight/scope.py`).** Load the project JSON, validate authorization fields, normalize target information, and apply the project's scope rules. The default mode is intended for loopback targets. External or private-network targets require explicit configuration and authorization, and individual modules may impose further restrictions.

**Orchestrator (`vulnsight/orchestrator.py`).** Runs the enabled modules, tracks completed, skipped, and failed module states, collects findings, writes intermediate JSON artifacts, and passes results to the reporting layer. We designed it so that a partial run is never mistaken for full coverage.

**Detection modules.** Each performs checks for its own vulnerability class and returns structured results.

**Reporting layer (`reporting_module/`).** Ingests module results, normalizes fields, classifies findings, deduplicates suitable equivalents, handles redaction, adds risk and remediation context, and generates the report artifacts.

## 7. Module Descriptions

For every module, we state what it checks and also where its evidence stops. We did this on purpose: a detector that overstates its coverage is worse than a narrow one.

### 7.1 CLI, configuration, and orchestration (`vulnsight/`)

The CLI provides commands for version information, environment diagnostics, documentation access, crawl-map validation, project-file initialization, scanning, report generation, and baseline comparison:

- `vulnsight version`
- `vulnsight doctor`
- `vulnsight docs`
- `vulnsight validate-input --file <crawl-map.json>`
- `vulnsight init-project`
- `vulnsight scan`
- `vulnsight report`
- `vulnsight compare`

The orchestrator records module status and errors. It can keep reporting findings from modules that completed even if another module fails. In that case the report is incomplete, and the module-status details must be reviewed.

### 7.2 Reconnaissance and crawler (`Crawler/`)

The crawler starts from a configured seed URL and discovers same-origin pages and links within configured limits. It applies scope checks and generates a crawl map that the detection modules consume.

The crawl map is an input-discovery artifact, not proof that every route was found. Unlinked routes, authenticated-only pages, JavaScript-heavy flows, and workflows that need special state may be missed. Crawling a URL never expands the operator's authorization.

### 7.3 Cross-site scripting (`xss_module/`)

Our XSS module performs marker-based reflection checks, context analysis, and optional active or browser-assisted verification. It can consume a crawl map and produces structured findings with evidence and verification information.

Reflection alone does not prove script execution is possible. Encoded or inert reflections can produce candidate findings, and complex DOM-based behavior or application-specific flows may be missed. Browser verification needs optional Playwright support and is not enabled by default in every workflow. The DOM-XSS helpers are documented as experimental and are not part of the core pipeline.

### 7.4 SQL injection (`sqli_&_command_module/sqli/`)

The SQL injection detector uses selected application behaviors, such as authentication-bypass behavior and database error signatures, to identify potential SQL-injection issues.

These are bounded checks, not universal detection. Database error text, or a response that differs from expectations, is an indicator that needs contextual review. It is not automatic proof of exploitability.

### 7.5 Operating-system command injection (`sqli_&_command_module/command_injection/`)

The command-injection detector checks selected command-like inputs and looks for a controlled output marker in the response. The checks are tailored to documented training-application patterns.

An echoed marker is evidence of the behavior that specific check tested, not proof that all command-injection paths were found. Applications should avoid unnecessary shell execution, use safe argument handling, and validate inputs on the server side.

### 7.6 Access control and IDOR (`access_control_module/`)

This module checks for insecure direct object reference (IDOR)-style access and selected broken-access-control behavior. Its documented checks use known training routes such as `/profile/<id>` and `/admin`, with expected test identities.

The checks depend on the target's routes, test accounts, session behavior, and authorization rules. An HTTP 200 is not sufficient evidence in every application, because the resource's intended access policy and returned content must be verified. This is a targeted training-app model, not a universal authorization scanner.

### 7.7 Security hygiene and misconfiguration (`misconfig_module/`)

The security-hygiene module checks selected configuration signals:

- Presence of common security headers.
- Session-cookie attributes such as `HttpOnly`, `Secure`, and `SameSite`.
- Forms that appear to lack CSRF tokens.
- Open-redirect candidates.
- Additional signals described by the detector and OWASP mapping, such as selected transport, disclosure, or SSRF-related indicators.

These checks inspect observable signals only. A missing header is not always an exploitable vulnerability, and a scanner cannot reliably infer every application's security requirements from a response. These findings need contextual review.

### 7.8 Reporting and risk context (`reporting_module/`)

The reporting subsystem turns module observations into consistent, reviewable output. It covers:

- Ingestion of module-specific JSON results.
- Normalization to a canonical finding schema.
- Classification and severity context.
- Deduplication that retains provenance.
- Redaction of common sensitive-data patterns.
- Remediation guidance.
- CVSS v3.1 processing when a defensible vector is available.
- OWASP Top 10 mapping and coverage summaries.
- HTML, Markdown, JSON, and optional PDF report generation.

Severity, confidence, and verification status are distinct concepts. A CVSS value is not proof of exploitation. When no defensible vector exists, we let a finding stay unscored rather than invent missing metrics. Operational priority is also distinct from CVSS severity.

## 8. Finding Data Flow and Reporting

Our detection modules return structured observations, and the reporting pipeline converts them into canonical findings so that results from different modules can be reviewed together.

The canonical report structure includes fields for metadata, summary, findings, issues, limitations, modules executed, modules not executed, incomplete status, and output paths. Each finding can include:

- Identifier and title.
- Vulnerability type and source module.
- URL, HTTP method, parameter, and location.
- Description, evidence, and impact.
- Severity, confidence, and verification status.
- CWE or OWASP mapping where available.
- CVSS version, vector, score, status, and provenance where applicable.
- Remediation suggestions.
- Timestamp and source provenance.
- Warnings and deduplication information.

We kept three questions separate throughout:

- **Severity:** how serious could the issue be in context?
- **Confidence:** how strong is the evidence that the behavior is relevant?
- **Verification status:** has the issue been confirmed, or does it remain probable or a candidate?

A report with no findings does not establish that the application is secure. Readers should check the module statuses, coverage limitations, evidence, and target context before drawing conclusions.

## 9. Technology Stack and Dependencies

We declared Python 3.10 or newer and used `pyproject.toml` for package configuration.

| Technology / dependency | Purpose |
| --- | --- |
| Python | Main implementation language |
| Requests | HTTP requests for crawling and checks |
| Beautiful Soup 4 | HTML parsing |
| Flask | Used by project dependencies and training/test-related workflows |
| Jinja2 | HTML report templating |
| `cvss` | CVSS scoring support |
| pytest | Automated tests |
| Playwright (optional) | Browser-assisted XSS verification |
| WeasyPrint and ReportLab (optional) | PDF report generation backends |
| lxml (optional) | Faster HTML parsing where available |

The optional dependency groups are `dev`, `browser`, `pdf`, and `fastparse`. Exact requirements are defined in `pyproject.toml` and in module-specific requirement files. PDF and browser functionality depend on the relevant packages and any required system dependencies.

## 10. Installation and Setup

Run these commands from the project repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
vulnsight doctor
```

On Windows PowerShell, activate the environment with:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install optional functionality only when needed:

```bash
python -m pip install -e ".[browser]"
playwright install chromium

python -m pip install -e ".[pdf,fastparse]"
```

The repository's interactive documentation opens with `vulnsight docs`. For installation troubleshooting, see `docs/INSTALLATION.md` and `docs/TROUBLESHOOTING.md`.

## 11. Typical Assessment Workflow

### Step 1: Prepare an authorized target

Start a web application that you own or are explicitly permitted to test. We recommend a local loopback address, for example `http://127.0.0.1:5001`. VulnSight does not provide a vulnerable target application.

### Step 2: Check the environment

```bash
vulnsight doctor
```

Resolve any missing required dependency or project-directory issue the diagnostic reports.

### Step 3: Create a project configuration

```bash
vulnsight init-project \
  -o myproject.json \
  --target http://127.0.0.1:5001 \
  --name "Local Training Lab"
```

Review the generated JSON and complete the required authorization information, including `authorization.authorized_by`. The project loader requires an explicit authorization attestation. The file records the operator's declaration; it does not independently prove legal permission.

### Step 4: Run the scan

```bash
vulnsight scan --project myproject.json
```

For direct loopback testing without a project file, the CLI also supports a target option:

```bash
vulnsight scan --target http://127.0.0.1:5001 --output ./reports -v
```

We prefer the project-file workflow because it records authorization and target configuration. `docs/USAGE.md` covers the available options, module selection, scan budgets, and use of an existing crawl map.

### Step 5: Review the results

Inspect the report artifacts and per-module status information. Confirm whether each module completed, failed, or was skipped. Verify candidate findings against the application's behavior, and review the remediation advice before treating a finding as confirmed.

### Step 6: Compare with a baseline when appropriate

```bash
vulnsight compare \
  --current reports/findings.json \
  --baseline fixtures/secure_baseline_findings.json \
  --output reports
```

This compares finding sets for a controlled demonstration. It does not prove that the current target is free of vulnerabilities.

## 12. Output Artifacts

Depending on the command, scan result, requested formats, and installed dependencies, the output directory may contain:

| Artifact | Purpose |
| --- | --- |
| `crawl_map.json` | Pages and input points discovered by reconnaissance |
| `findings_xss.json` | XSS module results |
| `findings_sqli.json` | SQL injection module results |
| `findings_command_injection.json` | Command-injection module results |
| `findings_access_control.json` | Access-control module results |
| `findings_misconfig.json` | Security-hygiene module results |
| `findings_raw.json` | Combined pre-normalization module observations and status information |
| `findings.json` | Stable alias for the generated canonical JSON findings report, when available |
| `vulnsight_report.html` | Browser-readable assessment report |
| `vulnsight_report.md` | Portable Markdown report |
| `vulnsight_report.pdf` | Printable PDF report, when a supported backend is available |

Not every artifact exists after every run, so check the CLI output, module status, and generated files. Reports can contain sensitive endpoints, evidence, or configuration details and should be protected accordingly.

## 13. OWASP Mapping

Our reporting code and documentation include an OWASP Top 10:2025 mapping and a 2021 continuity mapping. The mapping associates selected detector signals with relevant categories, so readers can interpret coverage.

It is not a compliance certificate, and it does not mean every category is comprehensively tested. Some categories have only limited signal-based coverage, and others are not dynamically tested by this project. A zero count in a category means the scan produced no matching finding within its configured scope. It does not mean the category is safe.

See `docs/OWASP_TOP10.md` for the category-level mapping and the stated coverage boundaries.

## 14. Testing and Quality Assurance

Our repository contains test suites for the CLI, project configuration, scope enforcement, orchestrator behavior, comparison logic, the crawler, XSS, SQL injection, command injection, access control, misconfiguration, and reporting.

Run the configured suite from the repository root:

```bash
python -m pytest
```

Some live integration tests need an authorized local target and the configuration described in the test documentation. Active tests must never be run against a public system without explicit authorization.

The presence of tests is not proof that every feature is correct. For a credible validation record, we document the environment, installed optional dependencies, command used, result, and any skipped or failing tests. When a scan has module failures, we treat its coverage as partial even if other modules produced useful findings.

### 14.1 Recorded test run

| Item | Value |
| --- | --- |
| Date of run | [fill in] |
| Operating system | [fill in] |
| Python version | [fill in] |
| Optional dependencies installed | [fill in: browser / pdf / fastparse / none] |
| Command | `python -m pytest` |
| Passed | [fill in] |
| Skipped (and why) | [fill in] |
| Failed | [fill in] |

## 15. Security, Ethics, and Data Handling

We intend VulnSight only for authorized assessment and cybersecurity education. Our rules for anyone using it:

- Test only systems you own or have explicit written permission to assess.
- Prefer loopback or local targets for coursework and demonstrations.
- Define the authorized scope before scanning.
- Do not treat crawler-discovered URLs as permission to test them.
- Use external or private-network target options only when the assessment is explicitly authorized and the relevant module supports that target.
- Be aware that active checks may affect target behavior, logs, or availability.
- Protect scan reports, and redact sensitive evidence before sharing them.
- Never commit production credentials, session cookies, tokens, or sensitive scan reports.
- Verify results safely and follow the target owner's remediation process.

The root `SECURITY.md` describes authorized use and how to report security issues in VulnSight; `docs/SECURITY.md` gives project-specific guidance. If a vulnerability is found in VulnSight itself, use the project's private disclosure route rather than publishing exploit details prematurely.

## 16. Known Limitations and Residual Risk

We state these limitations openly, and they should accompany any interpretation of VulnSight's results:

1. **Bounded detection coverage:** our detectors focus on selected patterns and known application behaviors.
2. **False positives and false negatives:** heuristics may report inert behavior, or miss issues that need complex state, JavaScript execution, authentication, or business context.
3. **Crawler coverage:** routes that are unlinked, authenticated-only, dynamically generated, or outside configured budgets may not be tested.
4. **Application-specific access control:** the scanner cannot infer every intended authorization rule.
5. **Signal-based misconfiguration checks:** a missing header or unusual response needs contextual interpretation.
6. **Partial execution:** skipped or failed modules reduce coverage and must be disclosed.
7. **Optional output dependencies:** PDF generation and browser-assisted verification may be unavailable until dependencies are installed.
8. **No bundled target:** operators must supply and configure their own authorized test application.
9. **No guarantee of security:** the absence of findings is not proof that a target is secure.

These limitations are part of our design context, and we include them in demonstrations and reports.

## 17. Repository Structure

| Path | Responsibility |
| --- | --- |
| `vulnsight/` | CLI, project configuration, scope handling, orchestration, comparison, and terminal UI |
| `Crawler/` | Same-origin crawling, scope logic, crawl-map schema, and tests |
| `xss_module/` | XSS engine, reflection/context analysis, verification helpers, finding models, and tests |
| `sqli_&_command_module/` | SQL injection and command-injection detectors, guidance, and tests |
| `access_control_module/` | IDOR and broken-access-control checks and tests |
| `misconfig_module/` | Security-hygiene and misconfiguration checks and tests |
| `reporting_module/reporting/` | Ingestion, normalization, classification, deduplication, risk, CVSS, redaction, remediation, and report rendering |
| `reporting_module/docs/` | Reporting implementation and canonical schema documentation |
| `docs/` | Architecture, usage, installation, threat model, OWASP mapping, demo runbook, and troubleshooting |
| `fixtures/` | Example project, crawl-map, and baseline data |
| `tests/` | CLI, unit, safety, and integration-oriented tests |
| `scripts/` | Demonstration and screenshot helper scripts |
| `AUTHORS.md` | Contributor roster |
| `CHANGELOG.md` | Recorded release history |
| `CONTRIBUTING.md` | Contribution conventions |
| `SECURITY.md` | Authorized-use and vulnerability-reporting policy |
| `LICENSE` | MIT License text |
| `pyproject.toml` | Package metadata, dependencies, CLI entry point, and pytest configuration |

## 18. Team, Contributions, and My Role

VulnSight is our Group 3 graduation project. `AUTHORS.md` holds the contributor roster and student identifiers. We divided ownership across seven areas: reconnaissance, XSS, SQL injection and command injection, access control, security hygiene, reporting, and CLI/orchestration.

When we change something that crosses module boundaries, we coordinate, preserve the shared finding contract, add or update tests, and document new finding types and their limitations. `CONTRIBUTING.md` and `docs/CONTRIBUTING.md` set out our contribution expectations, and before committing we inspect staged changes so only intended files go in.

### 18.1 My contribution

| Item | Detail |
| --- | --- |
| Name | [your full name] |
| Student ID | [as listed in AUTHORS.md] |
| Module(s) I owned | [e.g. xss_module / misconfig_module / reporting_module / Crawler / CLI] |
| What I built | [2–3 specific things: files, functions, checks] |
| A design decision I made and why | [one concrete decision and the trade-off] |
| A bug or problem I solved | [one real example] |
| Tests I wrote | [test files and what they cover] |
| Where my module is weakest | [one honest limitation, in your words] |

## 19. Existing Tools and Project Position

VulnSight overlaps with established web-security testing tools, and we do not claim to replace them.

- **OWASP ZAP** is a mature open-source web-application testing platform with a broader ecosystem.
- **Burp Scanner** is part of an established professional web-security testing workflow.
- **Nikto** focuses on web-server assessment and related configuration or file checks.
- **OWASP Web Security Testing Guide (WSTG)** is a testing methodology and reference, not a directly equivalent scanner.

Our value is that students can read a compact Python implementation that connects reconnaissance, selected detection modules, common finding handling, and report generation, and can explain it end to end. We have not run a formal benchmark, so we make no claim that VulnSight is more accurate, faster, safer, or more comprehensive than these tools. Such a claim would need a documented, repeatable comparative evaluation.

## 20. Future Improvement Opportunities

These are improvements we would pursue next. None is a claim about a feature already completed.

- Expand integration tests across representative local target applications.
- Improve authenticated crawling and support for stateful application workflows.
- Increase detector coverage while keeping each check's scope and evidence explicit.
- Strengthen schema validation and regression tests for module-to-report contracts.
- Add repeatable benchmark scenarios and publish measured comparison results.
- Improve documentation of per-module limitations and configuration compatibility.
- Add continuous integration checks for tests, formatting, packaging, and documentation links.
- Review report rendering and redaction behavior as part of ongoing security maintenance.

## 21. Conclusion and References

VulnSight shows a modular approach to authorized web vulnerability assessment. Our main contribution is integrating reconnaissance, selected detection checks, shared finding processing, and report generation in an inspectable Python project suited to academic learning.

A scanner can only report on the behaviors it tests and the scope it reaches, so results must be read with care. Responsible use, explicit authorization, evidence review, test validation, and clear communication of limitations are part of the project itself, not optional additions.

### Repository references

- `README.md`: installation overview and quick start.
- `docs/PROJECT.md`: project summary and deliverables.
- `docs/ARCHITECTURE.md`: module architecture and contracts.
- `docs/USAGE.md`: CLI workflow and options.
- `docs/INSTALLATION.md`: setup and optional dependencies.
- `docs/MODULE_GUIDE.md`: module-level usage.
- `docs/FINDINGS_SCHEMA.md` and `reporting_module/docs/FINDINGS_SCHEMA.md`: finding data structures.
- `docs/OWASP_TOP10.md`: OWASP category mapping and coverage notes.
- `docs/THREAT_MODEL.md`: assets, trust boundaries, threats, and residual risk.
- `docs/DEMO_RUNBOOK.md`: demonstration workflow.
- `docs/VULNERABLE_TARGET.md`: requirements for providing a target.
- `docs/TROUBLESHOOTING.md`: common setup and execution issues.
- `SECURITY.md` and `docs/SECURITY.md`: authorized use and vulnerability reporting.
- `CONTRIBUTING.md` and `docs/CONTRIBUTING.md`: contribution requirements.
- `CHANGELOG.md`: recorded changes by version.
- `AUTHORS.md`: contributor roster.
- `LICENSE`: license text.
