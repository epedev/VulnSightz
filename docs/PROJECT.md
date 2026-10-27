# Project summary

**Name:** VulnSight (epedev/VulnSightz)  
**Type:** Modular authorized web vulnerability scanner (CLI)  
**Group:** Group 3  
**License:** MIT  
**Language:** Python 3.10+

## Group 3 members

| Student name |
|--------------|
| Kenean Amare Eshetu |
| Kenneti Hailu Dange |
| Kidsit Ephrem |
| Alazar Elias Digafe |
| Firaol Mustefa Gossa |

## Purpose

VulnSight demonstrates a complete, ethically constrained scanning pipeline suitable for academic evaluation: explicit authorization, reconnaissance, multi-class detection, and professional reporting.

## Deliverables

1. Integrated CLI (`vulnsight`) orchestrating all modules
2. Independent member modules with shared finding contracts
3. HTML, Markdown, PDF, and JSON assessment reports
4. Documentation for installation, usage, architecture, and demo
5. Automated tests (`pytest`)

## Typical demonstration flow

1. Install and run `vulnsight doctor`
2. Start an authorized local target website
3. `vulnsight init-project -o myproject.json --target http://127.0.0.1:PORT`
4. `vulnsight scan --project myproject.json`
5. Present `reports/vulnsight_report.html` (and PDF/Markdown downloads)

## Out of scope

- Production or internet-facing deployment of the optional training lab
- Unauthorized or external scanning without explicit operator consent
- Guaranteed complete coverage of all vulnerability classes
