# Authors

VulnSight is developed by **Group 3** as a collaborative graduation project.

## Group 3 members

| Student name | Student ID | Primary ownership |
|--------------|------------|-------------------|
| Kenean Amare Eshetu | CTC-4837-26 | SQL injection & command injection (`sqli_&_command_module/`) |
| Kenneti Hailu Dange | CTC-535-26 | XSS detection (`xss_module/`) |
| Kidsit Ephrem | CTC-6744-26 | Documentation (`docs/`) |
| Alazar Elias Digafe | CTC-631-26 | Reconnaissance / crawler (`Crawler/`) |
| Firaol Mustefa Gossa | CTC-4301-26 | Access control (`access_control_module/`) |

## Integrated platform modules

| Area | Path | Notes |
|------|------|-------|
| CLI / orchestration | `vulnsight/` | Shared scan pipeline |
| Security hygiene | `misconfig_module/` | Headers, cookies, CSRF, redirect, disclosure |
| Reporting & scoring | `reporting_module/` | CVSS, OWASP Top 10:2025, HTML / MD / PDF / JSON |
| Cross-module tests | `tests/` | Unit and optional live lab tests |

Repository: [epedev/VulnSightz](https://github.com/epedev/VulnSightz)
