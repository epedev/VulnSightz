# OS Command Injection Detection

## Scope

This module probes the training lab `/ping` endpoint and crawl-map parameters that look like host/command inputs.

## Detection method

The detector submits a normal baseline request and a controlled request containing a unique output marker. It checks whether the marker appears in the HTTP response and not in the baseline.

## Interpretation

Observing the marker is **consistent with shell execution** (or with the application echoing the input). Findings are reported with confidence `medium` and verification `probable` until a non-reflective token proves the shell interpreted the payload.

## Remediation

Avoid `shell=True` when processing user input. Use `subprocess.run` with an argument list and `shell=False`, validate hostnames or IP addresses, and handle errors safely.

## Limitation

Reflection-only responses can false-positive. Prefer confirming with an arithmetic or computed marker that cannot appear verbatim in the request.
