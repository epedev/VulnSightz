#!/usr/bin/env python3
"""Capture sharp demo screenshots via Chrome headless at 2x device scale."""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "vulnsight_report.html"
OUT = ROOT / "docs" / "images"
CSS_WIDTH = 1600
SCALE = 2


def extract_head_and_style(html: str) -> str:
    m = re.search(r"(<head>.*?</head>)", html, flags=re.S | re.I)
    if not m:
        raise SystemExit("report <head> not found")
    head = m.group(1)
    # Keep screenshots readable on light canvas
    extra = """
<style>
  html, body { background: #eef3f2 !important; margin: 0 !important; }
  body { padding: 24px 28px 40px !important; max-width: 1600px !important; }
</style>
"""
    return head.replace("</head>", extra + "</head>")


def extract_section(html: str, section_id: str) -> str:
    pattern = rf'(<section\s+id="{re.escape(section_id)}"[^>]*>)(.*?)(</section>)'
    m = re.search(pattern, html, flags=re.S | re.I)
    if not m:
        raise SystemExit(f"section not found: {section_id}")
    return m.group(0)


def extract_cover_block(html: str) -> str:
    """Top nav + cover header + download toolbar (skip embedded md JSON blob)."""
    topnav = re.search(r'(<div class="topnav">.*?</div>\s*</div>)', html, flags=re.S | re.I)
    cover = re.search(r'(<header class="cover">.*?</header>)', html, flags=re.S | re.I)
    downloads = re.search(
        r'(<div class="downloads"[^>]*>.*?</div>)',
        html,
        flags=re.S | re.I,
    )
    parts: list[str] = []
    if topnav:
        parts.append(topnav.group(1))
    if cover:
        parts.append(cover.group(1))
    if downloads:
        parts.append(downloads.group(1))
    return "\n".join(parts)

def extract_first_finding(html: str) -> str:
    detail = extract_section(html, "detailed-findings")
    # heading + first finding block
    hm = re.search(r"(<h2[^>]*>.*?</h2>)", detail, flags=re.S | re.I)
    heading = hm.group(1) if hm else "<h2>Detailed findings</h2>"
    # Prefer article/section cards after the h2
    rest = detail[hm.end() :] if hm else detail
    card = re.search(
        r"(<(?:article|section|div)\b[^>]*(?:class=\"[^\"]*finding[^\"]*\"|id=\"finding-)[^>]*>.*?</(?:article|section|div)>)",
        rest,
        flags=re.S | re.I,
    )
    if not card:
        # take a bounded chunk after h2
        chunk = rest[:12000]
        return f'<section id="detailed-findings">{heading}{chunk}</section>'
    return f'<section id="detailed-findings">{heading}{card.group(1)}</section>'


def write_page(path: Path, head: str, body_inner: str) -> None:
    path.write_text(
        f"""<!DOCTYPE html>
<html lang="en">
{head}
<body>
{body_inner}
</body>
</html>
""",
        encoding="utf-8",
    )


def chrome_shot(html_path: Path, out_png: Path, height: int = 2200) -> None:
    out_png.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "google-chrome",
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-extensions",
        "--hide-scrollbars",
        f"--window-size={CSS_WIDTH},{height}",
        f"--force-device-scale-factor={SCALE}",
        f"--screenshot={out_png}",
        html_path.resolve().as_uri(),
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not out_png.is_file() or out_png.stat().st_size < 1000:
        raise SystemExit(f"screenshot failed: {out_png}")


def trim_bottom_whitespace(png_path: Path, threshold: int = 250) -> None:
    """Crop trailing empty canvas so exports are tight but still sharp."""
    try:
        from PIL import Image
        import numpy as np
    except Exception:
        return
    im = Image.open(png_path).convert("RGB")
    arr = np.asarray(im)
    # rows that are not near-background
    bg = arr[0, 0]
    diff = np.abs(arr.astype("int16") - bg.astype("int16")).sum(axis=2)
    row_has = (diff > 12).any(axis=1)
    if not row_has.any():
        return
    last = int(row_has.nonzero()[0].max())
    pad = 24 * SCALE
    cut = min(im.height, last + pad)
    if cut < im.height - 8:
        im.crop((0, 0, im.width, cut)).save(png_path, format="PNG", optimize=True)


def main() -> None:
    html = REPORT.read_text(encoding="utf-8")
    # Drop huge embedded markdown payload so section pages stay light.
    html = re.sub(
        r'<script type="application/json" id="md-source">.*?</script>',
        "",
        html,
        flags=re.S | re.I,
    )
    head = extract_head_and_style(html)
    cover = extract_cover_block(html)
    OUT.mkdir(parents=True, exist_ok=True)

    jobs = [
        (
            "demo-report-summary.png",
            f'<div class="wrap">{cover}{extract_section(html, "executive-summary")}</div>',
            2400,
        ),
        ("demo-report-owasp.png", f'<div class="wrap">{extract_section(html, "owasp-top10")}</div>', 2200),
        (
            "demo-report-findings.png",
            f'<div class="wrap">{extract_section(html, "findings-overview")}</div>',
            2600,
        ),
        ("demo-report-detail.png", f'<div class="wrap">{extract_first_finding(html)}</div>', 1800),
    ]

    with tempfile.TemporaryDirectory(prefix="vulnsight-shots-") as tmp:
        tmp_path = Path(tmp)
        for name, body, height in jobs:
            page = tmp_path / f"{name}.html"
            write_page(page, head, body)
            out = OUT / name
            chrome_shot(page, out, height=height)
            trim_bottom_whitespace(out)
            print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
