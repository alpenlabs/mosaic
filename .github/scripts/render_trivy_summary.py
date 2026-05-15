#!/usr/bin/env python3
"""Parse trivy-results/mosaic.json and write a Markdown summary to trivy-results/mosaic.md."""

import json
import os
import sys
from pathlib import Path

IMAGE_REF = os.environ.get("IMAGE_REF", "unknown")
IMAGE_TAG = os.environ.get("IMAGE_TAG", "unknown")

INPUT = Path("trivy-results/mosaic.json")
OUTPUT = Path("trivy-results/mosaic.md")


def main():
    if not INPUT.exists():
        print(f"::warning::Trivy JSON not found at {INPUT}, skipping summary", file=sys.stderr)
        return

    data = json.loads(INPUT.read_text())

    vulns = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            vulns.append({
                "severity": v.get("Severity", ""),
                "id": v.get("VulnerabilityID", ""),
                "pkg": v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion", "") or "—",
                "title": v.get("Title", ""),
            })

    lines = [f"### Trivy vulnerability scan — `{IMAGE_TAG}`", ""]

    if not vulns:
        lines.append(f":white_check_mark: No HIGH or CRITICAL vulnerabilities found in `{IMAGE_REF}`.")
    else:
        lines += [
            f":x: **{len(vulns)} HIGH/CRITICAL vulnerability(ies)** found in `{IMAGE_REF}`.",
            "",
            "| Severity | CVE | Package | Installed | Fixed | Summary |",
            "|---|---|---|---|---|---|",
        ]
        severity_order = {"CRITICAL": 0, "HIGH": 1}
        for v in sorted(vulns, key=lambda x: (severity_order.get(x["severity"], 9), x["id"])):
            title = (v["title"][:57] + "…") if len(v["title"]) > 60 else v["title"]
            lines.append(
                f"| {v['severity']} | {v['id']} | `{v['pkg']}` "
                f"| {v['installed']} | {v['fixed']} | {title} |"
            )

    OUTPUT.write_text("\n".join(lines) + "\n")
    print(f"Written: {OUTPUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
