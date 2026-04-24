#!/usr/bin/env python3
"""render_trivy_summary.py — Convert a Trivy JSON report to a Markdown summary table.

Called by the "Render Trivy markdown summary" step in docker-publish-ecr.yml after
the JSON-format Trivy scan completes. Reads trivy-results/mosaic.json and writes
trivy-results/mosaic.md, which is then appended to $GITHUB_STEP_SUMMARY so the
table appears on the workflow summary page.

A separate SARIF-format scan uploads structured results to the GitHub Security tab
for tracking; this script handles only the human-readable workflow summary.

Why JSON → Python instead of the built-in Trivy table format?
  The Trivy `table` format emits plain text which renders as a code block in
  $GITHUB_STEP_SUMMARY. JSON → Python lets us produce a proper Markdown table
  (rendered natively by GitHub) that matches the strata-bridge workflow layout.

Expected env vars (injected by the workflow step's env: block):
    IMAGE_REF  — full ECR image reference shown in the summary header
    IMAGE_TAG  — short SHA tag (unused in output, available for future use)

Output:
    trivy-results/mosaic.md
"""

import json
import os
from collections import Counter
from pathlib import Path


# Canonical ordering used for the severity count table columns and finding sort.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# Maximum number of individual findings to list in the summary.
# Keeps the summary page scannable — full results are in the uploaded artifact.
MAX_FINDINGS = 10


def iter_items(value: object) -> list[dict]:
    """Normalise a Trivy result field to a flat list of dicts.

    Trivy can emit a list, a dict, or null for the same field depending on the
    scanner mode and image content. This handles all three cases without fragile
    shell conditionals.
    """
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [item for item in value.values() if isinstance(item, dict)]
    return []


def main() -> None:
    image_ref = os.environ.get("IMAGE_REF", "mosaic")
    json_path = Path("trivy-results/mosaic.json")

    lines: list[str] = [
        "### Trivy Summary: Mosaic",
        "",
        f"`{image_ref}`",
        "",
        "- Scanners: `vuln`",
        "- Severity filter: `HIGH,CRITICAL` (unfixed vulnerabilities ignored)",
        "",
    ]

    if not json_path.exists():
        # JSON scan step may have been skipped or failed; emit a placeholder rather
        # than crashing the summary step.
        lines += ["Trivy did not produce a JSON report for this image.", ""]
    else:
        results = json.loads(json_path.read_text(encoding="utf-8"))
        counts: Counter = Counter()
        findings: list[dict] = []

        for target in results.get("Results", []):
            if not isinstance(target, dict):
                continue
            target_name = target.get("Target", "unknown")

            for vuln in iter_items(target.get("Vulnerabilities")):
                sev = vuln.get("Severity", "UNKNOWN")
                counts[sev] += 1
                findings.append({
                    "severity": sev,
                    "target": target_name,
                    "kind": "vuln",
                    "id": vuln.get("VulnerabilityID", "unknown"),
                })

        # Sort CRITICAL → HIGH → MEDIUM → LOW → UNKNOWN, then alphabetically by ID
        # for stable ordering across runs.
        findings.sort(key=lambda f: (
            SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER),
            f["id"],
        ))

        # Severity count summary table
        lines += [
            "| CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN |",
            "| --- | --- | --- | --- | --- |",
            "| " + " | ".join(str(counts.get(s, 0)) for s in SEVERITY_ORDER) + " |",
            "",
        ]

        if findings:
            lines += [
                f"Top findings (showing {min(len(findings), MAX_FINDINGS)} of {len(findings)}):",
                "",
                "| Severity | Type | ID | Target |",
                "| --- | --- | --- | --- |",
            ]
            for f in findings[:MAX_FINDINGS]:
                lines.append(f"| {f['severity']} | {f['kind']} | `{f['id']}` | `{f['target']}` |")
            lines.append("")
        else:
            lines += ["No HIGH/CRITICAL unfixed vulnerabilities found.", ""]

    Path("trivy-results/mosaic.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
