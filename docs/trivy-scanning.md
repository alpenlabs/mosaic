# Trivy Container Image Scanning

All Mosaic images must pass a Trivy vulnerability scan before being pushed to ECR.
This is enforced as a hard gate in the [Docker Publish to ECR](../.github/workflows/docker-publish-ecr.yml) workflow.

## How it works

The workflow builds the image locally (no push yet), then runs three Trivy scans:

| Scan | Format | Severity | Behaviour |
|---|---|---|---|
| Hard gate | JSON | HIGH, CRITICAL | Fails the build; image is never pushed if unfixed vulns are found |
| Security tab | SARIF | HIGH, CRITICAL | Advisory — always runs; uploaded to GitHub Code Scanning |
| SBOM | CycloneDX | all | Advisory — attached as a workflow artifact |

CVE suppressions live in [`.trivyignore`](../.trivyignore) at the repo root.

## Reading scan results

**Workflow summary** — every run appends a vulnerability table to the run's Summary page.
Open the run → **Summary** to see a ranked table of any HIGH/CRITICAL findings.

**GitHub Security tab** — SARIF results appear under **Security → Code scanning alerts**.
Filter by `Tool: Trivy` to see all findings across runs.

**Artifact download** — download the `trivy-mosaic-<tag>` artifact from the workflow run
to get the raw JSON, SARIF, and CycloneDX SBOM files for offline analysis.

## Fixing a blocked build

If the hard gate fails:

1. Open the **Scan Mosaic image with Trivy (hard gate)** step log to see which CVEs fired.
2. Update the base image in `docker/Dockerfile` to a version with a fix available, **or**
3. Add a justified exception to `.trivyignore` (see below) and open a PR for review.
4. Re-trigger via **Actions → Docker Publish to ECR → Run workflow**, or push to an `infra/**` branch.

## Adding a CVE exception

Only suppress a CVE when you can demonstrate it does not affect this project
(wrong architecture, unexposed code path, dependency not reachable at runtime, etc.).

```
# CVE-2023-12345: affects x86 only; Mosaic targets amd64 via distroless base — review by 2024-06-01
CVE-2023-12345
```

Steps:

1. Add the CVE ID to `.trivyignore` with a comment that explains the rationale and a review-by date.
2. Open a PR — exceptions are subject to security team review.
3. Revisit suppressed CVEs on the stated review-by date and remove them once a fix is available.
