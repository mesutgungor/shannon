# Modular Scanner Ingestion

Shannon supports ingesting external scanner reports across multiple security testing domains (**SAST, DAST, SCA, Secrets, IaC / Cloud Misconfigurations**).

Rather than relying purely on non-deterministic LLM exploration, deterministic scanners provide high-confidence findings that Shannon normalizes into a canonical schema and translates into targeted attack seeds for its autonomous pentest agents.

---

## Supported Scanner Types & Adapters

| Scanner Category | Supported Formats / Tools | What Shannon Extracts & How the Agent Uses It |
| :--- | :--- | :--- |
| **SAST** | Universal SARIF 2.1.0 (Semgrep, CodeQL) | File paths, line numbers, CWE tags, and taint source/sink flows. Directly mapped to Shannon's class reconciliation (`injection`, `xss`, `auth`, `authz`, `ssrf`). |
| **Secrets** | TruffleHog (JSON / NDJSON), Gitleaks (JSON) | Discovered tokens, API keys, and credential types. The agent uses these for immediate credential stuffing and authentication bypass attempts. |
| **DAST** | Nuclei (JSON / NDJSON) | Matched endpoint URLs, CVE/CWE classifications, and reproduction curl commands for instant exploit verification and escalation. |
| **SCA / SBOM** | Trivy JSON (`Results[].Vulnerabilities`) | Vulnerable third-party dependencies, installed/fixed versions, and CVE IDs for reachability analysis. |
| **IaC / Cloud** | Trivy JSON (`Results[].Misconfigurations`), Checkov SARIF | Terraform, Helm, and Dockerfile misconfigurations. Used by the agent to probe cloud metadata endpoints and misconfigured buckets. |

---

## Usage

### Ingesting a Single Report File

Pass `--scan-report` (or `-s`) when starting a scan:

```bash
# Ingest Semgrep SAST findings
shannon start -u http://target:3001 -r ./repo --scan-report ./semgrep.sarif

# Ingest TruffleHog leaked secrets
shannon start -u http://target:3001 -r ./repo --scan-report ./trufflehog.json

# Ingest Nuclei DAST results
shannon start -u http://target:3001 -r ./repo --scan-report ./nuclei.json

# Ingest Trivy dependency & IaC report
shannon start -u http://target:3001 -r ./repo --scan-report ./trivy.json
```

### Ingesting a Directory of Scanner Reports

You can also point `--scan-report` to an entire directory of mixed scan reports:

```bash
shannon start -u http://target:3001 -r ./repo --scan-report ./ci-artifacts/
```

Shannon automatically inspects each file, selects the appropriate adapter via content and schema detection, deduplicates findings across tools, and outputs an ingestion summary:

```text
================================================================================
[scanners] Ingested 18 findings from 4 report(s).
[scanners] Summary: SAST=8 | Secrets=3 | DAST=2 | SCA=4 | IaC=1
================================================================================
```

---

## Architecture

1. **Adapter Registry (`apps/worker/src/scanners/registry.ts`)**:
   Maintains pluggable adapters. Each adapter implements `canHandle(content, filename)` and `parse(content)`.
2. **Canonical Finding Model (`apps/worker/src/scanners/types.ts`)**:
   A unified schema containing standardized severity, identifiers (CWE/CVE), file/endpoint locations, and actionable `seedData` (tokens, taint sinks, reproduction curl commands).
3. **Shannon Bridge (`apps/worker/src/scanners/bridge.ts`)**:
   Converts canonical findings into Shannon's internal Capella-compliant SARIF format, allowing external scanner findings to flow straight through class reconciliation and prompt generation.
