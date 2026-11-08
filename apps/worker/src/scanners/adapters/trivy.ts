// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { createHash } from 'node:crypto';
import type { CanonicalFinding, FindingSeverity, ScannerAdapter, ScannerCategory } from '../types.js';

function computeId(parts: string[]): string {
  return createHash('sha256').update(parts.join(':')).digest('hex').slice(0, 16);
}

function normalizeTrivySeverity(sev?: string): FindingSeverity {
  switch (sev?.toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'info';
  }
}

interface TrivyVuln {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Title?: string;
  Description?: string;
  Severity?: string;
  CweIDs?: string[];
}

interface TrivyMisconfig {
  ID?: string;
  Title?: string;
  Description?: string;
  Severity?: string;
  Resolution?: string;
  CauseMetadata?: {
    StartLine?: number;
    EndLine?: number;
    Resource?: string;
  };
}

interface TrivyResult {
  Target?: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyVuln[];
  Misconfigurations?: TrivyMisconfig[];
}

interface TrivyReport {
  SchemaVersion?: number;
  ArtifactName?: string;
  Results?: TrivyResult[];
}

export class TrivyAdapter implements ScannerAdapter {
  readonly id = 'trivy';
  readonly name = 'Trivy SCA & IaC / Container Scanner';
  readonly defaultCategory: ScannerCategory = 'sca';

  canHandle(rawContent: string, filename?: string): boolean {
    if (filename && filename.toLowerCase().includes('trivy')) {
      return true;
    }
    try {
      const parsed = JSON.parse(rawContent);
      return (
        typeof parsed === 'object' &&
        parsed !== null &&
        (parsed.SchemaVersion !== undefined || Array.isArray(parsed.Results))
      );
    } catch {
      return false;
    }
  }

  async parse(rawContent: string): Promise<CanonicalFinding[]> {
    const findings: CanonicalFinding[] = [];
    let report: TrivyReport;

    try {
      report = JSON.parse(rawContent);
    } catch {
      return findings;
    }

    if (!Array.isArray(report.Results)) return findings;

    for (const res of report.Results) {
      const targetFile = res.Target || 'unknown_file';

      // 1. Process SCA Vulnerabilities (Dependencies)
      if (Array.isArray(res.Vulnerabilities)) {
        for (const v of res.Vulnerabilities) {
          const vulnId = v.VulnerabilityID || 'UNKNOWN_CVE';
          const pkg = v.PkgName || 'unknown-package';
          const title = v.Title || `${vulnId} in ${pkg}`;
          const description = v.Description || `Vulnerable component ${pkg}@${v.InstalledVersion} affected by ${vulnId}`;
          const severity = normalizeTrivySeverity(v.Severity);

          const findingId = computeId(['trivy', 'sca', vulnId, pkg, targetFile]);

          findings.push({
            id: findingId,
            category: 'sca',
            sourceTool: 'trivy',
            title: `SCA: ${title}`,
            description,
            severity,
            location: {
              file: {
                path: targetFile,
                startLine: 1,
              },
            },
            identifiers: {
              ruleId: vulnId,
              cve: [vulnId],
              cwe: v.CweIDs,
            },
            seedData: {
              vulnerablePackage: {
                name: pkg,
                installedVersion: v.InstalledVersion || '',
                fixedVersion: v.FixedVersion,
              },
            },
            metadata: {
              target: targetFile,
              class: res.Class,
              type: res.Type,
            },
          });
        }
      }

      // 2. Process IaC / Cloud Misconfigurations
      if (Array.isArray(res.Misconfigurations)) {
        for (const m of res.Misconfigurations) {
          const misconfigId = m.ID || 'MISCONFIG';
          const title = m.Title || misconfigId;
          const description = m.Description || title;
          const severity = normalizeTrivySeverity(m.Severity);
          const startLine = m.CauseMetadata?.StartLine ?? 1;

          const findingId = computeId(['trivy', 'iac', misconfigId, targetFile, String(startLine)]);

          findings.push({
            id: findingId,
            category: 'iac_cloud',
            sourceTool: 'trivy',
            title: `IaC / Cloud Misconfig: ${title}`,
            description: `${description}${m.Resolution ? `\nResolution: ${m.Resolution}` : ''}`,
            severity,
            location: {
              file: {
                path: targetFile,
                startLine,
                endLine: m.CauseMetadata?.EndLine,
              },
            },
            identifiers: {
              ruleId: misconfigId,
            },
            metadata: {
              resource: m.CauseMetadata?.Resource,
              resolution: m.Resolution,
              target: targetFile,
            },
          });
        }
      }
    }

    return findings;
  }
}
