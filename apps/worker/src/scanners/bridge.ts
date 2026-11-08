// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type {
  CapellaSarif,
  CapellaSarifLevel,
  CapellaSarifResult,
  CapellaSarifRule,
  CapellaSarifSeverity,
} from '../ai/sast/sarif-profile.js';
import type { CanonicalFinding, FindingSeverity } from './types.js';

function mapSeverityToCapella(sev: FindingSeverity): CapellaSarifSeverity {
  switch (sev) {
    case 'critical':
      return 'Critical';
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    case 'low':
      return 'Low';
    default:
      return 'Info';
  }
}

function mapLevel(sev: FindingSeverity): CapellaSarifLevel {
  switch (sev) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    default:
      return 'note';
  }
}

function resolveCwe(finding: CanonicalFinding): `CWE-${number}` {
  if (finding.identifiers.cwe && finding.identifiers.cwe.length > 0) {
    for (const cwe of finding.identifiers.cwe) {
      const match = cwe.match(/^CWE-([1-9][0-9]*)$/);
      if (match?.[1]) {
        return `CWE-${Number(match[1])}` as `CWE-${number}`;
      }
    }
  }

  // Fallbacks based on category / keywords
  switch (finding.category) {
    case 'secret':
      return 'CWE-798'; // Hard-coded credentials
    case 'sca':
      return 'CWE-1395'; // Dependency with Known Vulnerabilities
    case 'iac_cloud':
      return 'CWE-16'; // Configuration
    case 'dast':
      return 'CWE-699'; // Software Security
    default:
      return 'CWE-699';
  }
}

function cleanRelativePath(rawPath?: string): string {
  if (!rawPath) return 'src/app.ts';
  let p = rawPath.replace(/^[/\\]+/, '');
  if (p.startsWith('%SRCROOT%/')) p = p.slice(10);
  if (p.includes('..') || p.trim() === '') return 'src/app.ts';
  return p;
}

export class ShannonScannerBridge {
  /**
   * Converts canonical findings into a strict Capella-compliant SARIF document.
   * Allows external scanner findings (SAST, Secrets, SCA, IaC) to flow directly
   * through Shannon's existing class-reconciliation and exploitation engine.
   */
  static toCapellaSarif(findings: CanonicalFinding[], repository: string = 'scanned-repo'): CapellaSarif {
    const rulesMap = new Map<string, CapellaSarifRule>();
    const results: CapellaSarifResult[] = [];

    for (const finding of findings) {
      const cwe = resolveCwe(finding);
      const level = mapLevel(finding.severity);
      const severity = mapSeverityToCapella(finding.severity);
      const uri = cleanRelativePath(finding.location.file?.path);
      const startLine = Math.max(1, finding.location.file?.startLine ?? 1);

      // Register rule definition if not yet registered
      if (!rulesMap.has(cwe)) {
        rulesMap.set(cwe, {
          id: cwe,
          name: `${finding.sourceTool.toUpperCase()}: ${finding.title}`,
          shortDescription: { text: finding.title },
          fullDescription: { text: finding.description },
          helpUri: `https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`,
          properties: {
            cwe,
            tags: [finding.category, finding.sourceTool, cwe],
          },
        });
      }

      const physicalLoc = {
        artifactLocation: {
          uri,
          uriBaseId: '%SRCROOT%' as const,
        },
        region: {
          startLine,
        },
      };

      // Construct a valid codeFlow whose sink strictly matches primary location
      const result: CapellaSarifResult = {
        ruleId: cwe,
        level,
        message: { text: `${finding.title}: ${finding.description}` },
        locations: [{ physicalLocation: physicalLoc }],
        codeFlows: [
          {
            threadFlows: [
              {
                locations: [
                  {
                    location: {
                      physicalLocation: physicalLoc,
                      message: { text: finding.seedData?.taintSource || 'Source input' },
                    },
                    importance: 'important',
                  },
                  {
                    location: {
                      physicalLocation: physicalLoc,
                      message: { text: finding.seedData?.taintSink || 'Sink location' },
                    },
                    importance: 'essential',
                  },
                ],
              },
            ],
          },
        ],
        properties: {
          severity,
          cwe,
          status: 'verified',
          description: finding.description,
          findingSubType: 'AGENT_SAST',
        },
      };

      results.push(result);
    }

    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'Shannon External Scanner Ingestion Bridge',
              version: '1.0.0',
              informationUri: 'https://github.com/KeygraphHQ/shannon',
              rules: Array.from(rulesMap.values()),
            },
          },
          results,
          properties: {
            repository,
            totalFindings: results.length,
          },
        },
      ],
    };
  }

  /**
   * Generates formatted prompt seed context for the AI pentester.
   * Organizes findings by category so agents can use their specialized playbooks.
   */
  static formatAgentPromptContext(findings: CanonicalFinding[]): string {
    if (findings.length === 0) return '';

    const lines: string[] = [
      '### INGESTED SCANNER FINDINGS & ATTACK SEEDS',
      'The following pre-scan findings were discovered by deterministic security scanners:',
      '',
    ];

    const secrets = findings.filter((f) => f.category === 'secret');
    if (secrets.length > 0) {
      lines.push('#### 🔑 Discovered Secrets & Credentials (Immediate Auth Testing)');
      for (const s of secrets) {
        lines.push(`- [${s.severity.toUpperCase()}] ${s.title}`);
        lines.push(`  Location: ${s.location.file?.path}:${s.location.file?.startLine}`);
        if (s.seedData?.secretToken) {
          lines.push(`  Seed Token: ${s.seedData.secretToken}`);
        }
      }
      lines.push('');
    }

    const sast = findings.filter((f) => f.category === 'sast');
    if (sast.length > 0) {
      lines.push('#### 💻 Static Code Analysis (Taint Sinks & Injection Targets)');
      for (const s of sast.slice(0, 15)) {
        lines.push(`- [${s.severity.toUpperCase()}] ${s.title} (${s.identifiers.cwe?.join(', ') || s.identifiers.ruleId})`);
        lines.push(`  File: ${s.location.file?.path}:${s.location.file?.startLine}`);
        if (s.seedData?.taintSink) {
          lines.push(`  Sink: ${s.seedData.taintSink}`);
        }
      }
      lines.push('');
    }

    const dast = findings.filter((f) => f.category === 'dast');
    if (dast.length > 0) {
      lines.push('#### 🎯 DAST Verification Targets');
      for (const d of dast) {
        lines.push(`- [${d.severity.toUpperCase()}] ${d.title}`);
        lines.push(`  Target URL: ${d.location.endpoint?.url}`);
        if (d.seedData?.reproductionCommand) {
          lines.push(`  PoC: ${d.seedData.reproductionCommand}`);
        }
      }
      lines.push('');
    }

    const sca = findings.filter((f) => f.category === 'sca');
    if (sca.length > 0) {
      lines.push('#### 📦 Vulnerable Dependencies (SCA / Known CVEs)');
      for (const c of sca.slice(0, 10)) {
        lines.push(
          `- [${c.severity.toUpperCase()}] ${c.title} (${c.identifiers.cve?.join(', ') || 'CVE'}) in ${
            c.seedData?.vulnerablePackage?.name
          }@${c.seedData?.vulnerablePackage?.installedVersion}`,
        );
      }
      lines.push('');
    }

    const iac = findings.filter((f) => f.category === 'iac_cloud');
    if (iac.length > 0) {
      lines.push('#### ☁️ Cloud & Infrastructure Misconfigurations');
      for (const i of iac) {
        lines.push(`- [${i.severity.toUpperCase()}] ${i.title} at ${i.location.file?.path}:${i.location.file?.startLine}`);
      }
      lines.push('');
    }

    return lines.join('\n');
  }
}
