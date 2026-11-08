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

function normalizeNucleiSeverity(sev?: string): FindingSeverity {
  switch (sev?.toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'info';
  }
}

interface NucleiRecord {
  'template-id'?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
    classification?: {
      'cve-id'?: string[] | string;
      'cwe-id'?: string[] | string;
    };
  };
  type?: string;
  host?: string;
  'matched-at'?: string;
  'extracted-results'?: string[];
  'curl-command'?: string;
}

export class NucleiAdapter implements ScannerAdapter {
  readonly id = 'nuclei';
  readonly name = 'Nuclei DAST / Vulnerability Scanner';
  readonly defaultCategory: ScannerCategory = 'dast';

  canHandle(rawContent: string, filename?: string): boolean {
    if (filename && filename.toLowerCase().includes('nuclei')) {
      return true;
    }
    const trimmed = rawContent.trim();
    if (!trimmed) return false;

    try {
      const firstLine = trimmed.split('\n')[0] || '';
      const obj = JSON.parse(firstLine.startsWith('[') ? trimmed : firstLine);
      const target = Array.isArray(obj) ? obj[0] : obj;
      return typeof target === 'object' && target !== null && (target['template-id'] !== undefined || target.templateID !== undefined);
    } catch {
      return false;
    }
  }

  async parse(rawContent: string): Promise<CanonicalFinding[]> {
    const findings: CanonicalFinding[] = [];
    const lines = rawContent.trim().split('\n');

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      let records: unknown[];
      try {
        const parsed = JSON.parse(trimmed);
        records = Array.isArray(parsed) ? parsed : [parsed];
      } catch {
        continue;
      }

      for (const item of records) {
        if (typeof item !== 'object' || item === null) continue;
        const n = item as NucleiRecord;

        const templateId = n['template-id'] || 'nuclei-finding';
        const matchedUrl = n['matched-at'] || n.host || 'http://unknown-target';
        const title = n.info?.name || templateId;
        const description = n.info?.description || `DAST trigger from Nuclei template ${templateId} on ${matchedUrl}`;
        const severity = normalizeNucleiSeverity(n.info?.severity);

        const cveRaw = n.info?.classification?.['cve-id'];
        const cves = Array.isArray(cveRaw) ? cveRaw : typeof cveRaw === 'string' ? [cveRaw] : undefined;

        const cweRaw = n.info?.classification?.['cwe-id'];
        const cwes = Array.isArray(cweRaw) ? cweRaw : typeof cweRaw === 'string' ? [cweRaw] : undefined;

        const curlCmd = n['curl-command'];
        const extracted = n['extracted-results']?.[0];

        const findingId = computeId(['nuclei', templateId, matchedUrl]);

        findings.push({
          id: findingId,
          category: 'dast',
          sourceTool: 'nuclei',
          title: `DAST: ${title}`,
          description,
          severity,
          location: {
            endpoint: {
              url: matchedUrl,
            },
          },
          identifiers: {
            ruleId: templateId,
            cve: cves,
            cwe: cwes,
          },
          seedData: {
            reproductionCommand: curlCmd,
            proofOfConcept: extracted,
          },
          metadata: {
            type: n.type,
            host: n.host,
          },
        });
      }
    }

    return findings;
  }
}
