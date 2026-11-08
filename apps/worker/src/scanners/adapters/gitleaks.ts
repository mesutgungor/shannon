// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { createHash } from 'node:crypto';
import type { CanonicalFinding, ScannerAdapter, ScannerCategory } from '../types.js';

function computeId(parts: string[]): string {
  return createHash('sha256').update(parts.join(':')).digest('hex').slice(0, 16);
}

interface GitleaksFinding {
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  StartColumn?: number;
  EndColumn?: number;
  Match?: string;
  Secret?: string;
  File?: string;
  Commit?: string;
  Author?: string;
  Email?: string;
  Date?: string;
  RuleID?: string;
  Entropy?: number;
}

export class GitleaksAdapter implements ScannerAdapter {
  readonly id = 'gitleaks';
  readonly name = 'Gitleaks Secret Scanner';
  readonly defaultCategory: ScannerCategory = 'secret';

  canHandle(rawContent: string, filename?: string): boolean {
    if (filename && filename.toLowerCase().includes('gitleaks')) {
      return true;
    }
    const trimmed = rawContent.trim();
    if (!trimmed.startsWith('[')) return false;

    try {
      const arr = JSON.parse(trimmed);
      if (Array.isArray(arr) && arr.length > 0) {
        const item = arr[0];
        return typeof item === 'object' && item !== null && (item.RuleID !== undefined || item.Secret !== undefined);
      }
      return false;
    } catch {
      return false;
    }
  }

  async parse(rawContent: string): Promise<CanonicalFinding[]> {
    const findings: CanonicalFinding[] = [];
    let items: unknown[];

    try {
      items = JSON.parse(rawContent);
    } catch {
      return findings;
    }

    if (!Array.isArray(items)) return findings;

    for (const item of items) {
      if (typeof item !== 'object' || item === null) continue;
      const g = item as GitleaksFinding;

      const ruleId = g.RuleID || 'secret';
      const secret = g.Secret || g.Match || '';
      const filePath = g.File || 'unknown_file';
      const startLine = g.StartLine ?? 1;

      const findingId = computeId(['gitleaks', ruleId, filePath, String(startLine), secret.slice(0, 10)]);

      findings.push({
        id: findingId,
        category: 'secret',
        sourceTool: 'gitleaks',
        title: `Hardcoded Secret: ${g.Description || ruleId}`,
        description: `Discovered hardcoded ${g.Description || ruleId} in ${filePath} at line ${startLine}.`,
        severity: 'high',
        location: {
          file: {
            path: filePath,
            startLine,
            endLine: g.EndLine,
            startColumn: g.StartColumn,
            endColumn: g.EndColumn,
          },
        },
        identifiers: {
          ruleId,
          cwe: ['CWE-798', 'CWE-259'],
        },
        seedData: {
          secretToken: secret,
          secretService: ruleId.toLowerCase(),
        },
        metadata: {
          commit: g.Commit,
          author: g.Author,
          entropy: g.Entropy,
        },
      });
    }

    return findings;
  }
}
