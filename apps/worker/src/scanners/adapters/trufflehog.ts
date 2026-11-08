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

interface TruffleHogRecord {
  DetectorName?: string;
  DetectorType?: number;
  Verified?: boolean;
  Raw?: string;
  Redacted?: string;
  SourceMetadata?: {
    Data?: {
      Git?: {
        file?: string;
        line?: number;
        commit?: string;
      };
      Filesystem?: {
        file?: string;
        line?: number;
      };
    };
  };
}

export class TrufflehogAdapter implements ScannerAdapter {
  readonly id = 'trufflehog';
  readonly name = 'TruffleHog Secret Scanner';
  readonly defaultCategory: ScannerCategory = 'secret';

  canHandle(rawContent: string, filename?: string): boolean {
    if (filename && (filename.includes('trufflehog') || filename.includes('secrets'))) {
      return true;
    }
    const trimmed = rawContent.trim();
    if (!trimmed) return false;

    // Check first line or JSON object
    try {
      const firstLine = trimmed.split('\n')[0] || '';
      const obj = JSON.parse(firstLine);
      return typeof obj === 'object' && obj !== null && (obj.DetectorName !== undefined || obj.DetectorType !== undefined);
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

      let record: TruffleHogRecord;
      try {
        record = JSON.parse(trimmed);
      } catch {
        continue;
      }

      if (!record.DetectorName && record.DetectorType === undefined) {
        continue;
      }

      const detector = record.DetectorName || `Type-${record.DetectorType}`;
      const isVerified = record.Verified === true;
      const severity: FindingSeverity = isVerified ? 'critical' : 'high';

      const gitData = record.SourceMetadata?.Data?.Git;
      const fsData = record.SourceMetadata?.Data?.Filesystem;
      const filePath = gitData?.file || fsData?.file || 'unknown_file';
      const startLine = gitData?.line || fsData?.line || 1;

      const rawSecret = record.Raw || record.Redacted || '';
      const findingId = computeId(['trufflehog', detector, filePath, String(startLine), rawSecret.slice(0, 10)]);

      findings.push({
        id: findingId,
        category: 'secret',
        sourceTool: 'trufflehog',
        title: `Hardcoded Secret: ${detector}${isVerified ? ' (Verified Active)' : ''}`,
        description: `Discovered hardcoded ${detector} secret in ${filePath} at line ${startLine}. Status: ${
          isVerified ? 'VERIFIED ACTIVE' : 'UNVERIFIED'
        }`,
        severity,
        location: {
          file: {
            path: filePath,
            startLine,
          },
        },
        identifiers: {
          ruleId: detector,
          cwe: ['CWE-798', 'CWE-259'],
        },
        seedData: {
          secretToken: rawSecret,
          secretService: detector.toLowerCase(),
        },
        metadata: {
          verified: isVerified,
          commit: gitData?.commit,
        },
      });
    }

    return findings;
  }
}
