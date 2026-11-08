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

function normalizeSeverity(level: string | undefined, propSeverity: unknown): FindingSeverity {
  if (typeof propSeverity === 'string') {
    const lower = propSeverity.toLowerCase();
    if (lower === 'critical') return 'critical';
    if (lower === 'high') return 'high';
    if (lower === 'medium') return 'medium';
    if (lower === 'low') return 'low';
    if (lower === 'info' || lower === 'informational') return 'info';
  }

  switch (level?.toLowerCase()) {
    case 'error':
      return 'high';
    case 'warning':
      return 'medium';
    case 'note':
    case 'none':
      return 'low';
    default:
      return 'medium';
  }
}

function extractCwes(tags: unknown[], ruleId: string): string[] {
  const cwes = new Set<string>();
  const cweRegex = /CWE[-_]?(\d+)/i;

  const matchRule = ruleId.match(cweRegex);
  if (matchRule?.[1]) {
    cwes.add(`CWE-${matchRule[1]}`);
  }

  if (Array.isArray(tags)) {
    for (const tag of tags) {
      if (typeof tag === 'string') {
        const match = tag.match(cweRegex);
        if (match?.[1]) {
          cwes.add(`CWE-${match[1]}`);
        }
      }
    }
  }

  return [...cwes];
}

function detectSarifCategory(toolName: string, ruleId: string): ScannerCategory {
  const lowerTool = toolName.toLowerCase();
  const lowerRule = ruleId.toLowerCase();

  if (lowerTool.includes('checkov') || lowerTool.includes('tfsec') || lowerTool.includes('kics')) {
    return 'iac_cloud';
  }
  if (lowerTool.includes('trivy') && (lowerRule.includes('cve-') || lowerTool.includes('vuln'))) {
    return 'sca';
  }
  return 'sast';
}

export class SarifAdapter implements ScannerAdapter {
  readonly id = 'sarif';
  readonly name = 'Universal SARIF 2.1.0 Adapter (Semgrep, CodeQL, Checkov, KICS)';
  readonly defaultCategory: ScannerCategory = 'sast';

  canHandle(rawContent: string, filename?: string): boolean {
    if (filename && (filename.endsWith('.sarif') || filename.endsWith('.sarif.json'))) {
      return true;
    }
    try {
      const parsed = JSON.parse(rawContent);
      return (
        typeof parsed === 'object' &&
        parsed !== null &&
        (parsed.version === '2.1.0' || parsed.version === '2.0.0' || typeof parsed.$schema === 'string') &&
        Array.isArray(parsed.runs)
      );
    } catch {
      return false;
    }
  }

  async parse(rawContent: string): Promise<CanonicalFinding[]> {
    const doc = JSON.parse(rawContent);
    const findings: CanonicalFinding[] = [];

    if (!Array.isArray(doc.runs)) {
      return findings;
    }

    for (const run of doc.runs) {
      const toolName = run.tool?.driver?.name || 'unknown-sarif-tool';
      const rules = new Map<string, { name?: string; description?: string; tags?: string[] }>();

      if (Array.isArray(run.tool?.driver?.rules)) {
        for (const rule of run.tool.driver.rules) {
          if (rule && typeof rule.id === 'string') {
            rules.set(rule.id, {
              name: rule.name || rule.shortDescription?.text,
              description: rule.fullDescription?.text || rule.shortDescription?.text,
              tags: Array.isArray(rule.properties?.tags) ? rule.properties.tags : [],
            });
          }
        }
      }

      if (!Array.isArray(run.results)) {
        continue;
      }

      for (const result of run.results) {
        if (!result) continue;
        const ruleId = result.ruleId || 'UNKNOWN_RULE';
        const ruleMeta = rules.get(ruleId);

        const title = ruleMeta?.name || result.message?.text || ruleId;
        const description = result.message?.text || ruleMeta?.description || title;
        const severity = normalizeSeverity(result.level, result.properties?.severity);
        const category = detectSarifCategory(toolName, ruleId);

        const location = result.locations?.[0]?.physicalLocation;
        let filePath = location?.artifactLocation?.uri || 'unknown_file';
        // Strip %SRCROOT%/ prefix if present
        if (filePath.startsWith('%SRCROOT%/')) {
          filePath = filePath.slice(10);
        }

        const startLine = location?.region?.startLine ?? 1;
        const endLine = location?.region?.endLine;
        const startColumn = location?.region?.startColumn;
        const snippet = location?.region?.snippet?.text;

        const cwes = extractCwes(ruleMeta?.tags || [], ruleId);
        const findingId = computeId([toolName, ruleId, filePath, String(startLine)]);

        // Extract taint sink if present in codeFlows
        let taintSink: string | undefined;
        let taintSource: string | undefined;
        if (Array.isArray(result.codeFlows)) {
          const threadFlow = result.codeFlows[0]?.threadFlows?.[0];
          if (threadFlow && Array.isArray(threadFlow.locations) && threadFlow.locations.length > 0) {
            taintSource = threadFlow.locations[0]?.location?.message?.text;
            const last = threadFlow.locations[threadFlow.locations.length - 1];
            taintSink = last?.location?.message?.text;
          }
        }

        findings.push({
          id: findingId,
          category,
          sourceTool: toolName,
          title,
          description,
          severity,
          location: {
            file: {
              path: filePath,
              startLine,
              endLine,
              startColumn,
              snippet,
            },
          },
          identifiers: {
            ruleId,
            cwe: cwes.length > 0 ? cwes : undefined,
          },
          seedData:
            taintSink || taintSource
              ? {
                  taintSink,
                  taintSource,
                }
              : undefined,
          metadata: {
            properties: result.properties,
          },
        });
      }
    }

    return findings;
  }
}
