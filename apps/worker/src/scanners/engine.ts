// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { ScannerRegistry } from './registry.js';
import type { CanonicalFinding, IngestionResult, ScannerCategory } from './types.js';

export class ScannerIngestionEngine {
  private registry: ScannerRegistry;

  constructor(registry: ScannerRegistry = ScannerRegistry.getInstance()) {
    this.registry = registry;
  }

  async ingestContent(rawContent: string, filename?: string): Promise<CanonicalFinding[]> {
    const adapter = this.registry.detectAdapter(rawContent, filename);
    if (!adapter) {
      return [];
    }
    return adapter.parse(rawContent, filename);
  }

  async ingestFile(filePath: string): Promise<CanonicalFinding[]> {
    const content = await readFile(filePath, 'utf8');
    const filename = path.basename(filePath);
    return this.ingestContent(content, filename);
  }

  async ingestPaths(paths: string[]): Promise<IngestionResult> {
    const uniqueFindings = new Map<string, CanonicalFinding>();
    const reportsProcessed: IngestionResult['reportsProcessed'] = [];
    let totalParsed = 0;

    const summary: Record<ScannerCategory, number> = {
      sast: 0,
      dast: 0,
      sca: 0,
      secret: 0,
      iac_cloud: 0,
      cnapp: 0,
    };

    for (const targetPath of paths) {
      try {
        const fileStat = await stat(targetPath);
        if (fileStat.isDirectory()) {
          const dirFiles = await readdir(targetPath);
          for (const file of dirFiles) {
            const fullPath = path.join(targetPath, file);
            const subStat = await stat(fullPath);
            if (subStat.isFile()) {
              await this.processSingleFile(fullPath, uniqueFindings, reportsProcessed);
            }
          }
        } else if (fileStat.isFile()) {
          await this.processSingleFile(targetPath, uniqueFindings, reportsProcessed);
        }
      } catch (err) {
        // Skip unreadable files or directories gracefully
        continue;
      }
    }

    const allFindings = Array.from(uniqueFindings.values());
    for (const finding of allFindings) {
      summary[finding.category] = (summary[finding.category] || 0) + 1;
    }

    for (const rep of reportsProcessed) {
      totalParsed += rep.findingCount;
    }

    return {
      findings: allFindings,
      summary,
      reportsProcessed,
      totalParsed,
      droppedCount: totalParsed - allFindings.length, // Duplicates dropped
    };
  }

  private async processSingleFile(
    fullPath: string,
    uniqueFindings: Map<string, CanonicalFinding>,
    reportsProcessed: IngestionResult['reportsProcessed'],
  ): Promise<void> {
    try {
      const content = await readFile(fullPath, 'utf8');
      const filename = path.basename(fullPath);
      const adapter = this.registry.detectAdapter(content, filename);

      if (!adapter) return;

      const findings = await adapter.parse(content, filename);
      reportsProcessed.push({
        filename,
        adapterId: adapter.id,
        findingCount: findings.length,
      });

      for (const finding of findings) {
        if (!uniqueFindings.has(finding.id)) {
          uniqueFindings.set(finding.id, finding);
        }
      }
    } catch {
      // Ignore corrupted or unparseable files
    }
  }
}
