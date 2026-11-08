// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { GitleaksAdapter } from './adapters/gitleaks.js';
import { NucleiAdapter } from './adapters/nuclei.js';
import { SarifAdapter } from './adapters/sarif.js';
import { TrivyAdapter } from './adapters/trivy.js';
import { TrufflehogAdapter } from './adapters/trufflehog.js';
import type { ScannerAdapter } from './types.js';

export class ScannerRegistry {
  private static instance: ScannerRegistry;
  private adapters: Map<string, ScannerAdapter> = new Map();

  constructor() {
    this.registerDefaults();
  }

  static getInstance(): ScannerRegistry {
    if (!ScannerRegistry.instance) {
      ScannerRegistry.instance = new ScannerRegistry();
    }
    return ScannerRegistry.instance;
  }

  private registerDefaults(): void {
    this.register(new SarifAdapter());
    this.register(new TrufflehogAdapter());
    this.register(new GitleaksAdapter());
    this.register(new NucleiAdapter());
    this.register(new TrivyAdapter());
  }

  register(adapter: ScannerAdapter): void {
    this.adapters.set(adapter.id, adapter);
  }

  get(id: string): ScannerAdapter | undefined {
    return this.adapters.get(id);
  }

  list(): ScannerAdapter[] {
    return Array.from(this.adapters.values());
  }

  detectAdapter(rawContent: string, filename?: string): ScannerAdapter | undefined {
    for (const adapter of this.adapters.values()) {
      if (adapter.canHandle(rawContent, filename)) {
        return adapter;
      }
    }
    return undefined;
  }
}
