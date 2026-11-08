// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { GitleaksAdapter } from './adapters/gitleaks.js';
import { NucleiAdapter } from './adapters/nuclei.js';
import { SarifAdapter } from './adapters/sarif.js';
import { TrivyAdapter } from './adapters/trivy.js';
import { TrufflehogAdapter } from './adapters/trufflehog.js';
import { ShannonScannerBridge } from './bridge.js';
import { ScannerIngestionEngine } from './engine.js';
import { ScannerRegistry } from './registry.js';

describe('Modular Scanner Ingestion Pipeline', () => {
  describe('Universal SARIF Adapter', () => {
    const semgrepSarif = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'Semgrep OSS',
              rules: [
                {
                  id: 'python.django.security.injection.sql.sql-injection',
                  name: 'SQL Injection in Django',
                  shortDescription: { text: 'User input flows into raw SQL query' },
                  properties: {
                    tags: ['CWE-89', 'security'],
                  },
                },
              ],
            },
          },
          results: [
            {
              ruleId: 'python.django.security.injection.sql.sql-injection',
              level: 'error',
              message: { text: 'Possible SQL injection in raw query' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'myapp/views.py' },
                    region: { startLine: 42 },
                  },
                },
              ],
              codeFlows: [
                {
                  threadFlows: [
                    {
                      locations: [
                        { location: { message: { text: 'request.GET.get("id")' } } },
                        { location: { message: { text: 'cursor.execute(query)' } } },
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    });

    it('can detect and parse Semgrep SARIF', async () => {
      const adapter = new SarifAdapter();
      assert.ok(adapter.canHandle(semgrepSarif, 'semgrep.sarif'));

      const findings = await adapter.parse(semgrepSarif);
      assert.equal(findings.length, 1);
      const f = findings[0];
      assert.equal(f?.category, 'sast');
      assert.equal(f?.sourceTool, 'Semgrep OSS');
      assert.equal(f?.severity, 'high');
      assert.equal(f?.location.file?.path, 'myapp/views.py');
      assert.equal(f?.location.file?.startLine, 42);
      assert.deepEqual(f?.identifiers.cwe, ['CWE-89']);
      assert.equal(f?.seedData?.taintSink, 'cursor.execute(query)');
    });
  });

  describe('TruffleHog Secret Adapter', () => {
    const trufflehogJson = JSON.stringify({
      DetectorName: 'AWS',
      Verified: true,
      Raw: 'AKIAIOSFODNN7EXAMPLE',
      Redacted: 'AKIAIOSFODNN7*******',
      SourceMetadata: {
        Data: {
          Git: {
            file: 'src/config/aws.ts',
            line: 18,
            commit: '1a2b3c4d',
          },
        },
      },
    });

    it('can detect and parse TruffleHog secrets', async () => {
      const adapter = new TrufflehogAdapter();
      assert.ok(adapter.canHandle(trufflehogJson, 'trufflehog.json'));

      const findings = await adapter.parse(trufflehogJson);
      assert.equal(findings.length, 1);
      const f = findings[0];
      assert.equal(f?.category, 'secret');
      assert.equal(f?.severity, 'critical'); // Verified active
      assert.equal(f?.location.file?.path, 'src/config/aws.ts');
      assert.equal(f?.location.file?.startLine, 18);
      assert.equal(f?.seedData?.secretToken, 'AKIAIOSFODNN7EXAMPLE');
      assert.equal(f?.seedData?.secretService, 'aws');
    });
  });

  describe('Gitleaks Secret Adapter', () => {
    const gitleaksJson = JSON.stringify([
      {
        Description: 'GitHub Personal Access Token',
        StartLine: 10,
        File: 'deploy/.env',
        Secret: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456',
        RuleID: 'github-pat',
      },
    ]);

    it('can detect and parse Gitleaks findings', async () => {
      const adapter = new GitleaksAdapter();
      assert.ok(adapter.canHandle(gitleaksJson, 'gitleaks.json'));

      const findings = await adapter.parse(gitleaksJson);
      assert.equal(findings.length, 1);
      const f = findings[0];
      assert.equal(f?.category, 'secret');
      assert.equal(f?.location.file?.path, 'deploy/.env');
      assert.equal(f?.seedData?.secretToken, 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456');
    });
  });

  describe('Nuclei DAST Adapter', () => {
    const nucleiJson = JSON.stringify({
      'template-id': 'cve-2023-38606',
      info: {
        name: 'OpenAM Authentication Bypass',
        severity: 'critical',
        classification: {
          'cve-id': ['CVE-2023-38606'],
          'cwe-id': ['CWE-287'],
        },
      },
      'matched-at': 'http://target.local:8080/openam/oauth2/token',
      'curl-command': 'curl -X POST http://target.local:8080/openam/oauth2/token -d grant_type=none',
    });

    it('can detect and parse Nuclei DAST output', async () => {
      const adapter = new NucleiAdapter();
      assert.ok(adapter.canHandle(nucleiJson, 'nuclei.json'));

      const findings = await adapter.parse(nucleiJson);
      assert.equal(findings.length, 1);
      const f = findings[0];
      assert.equal(f?.category, 'dast');
      assert.equal(f?.severity, 'critical');
      assert.equal(f?.location.endpoint?.url, 'http://target.local:8080/openam/oauth2/token');
      assert.equal(
        f?.seedData?.reproductionCommand,
        'curl -X POST http://target.local:8080/openam/oauth2/token -d grant_type=none',
      );
    });
  });

  describe('Trivy SCA & IaC Adapter', () => {
    const trivyJson = JSON.stringify({
      SchemaVersion: 2,
      Results: [
        {
          Target: 'package-lock.json',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2023-45857',
              PkgName: 'axios',
              InstalledVersion: '0.21.1',
              FixedVersion: '0.21.2',
              Severity: 'CRITICAL',
              Title: 'SSRF vulnerability in Axios',
            },
          ],
        },
        {
          Target: 'terraform/main.tf',
          Misconfigurations: [
            {
              ID: 'AVD-AWS-0001',
              Title: 'S3 Bucket Public Access Enabled',
              Severity: 'HIGH',
              CauseMetadata: {
                StartLine: 25,
                EndLine: 30,
              },
            },
          ],
        },
      ],
    });

    it('can parse both SCA dependencies and IaC misconfigurations from Trivy', async () => {
      const adapter = new TrivyAdapter();
      assert.ok(adapter.canHandle(trivyJson, 'trivy.json'));

      const findings = await adapter.parse(trivyJson);
      assert.equal(findings.length, 2);

      const scaFinding = findings.find((f) => f.category === 'sca');
      assert.ok(scaFinding);
      assert.equal(scaFinding?.identifiers.ruleId, 'CVE-2023-45857');
      assert.equal(scaFinding?.seedData?.vulnerablePackage?.name, 'axios');

      const iacFinding = findings.find((f) => f.category === 'iac_cloud');
      assert.ok(iacFinding);
      assert.equal(iacFinding?.identifiers.ruleId, 'AVD-AWS-0001');
      assert.equal(iacFinding?.location.file?.startLine, 25);
    });
  });

  describe('Scanner Registry & Ingestion Engine', () => {
    it('registers all default adapters in registry', () => {
      const registry = ScannerRegistry.getInstance();
      assert.ok(registry.get('sarif'));
      assert.ok(registry.get('trufflehog'));
      assert.ok(registry.get('gitleaks'));
      assert.ok(registry.get('nuclei'));
      assert.ok(registry.get('trivy'));
      assert.equal(registry.list().length >= 5, true);
    });

    it('automatically selects the correct adapter based on payload content', async () => {
      const engine = new ScannerIngestionEngine();
      const findings = await engine.ingestContent(
        JSON.stringify({
          DetectorName: 'SlackWebhook',
          Raw: 'https://hooks.slack.com/services/T00/B00/X00',
        }),
      );
      assert.equal(findings.length, 1);
      assert.equal(findings[0]?.category, 'secret');
    });
  });

  describe('Shannon Bridge & Capella Normalizer', () => {
    it('converts canonical findings into valid Capella SARIF format', async () => {
      const engine = new ScannerIngestionEngine();
      const findings = await engine.ingestContent(
        JSON.stringify({
          version: '2.1.0',
          runs: [
            {
              tool: { driver: { name: 'Semgrep' } },
              results: [
                {
                  ruleId: 'cwe-89-sqli',
                  level: 'error',
                  message: { text: 'SQL Injection' },
                  locations: [
                    {
                      physicalLocation: {
                        artifactLocation: { uri: 'src/api/users.ts' },
                        region: { startLine: 15 },
                      },
                    },
                  ],
                },
              ],
            },
          ],
        }),
      );

      const capellaSarif = ShannonScannerBridge.toCapellaSarif(findings, 'my-repo');
      assert.equal(capellaSarif.version, '2.1.0');
      assert.equal(capellaSarif.runs[0]?.results.length, 1);

      const res = capellaSarif.runs[0]?.results[0];
      assert.equal(res?.ruleId, 'CWE-89');
      assert.equal(res?.properties.status, 'verified');
      assert.equal(res?.properties.findingSubType, 'AGENT_SAST');
      assert.equal(res?.locations[0]?.physicalLocation.artifactLocation.uri, 'src/api/users.ts');
    });

    it('formats specialized agent prompt attack seeds', () => {
      const context = ShannonScannerBridge.formatAgentPromptContext([
        {
          id: '1',
          category: 'secret',
          sourceTool: 'trufflehog',
          title: 'AWS Secret',
          description: 'Leaked AWS key',
          severity: 'critical',
          location: { file: { path: 'config.env', startLine: 3 } },
          identifiers: { ruleId: 'AWS' },
          seedData: { secretToken: 'AKIA12345', secretService: 'aws' },
        },
      ]);

      assert.ok(context.includes('Discovered Secrets & Credentials'));
      assert.ok(context.includes('AKIA12345'));
    });
  });
});
