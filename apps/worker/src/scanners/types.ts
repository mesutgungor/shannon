// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Universal contracts and data models for modular scanner ingestion.
 * Normalizes disparate security tools (SAST, DAST, SCA, Secrets, IaC/Cloud, CNAPP)
 * into a canonical representation for Shannon's pentesting agents.
 */

export type ScannerCategory =
  | 'sast' // Static Application Security Testing (e.g. Semgrep, CodeQL)
  | 'dast' // Dynamic Application Security Testing (e.g. Nuclei, OWASP ZAP)
  | 'sca' // Software Composition Analysis / SBOM (e.g. Trivy, Snyk, Grype)
  | 'secret' // Hardcoded Secret / Token Detection (e.g. TruffleHog, Gitleaks)
  | 'iac_cloud' // Infrastructure-as-Code / Cloud Misconfiguration (e.g. Checkov, tfsec, KICS)
  | 'cnapp'; // Cloud-Native Application Protection / Container runtime (e.g. Kubescape, Falco)

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface CodeLocation {
  /** Relative repository file path */
  path: string;
  startLine: number;
  endLine?: number | undefined;
  startColumn?: number | undefined;
  endColumn?: number | undefined;
  snippet?: string | undefined;
}

export interface DynamicLocation {
  /** Target endpoint / URL (e.g., http://target/api/login) */
  url: string;
  /** HTTP method if applicable */
  method?: string | undefined;
  /** Vulnerable parameter name */
  parameter?: string | undefined;
}

export interface FindingLocation {
  file?: CodeLocation | undefined;
  endpoint?: DynamicLocation | undefined;
}

export interface FindingIdentifiers {
  /** CVE identifiers (e.g., ["CVE-2023-38606"]) */
  cve?: string[] | undefined;
  /** CWE identifiers in standardized format (e.g., ["CWE-89", "CWE-79"]) */
  cwe?: string[] | undefined;
  /** Scanner-specific native rule/check ID (e.g. "python.django.security.injection.sql") */
  ruleId?: string | undefined;
}

/** Actionable seeds extracted from scan findings to accelerate agent exploitation */
export interface AttackSeedData {
  /** Discovered raw credential / API key to test against auth endpoints */
  secretToken?: string | undefined;
  /** Service type detected for the secret (e.g. "aws", "github", "stripe", "jwt") */
  secretService?: string | undefined;
  /** AST sink function where user input flows (e.g. "db.query", "child_process.exec") */
  taintSink?: string | undefined;
  /** AST source parameter */
  taintSource?: string | undefined;
  /** Reproduction curl command or HTTP request template from DAST/Nuclei */
  reproductionCommand?: string | undefined;
  /** Proof-of-concept payload */
  proofOfConcept?: string | undefined;
  /** Vulnerable dependency package name and version */
  vulnerablePackage?: {
    name: string;
    installedVersion: string;
    fixedVersion?: string | undefined;
  } | undefined;
}

/** Normalized security finding across any supported scanner format */
export interface CanonicalFinding {
  /** Unique deterministic identifier for deduplication (e.g. sha256 of tool:rule:location) */
  id: string;
  /** Broad scanner category governing how the AI agent approaches exploitation */
  category: ScannerCategory;
  /** Originating tool name (e.g. "semgrep", "trufflehog", "nuclei", "trivy", "gitleaks") */
  sourceTool: string;
  /** Human-readable finding title */
  title: string;
  /** Detailed vulnerability description */
  description: string;
  /** Normalized severity rating */
  severity: FindingSeverity;
  /** Location where the issue resides (code line, HTTP endpoint, or container resource) */
  location: FindingLocation;
  /** Industry standard identifiers */
  identifiers: FindingIdentifiers;
  /** Actionable seeds to pass into agent prompts */
  seedData?: AttackSeedData | undefined;
  /** Additional scanner-specific metadata */
  metadata?: Record<string, unknown> | undefined;
}

/** Interface implemented by format-specific scanner adapters */
export interface ScannerAdapter {
  /** Unique slug for the adapter (e.g. "sarif", "trufflehog", "nuclei") */
  readonly id: string;
  /** Display name of the scanner adapter */
  readonly name: string;
  /** Primary category handled by this adapter */
  readonly defaultCategory: ScannerCategory;

  /**
   * Determine whether this adapter can parse the supplied content.
   * Examines file extensions, JSON envelopes, or signature schemas.
   */
  canHandle(rawContent: string, filename?: string): boolean;

  /**
   * Parse and normalize the raw scanner report into canonical findings.
   */
  parse(rawContent: string, filename?: string): Promise<CanonicalFinding[]>;
}

/** Overall ingestion summary across multiple reports */
export interface IngestionResult {
  findings: CanonicalFinding[];
  summary: Record<ScannerCategory, number>;
  reportsProcessed: Array<{
    filename: string;
    adapterId: string;
    findingCount: number;
  }>;
  totalParsed: number;
  droppedCount: number;
}
