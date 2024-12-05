import { z } from 'zod';

// Add Snyk schemas
export const SnykScanSchema = z.object({
  owner: z.string(),
  repo: z.string(),
  branch: z.string().optional()
});

export const SnykVulnerabilitySchema = z.object({
  id: z.string(),
  severity: z.string(),
  title: z.string(),
  description: z.string(),
  package: z.string(),
  version: z.string(),
  fixedIn: z.string().optional()
});

export const SnykScanResultSchema = z.object({
  vulnerabilities: z.array(SnykVulnerabilitySchema),
  summary: z.object({
    total: z.number(),
    critical: z.number(),
    high: z.number(),
    medium: z.number(),
    low: z.number()
  })
});