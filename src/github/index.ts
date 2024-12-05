import { z } from 'zod';
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import fetch from "node-fetch";

// Add Snyk schemas
const SnykScanSchema = z.object({
  owner: z.string(),
  repo: z.string(),
  branch: z.string().optional()
});

const SnykVulnerabilitySchema = z.object({
  id: z.string(),
  severity: z.string(),
  title: z.string(),
  description: z.string(),
  package: z.string(),
  version: z.string(),
  fixedIn: z.string().optional()
});

const SnykScanResultSchema = z.object({
  vulnerabilities: z.array(SnykVulnerabilitySchema),
  summary: z.object({
    total: z.number(),
    critical: z.number(),
    high: z.number(),
    medium: z.number(),
    low: z.number()
  })
});

// Add scan_repository to tools list
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      // ... existing tools ...
      {
        name: "scan_repository",
        description: "Scan a GitHub repository for security vulnerabilities using Snyk",
        inputSchema: zodToJsonSchema(SnykScanSchema)
      }
    ]
  };
});

// Add scan_repository handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  switch (request.params.name) {
    case "scan_repository": {
      const args = SnykScanSchema.parse(request.params.arguments);
      const snykToken = process.env.SNYK_API_KEY;
      
      if (!snykToken) {
        throw new Error('SNYK_API_KEY environment variable is required');
      }

      const response = await fetch(
        'https://snyk.io/api/v1/test',
        {
          method: 'POST',
          headers: {
            'Authorization': `token ${snykToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            target: {
              remoteUrl: `https://github.com/${args.owner}/${args.repo}`
            }
          })
        }
      );

      if (!response.ok) {
        throw new Error(`Snyk API error: ${response.statusText}`);
      }

      const result = SnykScanResultSchema.parse(await response.json());
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
    // ... existing handlers ...
  }
});