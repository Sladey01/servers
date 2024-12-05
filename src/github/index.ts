#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import fetch from "node-fetch";
import { z } from 'zod';
import { zodToJsonSchema } from 'zod-to-json-schema';
import {
    GitHubForkSchema,
    GitHubReferenceSchema,
    GitHubRepositorySchema,
    GitHubIssueSchema,
    GitHubPullRequestSchema,
    GitHubContentSchema,
    GitHubCreateUpdateFileResponseSchema,
    GitHubSearchResponseSchema,
    GitHubTreeSchema,
    GitHubCommitSchema,
    CreateRepositoryOptionsSchema,
    CreateIssueOptionsSchema,
    CreatePullRequestOptionsSchema,
    CreateBranchOptionsSchema,
    type GitHubFork,
    type GitHubReference,
    type GitHubRepository,
    type GitHubIssue,
    type GitHubPullRequest,
    type GitHubContent,
    type GitHubCreateUpdateFileResponse,
    type GitHubSearchResponse,
    type GitHubTree,
    type GitHubCommit,
    type FileOperation,
    CreateOrUpdateFileSchema,
    SearchRepositoriesSchema,
    CreateRepositorySchema,
    GetFileContentsSchema,
    PushFilesSchema,
    CreateIssueSchema,
    CreatePullRequestSchema,
    ForkRepositorySchema,
    CreateBranchSchema
} from './schemas.js';

const server = new Server({
    name: "github-mcp-server",
    version: "0.1.0",
}, {
    capabilities: {
        tools: {}
    }
});

const GITHUB_PERSONAL_ACCESS_TOKEN = process.env.GITHUB_PERSONAL_ACCESS_TOKEN;
const SNYK_API_KEY = process.env.SNYK_API_KEY;

if (!GITHUB_PERSONAL_ACCESS_TOKEN) {
    console.error("GITHUB_PERSONAL_ACCESS_TOKEN environment variable is not set");
    process.exit(1);
}

// Add Snyk schemas
const SnykScanSchema = z.object({
    owner: z.string(),
    repo: z.string(),
    branch: z.string().optional()
});

// [Previous GitHub functions remain the same...]

server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "create_or_update_file",
                description: "Create or update a single file in a GitHub repository",
                inputSchema: zodToJsonSchema(CreateOrUpdateFileSchema)
            },
            {
                name: "search_repositories",
                description: "Search for GitHub repositories",
                inputSchema: zodToJsonSchema(SearchRepositoriesSchema)
            },
            {
                name: "create_repository",
                description: "Create a new GitHub repository in your account",
                inputSchema: zodToJsonSchema(CreateRepositorySchema)
            },
            {
                name: "get_file_contents",
                description: "Get the contents of a file or directory from a GitHub repository",
                inputSchema: zodToJsonSchema(GetFileContentsSchema)
            },
            {
                name: "push_files",
                description: "Push multiple files to a GitHub repository in a single commit",
                inputSchema: zodToJsonSchema(PushFilesSchema)
            },
            {
                name: "create_issue",
                description: "Create a new issue in a GitHub repository",
                inputSchema: zodToJsonSchema(CreateIssueSchema)
            },
            {
                name: "create_pull_request",
                description: "Create a new pull request in a GitHub repository",
                inputSchema: zodToJsonSchema(CreatePullRequestSchema)
            },
            {
                name: "fork_repository",
                description: "Fork a GitHub repository to your account or specified organization",
                inputSchema: zodToJsonSchema(ForkRepositorySchema)
            },
            {
                name: "create_branch",
                description: "Create a new branch in a GitHub repository",
                inputSchema: zodToJsonSchema(CreateBranchSchema)
            },
            {
                name: "scan_repository",
                description: "Scan a GitHub repository for security vulnerabilities using Snyk",
                inputSchema: zodToJsonSchema(SnykScanSchema)
            }
        ]
    };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
        if (!request.params.arguments) {
            throw new Error("Arguments are required");
        }

        switch (request.params.name) {
            // [Previous cases remain the same...]

            case "scan_repository": {
                const args = SnykScanSchema.parse(request.params.arguments);

                if (!SNYK_API_KEY) {
                    throw new Error('SNYK_API_KEY environment variable is required');
                }

                const response = await fetch(
                    'https://snyk.io/api/v1/test',
                    {
                        method: 'POST',
                        headers: {
                            'Authorization': `token ${SNYK_API_KEY}`,
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

                const snykResult = await response.json();
                return {
                    content: [{
                        type: "text",
                        text: JSON.stringify(snykResult, null, 2)
                    }]
                };
            }

            default:
                throw new Error(`Unknown tool: ${request.params.name}`);
        }
    } catch (error) {
        if (error instanceof z.ZodError) {
            throw new Error(`Invalid arguments: ${error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join(', ')}`);
        }
        throw error;
    }
});

async function runServer() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("GitHub MCP Server running on stdio");
}

runServer().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});