import axios from 'axios';
import { promises as fs } from 'fs';
import * as path from 'path';

interface SnykScanResult {
  vulnerabilitiesFound: number;
  issues: Array<{
    severity: string;
    title: string;
    description: string;
    packageName: string;
    fixedIn?: string;
  }>;
  summary: {
    uniqueCount: number;
    projectName: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

class GithubSnykServer {
  private githubToken: string;
  private snykToken: string;

  constructor() {
    this.githubToken = process.env.GITHUB_PERSONAL_ACCESS_TOKEN || '';
    this.snykToken = process.env.SNYK_API_KEY || '';
  }

  private async validateTokens() {
    if (!this.githubToken || !this.snykToken) {
      throw new Error('Missing required tokens. Please ensure GITHUB_PERSONAL_ACCESS_TOKEN and SNYK_API_KEY are set.');
    }
  }

  async analyzeRepository(owner: string, repo: string): Promise<SnykScanResult> {
    await this.validateTokens();

    // First get the repo details from GitHub
    const repoUrl = `https://github.com/${owner}/${repo}`;
    const repoDetails = await this.getGithubRepoDetails(owner, repo);

    // Then scan with Snyk
    const scanResults = await this.snykScan(repoUrl);

    return {
      ...scanResults,
      summary: {
        ...scanResults.summary,
        projectName: repoDetails.name
      }
    };
  }

  private async getGithubRepoDetails(owner: string, repo: string) {
    try {
      const response = await axios.get(`https://api.github.com/repos/${owner}/${repo}`, {
        headers: {
          'Authorization': `token ${this.githubToken}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      });
      return response.data;
    } catch (error) {
      throw new Error(`Failed to get repository details: ${error.message}`);
    }
  }

  private async snykScan(repoUrl: string): Promise<SnykScanResult> {
    try {
      const response = await axios.post(
        'https://snyk.io/api/v1/test/github',
        {
          target: {
            remoteUrl: repoUrl
          }
        },
        {
          headers: {
            'Authorization': `token ${this.snykToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      const vulns = response.data.vulnerabilities || [];
      
      return {
        vulnerabilitiesFound: vulns.length,
        issues: vulns.map((vuln: any) => ({
          severity: vuln.severity,
          title: vuln.title,
          description: vuln.description,
          packageName: vuln.package,
          fixedIn: vuln.fixedIn
        })),
        summary: {
          uniqueCount: vulns.length,
          projectName: response.data.projectName || '',
          critical: vulns.filter((v: any) => v.severity === 'critical').length,
          high: vulns.filter((v: any) => v.severity === 'high').length,
          medium: vulns.filter((v: any) => v.severity === 'medium').length,
          low: vulns.filter((v: any) => v.severity === 'low').length
        }
      };
    } catch (error) {
      throw new Error(`Snyk scan failed: ${error.message}`);
    }
  }

  // Example of how to use this in a Model Context Protocol server
  async handleCommand(command: string): Promise<any> {
    const repoRegex = /analyze|scan|check.*?([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)/i;
    const match = command.match(repoRegex);
    
    if (match) {
      const [owner, repo] = match[1].split('/');
      return await this.analyzeRepository(owner, repo);
    }
    
    throw new Error('Invalid command. Please specify a repository to analyze (e.g., "analyze owner/repo")');
  }
}

// For CLI usage
if (require.main === module) {
  const server = new GithubSnykServer();
  const [,, owner, repo] = process.argv;

  if (owner && repo) {
    server.analyzeRepository(owner, repo)
      .then(results => console.log(JSON.stringify(results, null, 2)))
      .catch(error => {
        console.error('Error:', error.message);
        process.exit(1);
      });
  } else {
    console.error('Please provide owner and repo arguments');
    console.error('Usage: ts-node index.ts owner repo');
    process.exit(1);
  }
}

export default GithubSnykServer;