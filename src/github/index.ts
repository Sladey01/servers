import axios from 'axios';
import * as fs from 'fs';
import * as path from 'path';

// Snyk API integration
class SnykIntegration {
  private apiKey: string;

  constructor() {
    // Load Snyk API key from config
    this.apiKey = this.loadSnykApiKey();
  }

  private loadSnykApiKey(): string {
    const configPath = path.join(__dirname, 'claude-config.json');
    try {
      const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      return config.snykApiKey || '';
    } catch (error) {
      console.error('Failed to load Snyk API key:', error);
      return '';
    }
  }

  async testRepository(repoUrl: string): Promise<any> {
    if (!this.apiKey) {
      throw new Error('Snyk API key is not configured');
    }

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
            'Authorization': `token ${this.apiKey}`,
            'Content-Type': 'application/json'
          }
        }
      );

      return this.processSnykResults(response.data);
    } catch (error) {
      console.error('Snyk test failed:', error);
      throw error;
    }
  }

  private processSnykResults(results: any): object {
    return {
      vulnerabilitiesFound: results.vulnerabilities?.length || 0,
      issues: results.vulnerabilities?.map((vuln: any) => ({
        severity: vuln.severity,
        title: vuln.title,
        description: vuln.description,
        packageName: vuln.packageName
      })) || []
    };
  }

  // Configuration method to set Snyk API key
  setSnykApiKey(apiKey: string): void {
    const configPath = path.join(__dirname, 'claude-config.json');
    let config: any = {};

    try {
      // Read existing config if it exists
      config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    } catch {
      // Create new config if file doesn't exist
    }

    // Update Snyk API key
    config.snykApiKey = apiKey;

    // Write updated config
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    
    // Reload API key
    this.apiKey = apiKey;
  }
}

// Example usage
async function main() {
  const snykIntegration = new SnykIntegration();

  // Example: Test a repository
  try {
    const results = await snykIntegration.testRepository('https://github.com/example/repo');
    console.log('Snyk Test Results:', results);
  } catch (error) {
    console.error('Repository testing failed:', error);
  }

  // To set API key (would typically be done via config or CLI)
  // snykIntegration.setSnykApiKey('your-snyk-api-key-here');
}

// Uncomment to run
// main();

export default SnykIntegration;