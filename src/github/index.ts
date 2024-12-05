import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';

const execAsync = promisify(exec);

class SnykIntegration {
  private configPath: string;

  constructor() {
    this.configPath = path.join(__dirname, 'claude-config.json');
  }

  async testRepository(repoUrl: string): Promise<any> {
    try {
      // Clone the repository to a temporary directory
      const tempDir = path.join(__dirname, 'temp', Date.now().toString());
      await execAsync(`git clone ${repoUrl} ${tempDir}`);

      // Run Snyk CLI test
      const { stdout, stderr } = await execAsync('snyk test --json', { cwd: tempDir });

      // Parse and process results
      const results = JSON.parse(stdout);
      
      // Clean up
      await execAsync(`rm -rf ${tempDir}`);

      return this.processSnykResults(results);
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
        packageName: vuln.packageName,
        fixedIn: vuln.fixedIn
      })) || [],
      summary: {
        uniqueCount: results.uniqueCount,
        projectName: results.projectName,
        displayTargetFile: results.displayTargetFile
      }
    };
  }

  async monitorRepository(repoUrl: string): Promise<any> {
    try {
      const tempDir = path.join(__dirname, 'temp', Date.now().toString());
      await execAsync(`git clone ${repoUrl} ${tempDir}`);

      // Run Snyk CLI monitor command
      const { stdout } = await execAsync('snyk monitor --json', { cwd: tempDir });

      // Clean up
      await execAsync(`rm -rf ${tempDir}`);

      return JSON.parse(stdout);
    } catch (error) {
      console.error('Snyk monitor failed:', error);
      throw error;
    }
  }
}

// Example usage
async function main() {
  const snykIntegration = new SnykIntegration();

  try {
    // Test a repository
    const results = await snykIntegration.testRepository('https://github.com/example/repo');
    console.log('Snyk Test Results:', results);

    // Monitor a repository
    const monitorResults = await snykIntegration.monitorRepository('https://github.com/example/repo');
    console.log('Snyk Monitor Results:', monitorResults);
  } catch (error) {
    console.error('Error:', error);
  }
}

// Uncomment to run
// main();

export default SnykIntegration;