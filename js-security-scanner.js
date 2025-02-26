#!/usr/bin/env node

/**
 * JavaScript Framework Security Scanner
 * 
 * This script analyzes web application project files to detect common security vulnerabilities
 * and code quality issues across various JavaScript frameworks (Vue, React, Angular, etc.)
 * 
 * Usage: node js-security-scanner.js [path/to/project]
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Configuration
const DEFAULT_PROJECT_PATH = './';
const EXTENSIONS_TO_SCAN = ['.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.html', '.htm'];

// Vulnerability patterns to check (framework-agnostic)
const vulnerabilityPatterns = [
  // Cross-Site Scripting (XSS) - covers various frameworks
  {
    name: 'Cross-Site Scripting (XSS)',
    pattern: /v-html=|dangerouslySetInnerHTML|innerHTML\s*=|\{\{\s*.+\s*\|\s*safe\s*\}\}|ng-bind-html|[^-]bind-html|bypassSecurityTrust\w+/i,
    description: 'Potentially unsafe HTML rendering that could lead to XSS attacks',
    severity: 'High',
    recommendation: 'Use safe content rendering methods and sanitize user input',
  },
  
  // SQL Injection
  {
    name: 'Potential SQL Injection',
    pattern: /\b(query|exec|execute)\s*\(\s*['"`].*?(\$\{|\?|:|\+\s*['"`])/i,
    description: 'Dynamic SQL queries with interpolated variables can lead to SQL injection',
    severity: 'High',
    recommendation: 'Use parameterized queries or an ORM with proper escaping',
  },
  
  // Insecure Direct Object References
  {
    name: 'Insecure Direct Object References',
    pattern: /\.(params|query)\.(id|userId|username)|getParam\(['"`](id|userId|username)/i,
    description: 'Direct use of request parameters without validation may lead to unauthorized access',
    severity: 'Medium',
    recommendation: 'Validate user permissions before accessing resources by ID',
  },
  
  // Hardcoded Secrets
  {
    name: 'Hardcoded Secrets',
    pattern: /(api[_-]?key|secret|password|token|auth|jwt)[\s]*[=:][\s]*['"`][A-Za-z0-9_\-\.]{10,}['"`]/i,
    description: 'Hardcoded API keys, secrets, or credentials in source code',
    severity: 'High',
    recommendation: 'Use environment variables or a secure vault for secrets',
  },
  
  // Insecure Cookie Settings
  {
    name: 'Insecure Cookie Settings',
    pattern: /document\.cookie\s*=|cookies\.set\(|cookie\s*:|cookie=/i,
    description: 'Setting cookies without secure attributes',
    severity: 'Medium',
    recommendation: 'Set HttpOnly, Secure, and SameSite attributes for sensitive cookies',
  },
  
  // Cross-Site Request Forgery (CSRF)
  {
    name: 'Cross-Site Request Forgery (CSRF)',
    pattern: /\.(post|put|delete)\s*\(|fetch\([^,]+,\s*\{[\s\S]*?method:\s*['"](?:POST|PUT|DELETE)['"]|axios\.(?:post|put|delete)/i,
    description: 'API calls without CSRF protection',
    severity: 'Medium',
    recommendation: 'Include CSRF tokens in requests or use SameSite cookies',
  },
  
  // Prototype Pollution
  {
    name: 'Prototype Pollution',
    pattern: /Object\.assign\(\{\}|Object\.merge|extend\(\{\}|\$\.extend|_.merge|_.extend/i,
    description: 'Potential prototype pollution vulnerability in object operations',
    severity: 'Medium',
    recommendation: 'Use Object.create(null) or careful input validation before merging objects',
  },
  
  // Insecure Randomness
  {
    name: 'Insecure Randomness',
    pattern: /Math\.random\(\)|Date\.now\(\).*random/i,
    description: 'Using weak randomness for security-sensitive operations',
    severity: 'Low',
    recommendation: 'Use crypto.getRandomValues() for cryptographic randomness',
  },
  
  // Eval Usage
  {
    name: 'Dynamic Code Execution',
    pattern: /\beval\(|new Function\(|setTimeout\(['"`]|setInterval\(['"`]/i,
    description: 'Using eval() or Function constructor which can lead to code injection',
    severity: 'High',
    recommendation: 'Avoid dynamic code execution; use safer alternatives',
  },
  
  // Insecure Storage
  {
    name: 'Insecure Client Storage',
    pattern: /localStorage\.|sessionStorage\.|indexedDB\.|document\.cookie/i,
    description: 'Storing sensitive data in browser storage',
    severity: 'Medium',
    recommendation: 'Don\'t store sensitive data in client-side storage mechanisms',
  },
  
  // Path Traversal
  {
    name: 'Path Traversal',
    pattern: /require\(.*\.\.\//i,
    description: 'Path traversal vulnerability in file operations',
    severity: 'High',
    recommendation: 'Validate and sanitize file paths before operations',
  },
  
  // NoSQL Injection
  {
    name: 'NoSQL Injection',
    pattern: /\$where\s*:\s*['"`]|\.find\(\s*{\s*\$where|\.aggregate\(/i,
    description: 'Potential NoSQL injection vulnerability',
    severity: 'High',
    recommendation: 'Use parameterized queries and validate input',
  },
  
  // Insecure JWT Verification
  {
    name: 'Insecure JWT Handling',
    pattern: /verify.*alg.*none|verify.*(!verify|ignoreExpiration|noTimestamp)/i,
    description: 'Insecure JWT token verification',
    severity: 'High',
    recommendation: 'Always validate JWT signature, expiration, and claims',
  },
  
  // Server-Side Request Forgery (SSRF)
  {
    name: 'Potential SSRF',
    pattern: /axios\.get\(\s*\$|request\(\s*\$|fetch\(\s*\$|https?\.get\(\s*\$/i,
    description: 'Server-side request with user-controlled input may lead to SSRF',
    severity: 'Medium',
    recommendation: 'Validate and sanitize URLs before making server-side requests',
  },
  
  // Regular Expression DoS (ReDoS)
  {
    name: 'Regular Expression DoS',
    pattern: /\(\.\*\)\+|\(\.\*\*\)|\(\.\*\?\)\*/i,
    description: 'Potentially vulnerable regex pattern that may cause DoS (ReDoS)',
    severity: 'Medium',
    recommendation: 'Use simple regex patterns or validate input length before regex operations',
  },
  
  // React Specific - useState with sensitive data
  {
    name: 'React: Sensitive Data in State',
    pattern: /useState\(\s*['"`](password|token|key|secret)/i,
    description: 'Potentially storing sensitive data in React component state',
    severity: 'Medium',
    recommendation: 'Avoid storing sensitive data in component state that might be exposed',
  },
  
  // Angular Specific - Template Injection
  {
    name: 'Angular: Template Injection',
    pattern: /bypassSecurityTrustHtml|bypassSecurityTrustScript|bypassSecurityTrustResourceUrl/i,
    description: 'Bypassing Angular\'s built-in sanitization',
    severity: 'High',
    recommendation: 'Avoid bypassing Angular\'s sanitization and use safe bindings',
  },
  
  // Vue Specific - No Props Validation
  {
    name: 'Vue: Missing Props Validation',
    pattern: /props\s*:\s*\[\s*['"`]/i,
    description: 'Using props array without type validation',
    severity: 'Low',
    recommendation: 'Use prop validation with types and required attributes',
  }
];

// Framework-specific checks based on file extension
const frameworkChecks = {
  '.vue': {
    name: 'Vue.js',
    packageName: 'vue',
    patterns: [
      {
        name: 'Vue: Missing Input Validation',
        pattern: /v-model(?!\.trim)/i,
        description: 'Using v-model without validation modifiers',
        severity: 'Low',
        recommendation: 'Add .trim modifier or implement additional validation',
      }
    ]
  },
  '.jsx': {
    name: 'React',
    packageName: 'react',
    patterns: [
      {
        name: 'React: Unsafe Component Methods',
        pattern: /componentWillMount|componentWillReceiveProps|componentWillUpdate/i,
        description: 'Using deprecated unsafe React lifecycle methods',
        severity: 'Medium',
        recommendation: 'Use modern lifecycle methods like componentDidMount or hooks',
      }
    ]
  },
  '.tsx': {
    name: 'React with TypeScript',
    packageName: 'react',
    patterns: [
      {
        name: 'React: Unsafe Component Methods',
        pattern: /componentWillMount|componentWillReceiveProps|componentWillUpdate/i,
        description: 'Using deprecated unsafe React lifecycle methods',
        severity: 'Medium',
        recommendation: 'Use modern lifecycle methods like componentDidMount or hooks',
      }
    ]
  },
  '.svelte': {
    name: 'Svelte',
    packageName: 'svelte',
    patterns: [
      {
        name: 'Svelte: Unsafe HTML',
        pattern: /\{@html/i,
        description: 'Using @html directive which bypasses sanitization',
        severity: 'High',
        recommendation: 'Avoid @html when possible or ensure content is sanitized',
      }
    ]
  }
};

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bright: {
    red: '\x1b[91m',
    yellow: '\x1b[93m',
  }
};

// Get project path from command line argument or use default
const projectPath = process.argv[2] || DEFAULT_PROJECT_PATH;
const absoluteProjectPath = path.resolve(projectPath);

console.log(`\n${colors.cyan}JavaScript Framework Security Scanner${colors.reset}`);
console.log(`${colors.cyan}====================================${colors.reset}`);
console.log(`Scanning project at: ${absoluteProjectPath}\n`);

// Detect frameworks used in the project
function detectFrameworks() {
  console.log(`${colors.cyan}Detecting frameworks...${colors.reset}`);
  
  const packagePath = path.join(absoluteProjectPath, 'package.json');
  const detectedFrameworks = new Set();
  
  if (fs.existsSync(packagePath)) {
    try {
      const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
      const dependencies = { 
        ...(packageJson.dependencies || {}), 
        ...(packageJson.devDependencies || {}) 
      };
      
      // Check for known frameworks
      if (dependencies.vue) {
        detectedFrameworks.add('Vue.js');
        console.log(`- ${colors.green}Vue.js detected${colors.reset} (${dependencies.vue})`);
      }
      
      if (dependencies.react) {
        detectedFrameworks.add('React');
        console.log(`- ${colors.green}React detected${colors.reset} (${dependencies.react})`);
      }
      
      if (dependencies.angular || dependencies['@angular/core']) {
        detectedFrameworks.add('Angular');
        console.log(`- ${colors.green}Angular detected${colors.reset} (${dependencies.angular || dependencies['@angular/core']})`);
      }
      
      if (dependencies.svelte) {
        detectedFrameworks.add('Svelte');
        console.log(`- ${colors.green}Svelte detected${colors.reset} (${dependencies.svelte})`);
      }
      
      if (dependencies.jquery) {
        detectedFrameworks.add('jQuery');
        console.log(`- ${colors.green}jQuery detected${colors.reset} (${dependencies.jquery})`);
      }
      
      if (dependencies.express) {
        detectedFrameworks.add('Express');
        console.log(`- ${colors.green}Express detected${colors.reset} (${dependencies.express})`);
      }
      
      if (dependencies.next) {
        detectedFrameworks.add('Next.js');
        console.log(`- ${colors.green}Next.js detected${colors.reset} (${dependencies.next})`);
      }
      
      if (dependencies.nuxt) {
        detectedFrameworks.add('Nuxt.js');
        console.log(`- ${colors.green}Nuxt.js detected${colors.reset} (${dependencies.nuxt})`);
      }
      
      if (dependencies.gatsby) {
        detectedFrameworks.add('Gatsby');
        console.log(`- ${colors.green}Gatsby detected${colors.reset} (${dependencies.gatsby})`);
      }
      
      if (detectedFrameworks.size === 0) {
        console.log(`- ${colors.yellow}No specific frameworks detected${colors.reset}`);
      }
    } catch (error) {
      console.log(`${colors.yellow}Error reading package.json: ${error.message}${colors.reset}`);
    }
  } else {
    console.log(`${colors.yellow}package.json not found. Framework detection limited.${colors.reset}`);
  }
  
  return detectedFrameworks;
}

// Check for outdated dependencies
function checkDependencies() {
  console.log(`\n${colors.cyan}Checking package.json for security issues...${colors.reset}`);
  
  const packagePath = path.join(absoluteProjectPath, 'package.json');
  
  if (!fs.existsSync(packagePath)) {
    console.log(`${colors.yellow}Warning: package.json not found. Skipping dependency check.${colors.reset}\n`);
    return;
  }
  
  try {
    const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    let hasIssues = false;
    
    // Check for NPM audit issues
    console.log(`\nRunning npm audit check...`);
    try {
      console.log('\nNPM audit summary:');
      const auditOutput = execSync('npm audit --json', { cwd: absoluteProjectPath }).toString();
      const auditResult = JSON.parse(auditOutput);
      
      if (auditResult.metadata.vulnerabilities.total > 0) {
        console.log(`${colors.red}Found ${auditResult.metadata.vulnerabilities.total} vulnerabilities:${colors.reset}`);
        console.log(`  High: ${auditResult.metadata.vulnerabilities.high}`);
        console.log(`  Medium: ${auditResult.metadata.vulnerabilities.moderate}`);
        console.log(`  Low: ${auditResult.metadata.vulnerabilities.low}`);
        console.log(`\n${colors.yellow}Run 'npm audit fix' to attempt to fix these issues.${colors.reset}`);
        hasIssues = true;
      } else {
        console.log(`${colors.green}No vulnerabilities found.${colors.reset}`);
      }
    } catch (error) {
      console.log(`${colors.yellow}Error running npm audit: ${error.message}${colors.reset}`);
      console.log(`${colors.yellow}Consider running 'npm audit' manually to check for vulnerabilities.${colors.reset}`);
    }
    
    if (!hasIssues) {
      console.log(`${colors.green}No dependency issues found.${colors.reset}`);
    }
  } catch (error) {
    console.log(`${colors.red}Error analyzing package.json: ${error.message}${colors.reset}`);
  }
  
  console.log('');
}

// Find all relevant files recursively
function findFiles(dir, fileList = []) {
  try {
    const files = fs.readdirSync(dir);
    
    files.forEach(file => {
      const filePath = path.join(dir, file);
      
      if (fs.statSync(filePath).isDirectory()) {
        // Skip node_modules, .git directories, and build/dist folders
        if (file !== 'node_modules' && file !== '.git' && 
            file !== 'dist' && file !== 'build' && file !== '.next' &&
            file !== 'out' && file !== 'public' && file !== '.nuxt') {
          findFiles(filePath, fileList);
        }
      } else {
        const ext = path.extname(file).toLowerCase();
        if (EXTENSIONS_TO_SCAN.includes(ext)) {
          fileList.push(filePath);
        }
      }
    });
  } catch (error) {
    console.log(`${colors.yellow}Error reading directory ${dir}: ${error.message}${colors.reset}`);
  }
  
  return fileList;
}

// Scan a file for vulnerabilities
function scanFile(filePath, detectedFrameworks) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const relativeFilePath = path.relative(absoluteProjectPath, filePath);
    let vulnerabilities = [];
    const fileExt = path.extname(filePath).toLowerCase();
    
    // Apply general vulnerability patterns
    vulnerabilityPatterns.forEach(vp => {
      const matches = [...content.matchAll(new RegExp(vp.pattern, 'g'))];
      
      if (matches.length > 0) {
        matches.forEach(match => {
          // Get line number of the match
          const lineNumber = content.substring(0, match.index).split('\n').length;
          
          // Get the line context
          const lines = content.split('\n');
          const contextLine = lines[lineNumber - 1].trim();
          
          vulnerabilities.push({
            file: relativeFilePath,
            line: lineNumber,
            context: contextLine,
            ...vp
          });
        });
      }
    });
    
    // Apply framework-specific patterns if applicable
    if (frameworkChecks[fileExt]) {
      const frameworkCheck = frameworkChecks[fileExt];
      
      // Only apply these checks if we've confirmed the framework is used
      if (detectedFrameworks.has(frameworkCheck.name) || detectedFrameworks.size === 0) {
        frameworkCheck.patterns.forEach(pattern => {
          const matches = [...content.matchAll(new RegExp(pattern.pattern, 'g'))];
          
          if (matches.length > 0) {
            matches.forEach(match => {
              const lineNumber = content.substring(0, match.index).split('\n').length;
              const lines = content.split('\n');
              const contextLine = lines[lineNumber - 1].trim();
              
              vulnerabilities.push({
                file: relativeFilePath,
                line: lineNumber,
                context: contextLine,
                ...pattern
              });
            });
          }
        });
      }
    }
    
    return vulnerabilities;
  } catch (error) {
    console.log(`${colors.red}Error scanning file ${filePath}: ${error.message}${colors.reset}`);
    return [];
  }
}

// Format output with severity color
function getSeverityColor(severity) {
  switch (severity) {
    case 'High':
      return colors.bright.red;
    case 'Medium':
      return colors.yellow;
    case 'Low':
      return colors.green;
    default:
      return colors.white;
  }
}

// Main scan function
function scanProject() {
  // Detect frameworks
  const detectedFrameworks = detectFrameworks();
  
  // Check dependencies
  checkDependencies();
  
  console.log(`${colors.cyan}Scanning for vulnerabilities in source code...${colors.reset}`);
  console.log(`${colors.cyan}--------------------------------------------${colors.reset}\n`);
  
  try {
    // Find all relevant files
    const filesToScan = findFiles(absoluteProjectPath);
    console.log(`Found ${filesToScan.length} files to scan\n`);
    
    // Scan each file
    let allVulnerabilities = [];
    let filesScanned = 0;
    
    filesToScan.forEach(file => {
      const vulnerabilities = scanFile(file, detectedFrameworks);
      allVulnerabilities = [...allVulnerabilities, ...vulnerabilities];
      filesScanned++;
      
      // Show progress for large projects
      if (filesToScan.length > 100 && filesScanned % 50 === 0) {
        console.log(`Progress: ${filesScanned}/${filesToScan.length} files scanned...`);
      }
    });
    
    // Group vulnerabilities by type
    const groupedVulnerabilities = {};
    allVulnerabilities.forEach(v => {
      if (!groupedVulnerabilities[v.name]) {
        groupedVulnerabilities[v.name] = [];
      }
      groupedVulnerabilities[v.name].push(v);
    });
    
    // Print results
    console.log(`${colors.cyan}Scan Results:${colors.reset}\n`);
    
    if (allVulnerabilities.length === 0) {
      console.log(`${colors.green}Great! No vulnerabilities found in the codebase.${colors.reset}`);
    } else {
      console.log(`${colors.yellow}Found ${allVulnerabilities.length} potential security issues:${colors.reset}\n`);
      
      // Print vulnerabilities by type
      Object.keys(groupedVulnerabilities).forEach(vulnType => {
        const vulns = groupedVulnerabilities[vulnType];
        const severity = vulns[0].severity;
        const severityColor = getSeverityColor(severity);
        
        console.log(`${severityColor}${vulnType} (${severity})${colors.reset}`);
        console.log(`${vulns[0].description}`);
        console.log(`${colors.blue}Recommendation: ${vulns[0].recommendation}${colors.reset}`);
        console.log(`Found ${vulns.length} instances:\n`);
        
        // Limit to 5 examples for each vulnerability type for readability
        const displayVulns = vulns.slice(0, 5);
        displayVulns.forEach(v => {
          console.log(`  ${colors.magenta}${v.file}:${v.line}${colors.reset}`);
          console.log(`  ${colors.white}${v.context}${colors.reset}\n`);
        });
        
        if (vulns.length > 5) {
          console.log(`  ${colors.yellow}... and ${vulns.length - 5} more instances${colors.reset}\n`);
        }
        
        console.log('');
      });
    }
    
    // Summary
    console.log(`${colors.cyan}Scan Summary:${colors.reset}`);
    console.log(`Files scanned: ${filesToScan.length}`);
    console.log(`Total issues: ${allVulnerabilities.length}`);
    
    // Count by severity
    const highSeverity = allVulnerabilities.filter(v => v.severity === 'High').length;
    const mediumSeverity = allVulnerabilities.filter(v => v.severity === 'Medium').length;
    const lowSeverity = allVulnerabilities.filter(v => v.severity === 'Low').length;
    
    console.log(`  ${colors.bright.red}High severity: ${highSeverity}${colors.reset}`);
    console.log(`  ${colors.yellow}Medium severity: ${mediumSeverity}${colors.reset}`);
    console.log(`  ${colors.green}Low severity: ${lowSeverity}${colors.reset}`);
    
    // Export results to JSON if there are vulnerabilities
    if (allVulnerabilities.length > 0) {
      try {
        const resultPath = path.join(process.cwd(), 'security-scan-results.json');
        fs.writeFileSync(
          resultPath,
          JSON.stringify({
            timestamp: new Date().toISOString(),
            projectPath: absoluteProjectPath,
            summary: {
              filesScanned: filesToScan.length,
              totalIssues: allVulnerabilities.length,
              highSeverity,
              mediumSeverity,
              lowSeverity
            },
            vulnerabilities: allVulnerabilities.map(v => ({
              name: v.name,
              file: v.file,
              line: v.line,
              severity: v.severity,
              description: v.description,
              recommendation: v.recommendation,
              context: v.context
            }))
          }, null, 2)
        );
        console.log(`\n${colors.green}Results exported to: ${resultPath}${colors.reset}`);
      } catch (error) {
        console.log(`${colors.red}Error exporting results: ${error.message}${colors.reset}`);
      }
    }
    
  } catch (error) {
    console.log(`${colors.red}Error during scan: ${error.message}${colors.reset}`);
  }
}

// Run the scanner
scanProject();
