# JavaScript Framework Security Scanner

A command-line tool to scan JavaScript projects for security vulnerabilities and code quality issues across various frameworks including React, Vue.js, Angular, and more.

## Features

- 🔍 **Framework Detection**: Automatically identifies which frameworks your project uses
- 🛡️ **Comprehensive Security Checks**: Detects 20+ common web vulnerabilities  
- 🔄 **Cross-Framework Support**: Works with React, Vue.js, Angular, Svelte, and vanilla JS
- 📊 **Detailed Reporting**: Severity ratings, line numbers, and remediation advice
- 📦 **Dependency Analysis**: Checks for vulnerable npm packages via `npm audit`

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/js-security-scanner.git

# Navigate to the directory
cd js-security-scanner

# Make the script executable
chmod +x js-security-scanner.js

# Optional: install globally
npm link  # or sudo npm link
```

## Usage

```bash
# Scan the current directory
node js-security-scanner.js

# Scan a specific project
node js-security-scanner.js /path/to/your/project

# If installed globally
js-security-scanner /path/to/your/project
```

## Vulnerability Checks

The scanner checks for various security issues including:

### Cross-Framework Vulnerabilities
- Cross-Site Scripting (XSS)
- SQL Injection points
- NoSQL Injection vulnerabilities
- Hardcoded secrets and API keys
- Insecure cookie usage
- Cross-Site Request Forgery (CSRF) vulnerabilities
- Prototype pollution risks
- Insecure randomness
- Dynamic code execution (eval)
- Insecure client storage
- Path traversal
- Regex DoS
- Server-Side Request Forgery

### Framework-Specific Checks

#### React
- Unsafe component lifecycle methods
- Sensitive data in component state
- Dangerous use of `dangerouslySetInnerHTML`

#### Vue.js
- Missing prop validation
- Unsafe use of `v-html`
- Missing input validation in `v-model`

#### Angular
- Template injection via bypass methods
- Unsafe binding

#### Svelte
- Unsafe HTML rendering

## Output Example

```
JavaScript Framework Security Scanner
====================================
Scanning project at: /path/to/project

Detecting frameworks...
- Vue.js detected (^3.2.0)
- Express detected (^4.17.1)

Checking package.json for security issues...

Running npm audit check...

NPM audit summary:
Found 3 vulnerabilities:
  High: 1
  Medium: 1
  Low: 1

Run 'npm audit fix' to attempt to fix these issues.

Scanning for vulnerabilities in source code...
--------------------------------------------

Found 137 files to scan

Progress: 50/137 files scanned...
Progress: 100/137 files scanned...

Scan Results:

Found 8 potential security issues:

Cross-Site Scripting (XSS) (High)
Potentially unsafe HTML rendering that could lead to XSS attacks
Recommendation: Use safe content rendering methods and sanitize user input
Found 3 instances:

  src/components/ArticleView.vue:42
  <div v-html="article.content"></div>

  src/utils/formatter.js:15
  element.innerHTML = marked(content);

  ... and 1 more instances


Hardcoded Secrets (High)
Hardcoded API keys, secrets, or credentials in source code
Recommendation: Use environment variables or a secure vault for secrets
Found 2 instances:

  src/services/api.js:5
  const API_KEY = "aKd82nLpqT7Bn91jNsP0Kld72"

  ... and 1 more instances

...

Scan Summary:
Files scanned: 137
Total issues: 8
  High severity: 3
  Medium severity: 4
  Low severity: 1

Results exported to: /path/to/project/security-scan-results.json
```

## Understanding Results

The scanner categorizes issues by severity:

- **High**: Critical vulnerabilities that should be addressed immediately
- **Medium**: Important issues that should be fixed in the near term
- **Low**: Minor issues or best practices that could be improved

For each vulnerability type, the scanner provides:
- Description of the issue
- File path and line number
- Code context
- Recommended fix

## Export Format

Results are automatically exported to a JSON file (`security-scan-results.json`) in your current directory, containing all detected vulnerabilities and scan metadata.

## Exclusions

The scanner automatically skips:
- `node_modules/` directory
- `.git/` directory
- Build directories (`dist/`, `build/`, `.next/`, etc.)
- Other generated code directories

## Limitations

- False positives may occur, especially for complex code patterns
- Some framework-specific vulnerabilities might not be detected in unusual implementations
- Dynamic code loading or eval-based code generation might hide some vulnerabilities

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
