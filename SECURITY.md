# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please send an email to: ftrout@users.noreply.github.com

Include the following information:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested fixes (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution for Critical Issues**: Within 30 days

## Scope

### In Scope

- Code injection vulnerabilities in generated outputs
- Unauthorized access to data or credentials
- Prompt injection attacks that bypass safety measures
- Vulnerabilities in dependencies
- Authentication/authorization flaws

### Out of Scope

- Vulnerabilities in upstream dependencies already reported
- Theoretical attacks without proof of concept
- Social engineering attacks
- Physical security issues
- Issues requiring extensive user misconfiguration

## Security Best Practices

When using this tool:

1. **Review Generated Outputs**: Always review model-generated triage decisions before acting on them
2. **Validate Inputs**: Sanitize alert data before passing to the model
3. **Use Minimal Permissions**: Apply least-privilege principles for API credentials
4. **Secure Credentials**: Never include API keys in prompts or version control
5. **Monitor Usage**: Maintain audit logs of model predictions and actions taken
6. **Environment Isolation**: Run in isolated environments when processing sensitive alerts

## Architecture Security Notes

- The model generates triage recommendations only; it does not execute actions
- API credentials are validated but never logged or stored
- All model inference is stateless; no alert data is persisted
