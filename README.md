# DevOps Security Toolkit

Security automation scripts, compliance tools, and best practices for DevOps environments.

## Overview

This toolkit provides security automation for AWS, Kubernetes, and CI/CD pipelines. Built for FinTech and healthcare compliance requirements (PCI-DSS, HIPAA, SOC2).

## Components

### AWS Security
- **iam-audit**: IAM role and policy auditing
- **security-group-scanner**: Detect overly permissive security groups
- **s3-bucket-hardening**: S3 bucket security compliance checker
- **cloudtrail-monitor**: CloudTrail log analysis and alerting
- **kms-rotation**: Automated KMS key rotation

### Kubernetes Security
- **pod-security-scanner**: Runtime security scanning
- **rbac-audit**: RBAC role analysis and least privilege recommendations
- **secret-scanner**: Detect hardcoded secrets in configs
- **network-policy-validator**: Validate network policies
- **image-scanner**: Container image vulnerability scanning

### CI/CD Security
- **github-actions-scanner**: Security analysis for GitHub Actions
- **docker-hardening**: Dockerfile security best practices checker
- **dependency-scanner**: Scan for vulnerable dependencies
- **sast-tools**: Static application security testing

### Compliance
- **cis-benchmarks**: CIS compliance validation scripts
- **pci-dss-audit**: PCI-DSS compliance checker
- **hipaa-controls**: HIPAA security controls validation
- **soc2-evidence**: SOC2 audit evidence collection

## Quick Start

```bash
# AWS IAM Audit
./aws/iam-audit.py --profile production --output report.html

# Kubernetes RBAC Analysis
./kubernetes/rbac-audit.sh --context prod-cluster

# Scan Docker images
./containers/image-scanner.sh nginx:latest
```

## Best Practices Included

- Zero Trust Architecture
- Least Privilege Access
- Defense in Depth
- Continuous Compliance
- Automated Remediation

## Author

Andrés Muñoz - Principal DevOps Architect
Specialized in security, compliance, and cloud architecture

## License

MIT
# Final security updates
