#!/usr/bin/env python3
"""
IAM Security Audit Tool
Analyzes IAM roles, policies, and users for security issues
"""

import boto3
import json
from datetime import datetime, timedelta
from typing import Dict, List

class IAMAuditor:
    def __init__(self, profile_name='default'):
        session = boto3.Session(profile_name=profile_name)
        self.iam = session.client('iam')
        self.findings = []

    def audit_users(self):
        """Audit IAM users for security issues"""
        users = self.iam.list_users()['Users']

        for user in users:
            username = user['UserName']

            # Check for old access keys
            keys = self.iam.list_access_keys(UserName=username)
            for key in keys['AccessKeyMetadata']:
                age = datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']
                if age > timedelta(days=90):
                    self.findings.append({
                        'severity': 'HIGH',
                        'resource': username,
                        'issue': f'Access key older than 90 days: {age.days} days',
                        'remediation': 'Rotate access keys regularly'
                    })

            # Check for console access without MFA
            try:
                login_profile = self.iam.get_login_profile(UserName=username)
                mfa_devices = self.iam.list_mfa_devices(UserName=username)

                if not mfa_devices['MFADevices']:
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'resource': username,
                        'issue': 'Console access without MFA enabled',
                        'remediation': 'Enable MFA for all users with console access'
                    })
            except self.iam.exceptions.NoSuchEntityException:
                pass

    def audit_roles(self):
        """Audit IAM roles for overly permissive policies"""
        roles = self.iam.list_roles()['Roles']

        for role in roles:
            role_name = role['RoleName']

            # Get attached policies
            attached = self.iam.list_attached_role_policies(RoleName=role_name)

            for policy in attached['AttachedPolicies']:
                if policy['PolicyName'] in ['AdministratorAccess', 'PowerUserAccess']:
                    self.findings.append({
                        'severity': 'HIGH',
                        'resource': role_name,
                        'issue': f'Overly permissive policy: {policy["PolicyName"]}',
                        'remediation': 'Apply principle of least privilege'
                    })

    def generate_report(self) -> str:
        """Generate audit report"""
        self.audit_users()
        self.audit_roles()

        report = {
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'critical': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
            'high': len([f for f in self.findings if f['severity'] == 'HIGH']),
            'findings': self.findings
        }

        return json.dumps(report, indent=2)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='IAM Security Audit')
    parser.add_argument('--profile', default='default', help='AWS profile name')
    parser.add_argument('--output', help='Output file for report')

    args = parser.parse_args()

    auditor = IAMAuditor(profile_name=args.profile)
    report = auditor.generate_report()

    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f'Report written to {args.output}')
    else:
        print(report)
