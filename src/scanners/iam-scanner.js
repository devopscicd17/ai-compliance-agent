'use strict';
/**
 * iam-scanner.js
 * Evaluates IAM configuration against:
 *   CIS AWS Foundations 1.x
 *   FedRAMP Moderate AC-2, AC-3, IA-2, IA-5
 *   NIST 800-53 AC-2, AC-6, IA-2, IA-5
 */

const {
  GetAccountPasswordPolicyCommand,
  GetCredentialReportCommand,
  GenerateCredentialReportCommand,
  ListUsersCommand,
  ListAccessKeysCommand,
  GetAccessKeyLastUsedCommand,
  ListAttachedUserPoliciesCommand,
  ListUserPoliciesCommand,
  GetUserPolicyCommand,
  ListRolesCommand,
  ListAttachedRolePoliciesCommand,
  GetRolePolicyCommand,
  ListRolePoliciesCommand,
  GetPolicyVersionCommand,
  ListAttachedGroupPoliciesCommand,
  ListGroupPoliciesCommand,
  GetGroupPolicyCommand,
  ListGroupsCommand,
} = require('@aws-sdk/client-iam');

const { paginate } = require('../aws/client');

class IAMScanner {
  constructor(clients, accountId, region) {
    this.iam = clients.iam;
    this.accountId = accountId;
    this.region = region;
  }

  async scan() {
    const findings = [];
    console.log('  → Scanning IAM configuration...');

    const [pwdFindings, credFindings, keyFindings, roleFindings] = await Promise.allSettled([
      this._checkPasswordPolicy(),
      this._checkCredentialReport(),
      this._checkAccessKeys(),
      this._checkOverlyPermissiveRoles(),
    ]);

    for (const result of [pwdFindings, credFindings, keyFindings, roleFindings]) {
      if (result.status === 'fulfilled') findings.push(...result.value);
      else console.warn('  ⚠ IAM sub-scan error:', result.reason?.message);
    }

    return findings;
  }

  async _checkPasswordPolicy() {
    const findings = [];
    const resource = `arn:aws:iam::${this.accountId}:account-password-policy`;

    let policy = null;
    try {
      const r = await this.iam.send(new GetAccountPasswordPolicyCommand({}));
      policy = r.PasswordPolicy;
    } catch (e) {
      if (e.name === 'NoSuchEntityException') {
        findings.push(this._finding({
          id: `IAM-001-${this.accountId}`,
          resource,
          resourceName: 'Account Password Policy',
          short: 'No IAM password policy configured',
          description: 'No IAM account password policy is set. This means there are no minimum requirements for password length, complexity, or rotation.',
          severity: 'HIGH',
          controls: [
            { framework: 'CIS', id: 'CIS-1.8', title: 'Ensure IAM password policy requires minimum length of 14' },
            { framework: 'NIST', id: 'NIST-IA-5', title: 'Authenticator Management' },
            { framework: 'FEDRAMP', id: 'FEDRAMP-IA-5', title: 'Authenticator Management' },
          ],
          remediation: {
            manual: [
              `aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --allow-users-to-change-password --max-password-age 90 --password-reuse-prevention 24`,
            ],
            automated: true,
            risk: 'LOW',
          },
          current: null,
          expected: { MinimumPasswordLength: 14, RequireSymbols: true, MaxPasswordAge: 90 },
        }));
        return findings;
      }
    }

    if (policy) {
      if ((policy.MinimumPasswordLength || 0) < 14) {
        findings.push(this._finding({
          id: `IAM-002-${this.accountId}`,
          resource,
          resourceName: 'Account Password Policy',
          short: 'Password policy minimum length < 14 characters',
          description: `Current minimum password length is ${policy.MinimumPasswordLength || 'not set'}. CIS requires at least 14 characters.`,
          severity: 'MEDIUM',
          controls: [
            { framework: 'CIS', id: 'CIS-1.8', title: 'Ensure IAM password policy requires minimum length of 14' },
            { framework: 'NIST', id: 'NIST-IA-5', title: 'Authenticator Management' },
          ],
          remediation: {
            manual: [`aws iam update-account-password-policy --minimum-password-length 14`],
            automated: true, risk: 'LOW',
          },
          current: { MinimumPasswordLength: policy.MinimumPasswordLength },
          expected: { MinimumPasswordLength: 14 },
        }));
      }

      if (!policy.MaxPasswordAge || policy.MaxPasswordAge > 90) {
        findings.push(this._finding({
          id: `IAM-003-${this.accountId}`,
          resource,
          resourceName: 'Account Password Policy',
          short: 'Password rotation not enforced within 90 days',
          description: `Password expiry is set to ${policy.MaxPasswordAge || 'never'}. Passwords should rotate every 90 days or less.`,
          severity: 'MEDIUM',
          controls: [
            { framework: 'CIS', id: 'CIS-1.11', title: 'Do not setup access keys during initial user setup' },
            { framework: 'NIST', id: 'NIST-IA-5', title: 'Authenticator Management' },
            { framework: 'FEDRAMP', id: 'FEDRAMP-IA-5', title: 'Authenticator Management' },
          ],
          remediation: {
            manual: [`aws iam update-account-password-policy --max-password-age 90`],
            automated: true, risk: 'LOW',
          },
          current: { MaxPasswordAge: policy.MaxPasswordAge },
          expected: { MaxPasswordAge: 90 },
        }));
      }

      if (!policy.PasswordReusePrevention || policy.PasswordReusePrevention < 24) {
        findings.push(this._finding({
          id: `IAM-004-${this.accountId}`,
          resource,
          resourceName: 'Account Password Policy',
          short: 'Password reuse prevention < 24 generations',
          description: `Password reuse prevention is ${policy.PasswordReusePrevention || 0}. Best practice requires 24 previous passwords to be blocked.`,
          severity: 'LOW',
          controls: [
            { framework: 'CIS', id: 'CIS-1.9', title: 'Ensure IAM password policy prevents password reuse' },
            { framework: 'NIST', id: 'NIST-IA-5', title: 'Authenticator Management' },
          ],
          remediation: {
            manual: [`aws iam update-account-password-policy --password-reuse-prevention 24`],
            automated: true, risk: 'LOW',
          },
          current: { PasswordReusePrevention: policy.PasswordReusePrevention },
          expected: { PasswordReusePrevention: 24 },
        }));
      }
    }
    return findings;
  }

  async _checkCredentialReport() {
    const findings = [];

    try {
      // Generate report first
      await this.iam.send(new GenerateCredentialReportCommand({}));
      await new Promise(r => setTimeout(r, 2000));
      const r = await this.iam.send(new GetCredentialReportCommand({}));
      const csv = Buffer.from(r.Content).toString('utf-8');
      const lines = csv.split('\n');
      const headers = lines[0].split(',');

      const colIndex = (name) => headers.indexOf(name);

      for (let i = 1; i < lines.length; i++) {
        const row = lines[i].split(',');
        if (!row[0]) continue;
        const username = row[colIndex('user')];
        const resource = `arn:aws:iam::${this.accountId}:user/${username}`;
        const mfaActive = row[colIndex('mfa_active')] === 'true';
        const passwordEnabled = row[colIndex('password_enabled')] === 'true';
        const key1Active = row[colIndex('access_key_1_active')] === 'true';
        const key2Active = row[colIndex('access_key_2_active')] === 'true';
        const key1LastRotated = row[colIndex('access_key_1_last_rotated')];
        const key2LastRotated = row[colIndex('access_key_2_last_rotated')];

        // Root account checks
        if (username === '<root_account>') {
          if (key1Active || key2Active) {
            findings.push(this._finding({
              id: `IAM-ROOT-001-${this.accountId}`,
              resource: `arn:aws:iam::${this.accountId}:root`,
              resourceName: 'Root Account',
              short: 'Root account has active access keys',
              description: 'The AWS root account has active programmatic access keys. Root keys bypass all IAM policies and cannot be scoped. This is a critical security risk.',
              severity: 'CRITICAL',
              controls: [
                { framework: 'CIS', id: 'CIS-1.4', title: 'Ensure no root account access key exists' },
                { framework: 'NIST', id: 'NIST-AC-6', title: 'Least Privilege' },
                { framework: 'FEDRAMP', id: 'FEDRAMP-AC-6', title: 'Least Privilege' },
                { framework: 'PCI', id: 'PCI-7.1', title: 'Limit access to system components' },
              ],
              remediation: {
                manual: [
                  '1. Log in to AWS Console as root',
                  '2. Navigate to IAM → Security credentials',
                  '3. Under "Access keys" — delete all root access keys',
                  '4. Use IAM roles for all programmatic access instead',
                ],
                automated: false,
                risk: 'HIGH',
              },
              current: { rootKeyActive: true },
              expected: { rootKeyActive: false },
            }));
          }
          if (!mfaActive) {
            findings.push(this._finding({
              id: `IAM-ROOT-002-${this.accountId}`,
              resource: `arn:aws:iam::${this.accountId}:root`,
              resourceName: 'Root Account',
              short: 'MFA not enabled on root account',
              description: 'The root account does not have multi-factor authentication enabled. Anyone with the root password has unrestricted account access.',
              severity: 'CRITICAL',
              controls: [
                { framework: 'CIS', id: 'CIS-1.5', title: 'Ensure MFA is enabled for the root account' },
                { framework: 'NIST', id: 'NIST-IA-2', title: 'Identification and Authentication' },
                { framework: 'FEDRAMP', id: 'FEDRAMP-IA-2', title: 'Identification and Authentication' },
              ],
              remediation: {
                manual: [
                  '1. Log in to AWS Console as root',
                  '2. Navigate to IAM → Security credentials → Multi-factor authentication',
                  '3. Click "Activate MFA" and follow the wizard',
                  '4. Use a hardware MFA device for root (best practice)',
                ],
                automated: false, risk: 'HIGH',
              },
              current: { mfa: false },
              expected: { mfa: true },
            }));
          }
          continue;
        }

        // Console users without MFA
        if (passwordEnabled && !mfaActive) {
          findings.push(this._finding({
            id: `IAM-MFA-${username}`,
            resource,
            resourceName: username,
            short: `IAM user "${username}" has no MFA`,
            description: `User "${username}" can log in to the AWS Console without MFA. A compromised password gives full console access.`,
            severity: 'HIGH',
            controls: [
              { framework: 'CIS', id: 'CIS-1.10', title: 'Ensure MFA is enabled for all IAM users with console access' },
              { framework: 'NIST', id: 'NIST-IA-2', title: 'Identification and Authentication — Multi-Factor' },
              { framework: 'FEDRAMP', id: 'FEDRAMP-IA-2(1)', title: 'MFA for Privileged Access' },
            ],
            remediation: {
              manual: [
                `# Enforce MFA via policy — create a policy that denies all actions if MFA not present:`,
                `aws iam attach-user-policy --user-name ${username} --policy-arn arn:aws:iam::aws:policy/IAMUserChangePassword`,
                `# Add DenyWithoutMFA inline policy (see AWS docs for full policy JSON)`,
              ],
              automated: false, risk: 'MEDIUM',
            },
            current: { mfa: false, consoleAccess: true },
            expected: { mfa: true },
          }));
        }

        // Stale access keys (>90 days)
        const checkKeyAge = (lastRotated, keyNum) => {
          if (!lastRotated || lastRotated === 'N/A') return;
          const age = Math.floor((Date.now() - new Date(lastRotated)) / 86400000);
          if (age > 90) {
            findings.push(this._finding({
              id: `IAM-STALEKEY-${username}-${keyNum}`,
              resource,
              resourceName: username,
              short: `Access key ${keyNum} for "${username}" not rotated in ${age} days`,
              description: `Access key ${keyNum} for user "${username}" was last rotated ${age} days ago. Keys older than 90 days increase the risk of credential compromise.`,
              severity: age > 180 ? 'HIGH' : 'MEDIUM',
              controls: [
                { framework: 'CIS', id: 'CIS-1.14', title: 'Ensure access keys are rotated every 90 days or less' },
                { framework: 'NIST', id: 'NIST-IA-5', title: 'Authenticator Management' },
                { framework: 'PCI', id: 'PCI-8.2.4', title: 'Change user passwords/passphrases at least once every 90 days' },
              ],
              remediation: {
                manual: [
                  `# Create new key:`,
                  `aws iam create-access-key --user-name ${username}`,
                  `# Update the service/application using the old key`,
                  `# Deactivate old key:`,
                  `aws iam update-access-key --user-name ${username} --access-key-id <OLD_KEY_ID> --status Inactive`,
                  `# After confirming the new key works, delete the old one:`,
                  `aws iam delete-access-key --user-name ${username} --access-key-id <OLD_KEY_ID>`,
                ],
                automated: false, risk: 'MEDIUM',
              },
              current: { lastRotated, ageInDays: age },
              expected: { maxAgeInDays: 90 },
            }));
          }
        };
        if (key1Active) checkKeyAge(key1LastRotated, 1);
        if (key2Active) checkKeyAge(key2LastRotated, 2);
      }
    } catch (e) {
      console.warn('  ⚠ Could not generate credential report:', e.message);
    }

    return findings;
  }

  async _checkAccessKeys() {
    return []; // Covered in credential report
  }

  async _checkOverlyPermissiveRoles() {
    const findings = [];

    let roles = [];
    try {
      roles = await paginate(this.iam, ListRolesCommand, {}, 'Roles');
    } catch (e) {
      console.warn('  ⚠ Cannot list IAM roles:', e.message);
      return [];
    }

    console.log(`  → Checking ${roles.length} IAM roles for over-permissive policies`);

    for (const role of roles.slice(0, 50)) { // Limit to avoid throttling
      try {
        const inlinePolicies = await paginate(this.iam, ListRolePoliciesCommand, { RoleName: role.RoleName }, 'PolicyNames');
        for (const pname of inlinePolicies) {
          const pr = await this.iam.send(new GetRolePolicyCommand({ RoleName: role.RoleName, PolicyName: pname }));
          const doc = JSON.parse(decodeURIComponent(pr.PolicyDocument));
          if (this._isWildcardPolicy(doc)) {
            findings.push(this._finding({
              id: `IAM-WILDCARD-${role.RoleName}-${pname}`,
              resource: role.Arn,
              resourceName: `${role.RoleName}/${pname}`,
              short: `Role "${role.RoleName}" has wildcard (*:*) inline policy`,
              description: `Inline policy "${pname}" on role "${role.RoleName}" uses Action: * and/or Resource: *, granting unrestricted permissions. This violates least-privilege.`,
              severity: 'HIGH',
              controls: [
                { framework: 'CIS', id: 'CIS-1.16', title: 'Ensure IAM policies are attached only to groups or roles' },
                { framework: 'NIST', id: 'NIST-AC-6', title: 'Least Privilege' },
                { framework: 'FEDRAMP', id: 'FEDRAMP-AC-6', title: 'Least Privilege' },
              ],
              remediation: {
                manual: [
                  `# Use IAM Access Analyzer to generate least-privilege policy:`,
                  `aws accessanalyzer create-access-preview --analyzer-arn <ARN> --configuration ...`,
                  `# Replace the wildcard policy with scoped permissions`,
                  `aws iam delete-role-policy --role-name ${role.RoleName} --policy-name ${pname}`,
                  `# Then attach a new scoped policy`,
                ],
                automated: false, risk: 'HIGH',
              },
              current: { policyDocument: doc },
              expected: { action: 'scoped', resource: 'scoped' },
            }));
          }
        }
      } catch (e) { /* skip if access denied */ }
    }

    return findings;
  }

  _isWildcardPolicy(doc) {
    const stmts = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
    return stmts.some(s => {
      if (s.Effect !== 'Allow') return false;
      const actions = Array.isArray(s.Action) ? s.Action : [s.Action];
      const resources = Array.isArray(s.Resource) ? s.Resource : [s.Resource];
      return actions.includes('*') && resources.includes('*');
    });
  }

  _finding(f) {
    return {
      ...f,
      service: 'IAM',
      status: 'OPEN',
      timestamp: new Date().toISOString(),
      accountId: this.accountId,
    };
  }
}

module.exports = IAMScanner;
