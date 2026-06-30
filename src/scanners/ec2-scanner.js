'use strict';
/**
 * ec2-scanner.js
 * Evaluates EC2 instances and Security Groups against:
 *   CIS AWS Foundations 5.x
 *   NIST 800-53 SC-7, SC-5
 *   FedRAMP SC-7, SC-5
 */

const {
  DescribeSecurityGroupsCommand,
  DescribeInstancesCommand,
  DescribeRegionsCommand,
  DescribeVpcsCommand,
  DescribeFlowLogsCommand,
} = require('@aws-sdk/client-ec2');

const { paginate } = require('../aws/client');

const DANGEROUS_PORTS = [
  { port: 22, name: 'SSH', severity: 'CRITICAL' },
  { port: 3389, name: 'RDP', severity: 'CRITICAL' },
  { port: 3306, name: 'MySQL', severity: 'HIGH' },
  { port: 5432, name: 'PostgreSQL', severity: 'HIGH' },
  { port: 1433, name: 'MSSQL', severity: 'HIGH' },
  { port: 27017, name: 'MongoDB', severity: 'HIGH' },
  { port: 6379, name: 'Redis', severity: 'HIGH' },
  { port: 9200, name: 'Elasticsearch', severity: 'HIGH' },
  { port: 2379, name: 'etcd', severity: 'HIGH' },
  { port: 23, name: 'Telnet', severity: 'CRITICAL' },
  { port: 21, name: 'FTP', severity: 'HIGH' },
];

class EC2Scanner {
  constructor(clients, accountId, region) {
    this.ec2 = clients.ec2;
    this.accountId = accountId;
    this.region = region;
  }

  async scan() {
    const findings = [];
    console.log('  → Scanning EC2 security groups and instances...');

    const [sgFindings, vpcFindings, instanceFindings] = await Promise.allSettled([
      this._checkSecurityGroups(),
      this._checkVPCFlowLogs(),
      this._checkInstances(),
    ]);

    for (const r of [sgFindings, vpcFindings, instanceFindings]) {
      if (r.status === 'fulfilled') findings.push(...r.value);
      else console.warn('  ⚠ EC2 sub-scan error:', r.reason?.message);
    }

    return findings;
  }

  async _checkSecurityGroups() {
    const findings = [];
    let groups = [];

    try {
      groups = await paginate(this.ec2, DescribeSecurityGroupsCommand, {}, 'SecurityGroups');
    } catch (e) {
      console.warn('  ⚠ Cannot list security groups:', e.message);
      return [];
    }

    console.log(`  → Checking ${groups.length} security groups`);

    for (const sg of groups) {
      const resource = `arn:aws:ec2:${this.region}:${this.accountId}:security-group/${sg.GroupId}`;
      const label = `${sg.GroupName} (${sg.GroupId})`;

      for (const rule of sg.IpPermissions || []) {
        const fromPort = rule.FromPort;
        const toPort = rule.ToPort;
        const proto = rule.IpProtocol;
        const allTraffic = proto === '-1';

        // Check for 0.0.0.0/0 inbound
        const openToWorld = [
          ...(rule.IpRanges || []).map(r => r.CidrIp),
          ...(rule.Ipv6Ranges || []).map(r => r.CidrIpv6),
        ].some(cidr => cidr === '0.0.0.0/0' || cidr === '::/0');

        if (!openToWorld) continue;

        if (allTraffic) {
          findings.push(this._finding({
            id: `EC2-SG-ALLTRAFFIC-${sg.GroupId}`,
            resource, resourceName: label,
            short: `Security group "${sg.GroupName}" allows all inbound traffic from 0.0.0.0/0`,
            description: `Security group ${label} has an inbound rule allowing ALL traffic (protocol -1) from the internet. This completely exposes all instances in this group.`,
            severity: 'CRITICAL',
            controls: [
              { framework: 'CIS', id: 'CIS-5.2', title: 'Ensure no security groups allow unrestricted inbound access' },
              { framework: 'NIST', id: 'NIST-SC-7', title: 'Boundary Protection' },
              { framework: 'FEDRAMP', id: 'FEDRAMP-SC-7', title: 'Boundary Protection' },
            ],
            remediation: {
              manual: [
                `aws ec2 revoke-security-group-ingress --group-id ${sg.GroupId} --protocol -1 --port -1 --cidr 0.0.0.0/0`,
                `# Replace with specific rules for required ports only`,
              ],
              automated: true, risk: 'MEDIUM',
            },
            current: { protocol: '-1', cidr: '0.0.0.0/0' },
            expected: { restricted: true },
          }));
          continue;
        }

        // Check specific dangerous ports
        for (const danger of DANGEROUS_PORTS) {
          if (fromPort !== undefined && toPort !== undefined) {
            if (danger.port >= fromPort && danger.port <= toPort) {
              findings.push(this._finding({
                id: `EC2-SG-PORT-${sg.GroupId}-${danger.port}`,
                resource, resourceName: label,
                short: `Security group "${sg.GroupName}" exposes ${danger.name} (port ${danger.port}) to 0.0.0.0/0`,
                description: `Security group ${label} allows inbound ${danger.name} (TCP ${danger.port}) from 0.0.0.0/0. This exposes the service to the entire internet.`,
                severity: danger.severity,
                controls: [
                  { framework: 'CIS', id: 'CIS-5.2', title: 'Ensure no security groups allow unrestricted inbound access on sensitive ports' },
                  { framework: 'NIST', id: 'NIST-SC-7', title: 'Boundary Protection' },
                  { framework: 'FEDRAMP', id: 'FEDRAMP-SC-7', title: 'Boundary Protection' },
                  { framework: 'PCI', id: 'PCI-1.2', title: 'Restrict inbound and outbound traffic' },
                ],
                remediation: {
                  manual: [
                    `# Revoke the open rule:`,
                    `aws ec2 revoke-security-group-ingress --group-id ${sg.GroupId} --protocol tcp --port ${danger.port} --cidr 0.0.0.0/0`,
                    `# Authorize only known IP ranges:`,
                    `aws ec2 authorize-security-group-ingress --group-id ${sg.GroupId} --protocol tcp --port ${danger.port} --cidr <YOUR_OFFICE_CIDR>`,
                    danger.name === 'SSH' ? `# Better: Use AWS Systems Manager Session Manager instead of SSH` : '',
                  ].filter(Boolean),
                  automated: danger.severity === 'CRITICAL' ? false : true,
                  risk: danger.severity === 'CRITICAL' ? 'HIGH' : 'MEDIUM',
                },
                current: { port: danger.port, cidr: '0.0.0.0/0' },
                expected: { port: danger.port, cidr: 'restricted' },
              }));
            }
          }
        }
      }
    }

    return findings;
  }

  async _checkVPCFlowLogs() {
    const findings = [];

    let vpcs = [];
    try {
      vpcs = await paginate(this.ec2, DescribeVpcsCommand, {}, 'Vpcs');
    } catch (e) {
      console.warn('  ⚠ Cannot list VPCs:', e.message);
      return [];
    }

    let flowLogs = [];
    try {
      flowLogs = await paginate(this.ec2, DescribeFlowLogsCommand, {}, 'FlowLogs');
    } catch (e) { /* ignore */ }

    const vpcWithLogs = new Set(flowLogs.map(fl => fl.ResourceId));

    for (const vpc of vpcs) {
      if (!vpcWithLogs.has(vpc.VpcId)) {
        const name = vpc.Tags?.find(t => t.Key === 'Name')?.Value || vpc.VpcId;
        findings.push(this._finding({
          id: `EC2-VPC-FLOWLOGS-${vpc.VpcId}`,
          resource: `arn:aws:ec2:${this.region}:${this.accountId}:vpc/${vpc.VpcId}`,
          resourceName: name,
          short: `VPC "${name}" has no flow logs enabled`,
          description: `VPC ${vpc.VpcId} has no flow logs. Without flow logs, network traffic cannot be audited for incident investigation or anomaly detection.`,
          severity: 'MEDIUM',
          controls: [
            { framework: 'CIS', id: 'CIS-3.9', title: 'Ensure VPC flow logging is enabled in all VPCs' },
            { framework: 'NIST', id: 'NIST-AU-12', title: 'Audit Record Generation' },
            { framework: 'FEDRAMP', id: 'FEDRAMP-AU-12', title: 'Audit Record Generation' },
          ],
          remediation: {
            manual: [
              `aws ec2 create-flow-logs --resource-type VPC --resource-ids ${vpc.VpcId} --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs --deliver-logs-permission-arn <IAM_ROLE_ARN>`,
            ],
            automated: true, risk: 'LOW',
          },
          current: { flowLogs: false },
          expected: { flowLogs: true },
        }));
      }
    }

    return findings;
  }

  async _checkInstances() {
    const findings = [];

    let reservations = [];
    try {
      reservations = await paginate(this.ec2, DescribeInstancesCommand,
        { Filters: [{ Name: 'instance-state-name', Values: ['running'] }] }, 'Reservations');
    } catch (e) {
      console.warn('  ⚠ Cannot list EC2 instances:', e.message);
      return [];
    }

    const instances = reservations.flatMap(r => r.Instances || []);
    console.log(`  → Checking ${instances.length} running EC2 instances`);

    for (const inst of instances) {
      const resource = `arn:aws:ec2:${this.region}:${this.accountId}:instance/${inst.InstanceId}`;
      const name = inst.Tags?.find(t => t.Key === 'Name')?.Value || inst.InstanceId;

      // IMDSv2 check
      if (inst.MetadataOptions?.HttpTokens !== 'required') {
        findings.push(this._finding({
          id: `EC2-IMDS-${inst.InstanceId}`,
          resource, resourceName: name,
          short: `Instance "${name}" does not enforce IMDSv2`,
          description: `EC2 instance ${inst.InstanceId} allows IMDSv1 requests. IMDSv1 is vulnerable to SSRF attacks that can steal instance credentials.`,
          severity: 'MEDIUM',
          controls: [
            { framework: 'CIS', id: 'CIS-5.6', title: 'Ensure that EC2 Metadata Service only allows IMDSv2' },
            { framework: 'NIST', id: 'NIST-SI-10', title: 'Information Input Validation' },
          ],
          remediation: {
            manual: [
              `aws ec2 modify-instance-metadata-options --instance-id ${inst.InstanceId} --http-tokens required --http-endpoint enabled`,
            ],
            automated: true, risk: 'LOW',
          },
          current: { httpTokens: inst.MetadataOptions?.HttpTokens || 'optional' },
          expected: { httpTokens: 'required' },
        }));
      }

      // EBS volume encryption check
      for (const bdm of inst.BlockDeviceMappings || []) {
        if (bdm.Ebs && !bdm.Ebs.Encrypted) {
          findings.push(this._finding({
            id: `EC2-EBS-${inst.InstanceId}-${bdm.Ebs.VolumeId}`,
            resource, resourceName: name,
            short: `EBS volume on "${name}" is not encrypted`,
            description: `EBS volume ${bdm.Ebs.VolumeId} on instance ${inst.InstanceId} is not encrypted at rest.`,
            severity: 'HIGH',
            controls: [
              { framework: 'CIS', id: 'CIS-2.2.1', title: 'Ensure EBS volume encryption is enabled' },
              { framework: 'NIST', id: 'NIST-SC-28', title: 'Protection of Information at Rest' },
              { framework: 'FEDRAMP', id: 'FEDRAMP-SC-28', title: 'Protection of Information at Rest' },
            ],
            remediation: {
              manual: [
                `# Enable EBS encryption by default for all new volumes:`,
                `aws ec2 enable-ebs-encryption-by-default`,
                `# For existing volume ${bdm.Ebs.VolumeId}: take snapshot → copy with encryption → create new volume → detach/reattach`,
              ],
              automated: false, risk: 'MEDIUM',
            },
            current: { encrypted: false, volumeId: bdm.Ebs.VolumeId },
            expected: { encrypted: true },
          }));
          break; // One finding per instance
        }
      }
    }

    return findings;
  }

  _finding(f) {
    return {
      ...f,
      service: 'EC2',
      status: 'OPEN',
      timestamp: new Date().toISOString(),
      accountId: this.accountId,
    };
  }
}

module.exports = EC2Scanner;
