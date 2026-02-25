import re

class Rule:
    def __init__(self, id, name, severity, description, remediation, estimated_savings):
        self.id = id
        self.name = name
        self.severity = severity
        self.description = description
        self.remediation = remediation
        self.estimated_savings = estimated_savings

    def check(self, content):
        raise NotImplementedError

class RegexRule(Rule):
    def __init__(self, id, name, severity, description, remediation, estimated_savings, pattern):
        super().__init__(id, name, severity, description, remediation, estimated_savings)
        self.pattern = pattern

    def check(self, content):
        matches = []
        for i, line in enumerate(content.splitlines()):
            if re.search(self.pattern, line):
                matches.append({
                    "line": i + 1,
                    "content": line.strip()
                })
        return matches

class InverseRegexRule(Rule):
    """Rule that triggers when a pattern is NOT found in the content"""
    def __init__(self, id, name, severity, description, remediation, estimated_savings, pattern, resource_pattern=None):
        super().__init__(id, name, severity, description, remediation, estimated_savings)
        self.pattern = pattern
        self.resource_pattern = resource_pattern

    def check(self, content):
        matches = []
        if self.resource_pattern:
            resource_found = re.search(self.resource_pattern, content, re.MULTILINE | re.DOTALL)
            pattern_found = re.search(self.pattern, content, re.MULTILINE | re.DOTALL)
            
            if resource_found and not pattern_found:
                # Find the line number of the resource
                for i, line in enumerate(content.splitlines()):
                    if re.search(self.resource_pattern, line):
                        matches.append({
                            "line": i + 1,
                            "content": line.strip()
                        })
                        break
        return matches

RULES = [
    RegexRule(
        id="COST-001",
        name="Old Generation Instance",
        severity="High",
        description="Usage of old generation EC2 instances (e.g., t2, m3, c4, r3). Newer generations are often cheaper and faster.",
        remediation="Upgrade to current generation instances (e.g., t3, m5, c5, r5).",
        estimated_savings="$10-50/month per instance",
        pattern=r'instance_type\s*=\s*["\'](t2\.|m3\.|c4\.|r3\.)'
    ),
    RegexRule(
        id="COST-002",
        name="Expensive Instance Type",
        severity="High",
        description="Usage of very large instance types (xlarge+). Ensure this capacity is actually needed.",
        remediation="Review utilization metrics. Consider rightsizing or Spot Instances.",
        estimated_savings="$100-500+/month per instance",
        pattern=r'instance_type\s*=\s*["\'].*\.(8xlarge|12xlarge|16xlarge|24xlarge|metal)["\']'
    ),
    RegexRule(
        id="COST-003",
        name="Unencrypted EBS Volume",
        severity="High",
        description="EBS volume is not encrypted. This is a security risk and often indicates unmanaged infrastructure.",
        remediation="Enable encryption for EBS volumes.",
        estimated_savings="Risk mitigation (priceless)",
        pattern=r'encrypted\s*=\s*false'
    ),
     RegexRule(
        id="COST-004",
        name="Provisioned IOPS (io1/io2)",
        severity="High",
        description="Usage of Provisioned IOPS SSD (io1/io2). These are very expensive.",
        remediation="Verify if gp3 can meet performance requirements at a lower cost.",
        estimated_savings="$50-200+/month per volume",
        pattern=r'type\s*=\s*["\'](io1|io2)["\']'
    ),
    RegexRule(
        id="COST-005",
        name="Expensive NAT Gateway",
        severity="High",
        description="NAT Gateways are expensive managed services. Ensure they are strictly necessary.",
        remediation="Consider using VPC Endpoints, NAT Instances for non-critical workloads, or share a single NAT Gateway across multiple subnets.",
        estimated_savings="$30-40/month + data processing fees per gateway",
        pattern=r'resource\s*["\']aws_nat_gateway["\']'
    ),
    RegexRule(
        id="COST-006",
        name="Elastic IP Usage",
        severity="Low",
        description="Elastic IPs are charged if not attached to a running instance or if you have more than one per instance.",
        remediation="Release unattached Elastic IPs.",
        estimated_savings="$3-4/month per IP",
        pattern=r'resource\s*["\']aws_eip["\']'
    ),
    RegexRule(
        id="COST-007",
        name="DynamoDB Provisioned Mode",
        severity="Medium",
        description="Provisioned capacity mode charges for capacity regardless of usage. On-demand is often cheaper for irregular workloads.",
        remediation="Switch to On-Demand billing mode if traffic is unpredictable.",
        estimated_savings="Variable (potentially 90% savings for idle tables)",
        pattern=r'billing_mode\s*=\s*["\']PROVISIONED["\']'
    ),
    RegexRule(
        id="COST-008",
        name="EC2 Detailed Monitoring",
        severity="Low",
        description="Detailed monitoring for EC2 instances incurs extra costs.",
        remediation="Disable detailed monitoring if standard 5-minute metrics are sufficient.",
        estimated_savings="$2-3/month per instance",
        pattern=r'monitoring\s*=\s*true'
    ),
    RegexRule(
        id="COST-009",
        name="Old Generation Storage (gp2)",
        severity="Medium",
        description="Using gp2 EBS volumes when gp3 provides better performance at lower cost.",
        remediation="Migrate from gp2 to gp3 volumes. gp3 offers 20% cost savings and better baseline performance.",
        estimated_savings="$10-30/month per volume",
        pattern=r'volume_type\s*=\s*["\']gp2["\']'
    ),
    InverseRegexRule(
        id="COST-010",
        name="Missing S3 Lifecycle Policy",
        severity="Medium",
        description="S3 bucket without lifecycle rules. Objects are retained indefinitely, increasing storage costs.",
        remediation="Define lifecycle rules to transition objects to cheaper storage classes (e.g., Glacier) or delete them after a retention period.",
        estimated_savings="$20-100+/month depending on bucket size",
        pattern=r'aws_s3_bucket_lifecycle',
        resource_pattern=r'resource\s*["\']aws_s3_bucket["\']'
    ),
    InverseRegexRule(
        id="COST-011",
        name="Missing AWS Budget",
        severity="High",
        description="No AWS budget configured. Budgets help monitor and control spending with alerts.",
        remediation="Create AWS budgets with alerts for forecasted and actual costs to avoid unexpected charges.",
        estimated_savings="Prevention of cost overruns (potentially thousands)",
        pattern=r'aws_budgets_budget',
        resource_pattern=r'provider\s*["\']aws["\']'
    ),
    InverseRegexRule(
        id="COST-012",
        name="Missing Spot Instance Usage",
        severity="Medium",
        description="No spot instances detected. Spot instances can save 50-90% on compute costs for interruptible workloads.",
        remediation="Use spot instances for batch jobs, data analysis, and optional tasks. Consider aws_spot_instance_request or spot_price in launch templates.",
        estimated_savings="50-90% savings on compute (hundreds to thousands per month)",
        pattern=r'(spot_instance_request|spot_price|spot\s*=|provisioning_model|market_type)',
        resource_pattern=r'(instance_type\s*=|aws_instance|aws_launch)'
    ),
    RegexRule(
        id="COST-013",
        name="Expensive Premium Storage",
        severity="Medium",
        description="Using premium storage tiers (Premium_LRS, io1, io2) which are significantly more expensive.",
        remediation="Evaluate if Standard storage or gp3 volumes meet performance requirements. Premium storage should only be used when necessary.",
        estimated_savings="$30-100+/month per disk",
        pattern=r'storage_account_type\s*=\s*["\']Premium_LRS["\']'
    ),
    RegexRule(
        id="COST-014",
        name="Route53 Health Checks",
        severity="Low",
        description="Route53 health checks incur monthly costs. May not be necessary for all resources.",
        remediation="Remove health checks for non-critical resources or personal projects.",
        estimated_savings="$0.50/month per health check",
        pattern=r'resource\s*["\']aws_route53_health_check["\']'
    ),
    RegexRule(
        id="COST-015",
        name="CloudWatch Logs Without Retention",
        severity="Medium",
        description="CloudWatch logs without retention policy. Logs are kept indefinitely, increasing storage costs.",
        remediation="Set appropriate retention periods for log groups (e.g., 7, 14, 30 days).",
        estimated_savings="$5-50+/month depending on log volume",
        pattern=r'aws_cloudwatch_log_group[^}]*\n(?!.*retention_in_days)'
    ),
    RegexRule(
        id="COST-016",
        name="Large Root Volume",
        severity="Low",
        description="Oversized root block device. Many workloads don't require large root volumes.",
        remediation="Reduce root volume size to minimum required (typically 8-20 GB for most Linux instances).",
        estimated_savings="$2-10/month per instance",
        pattern=r'volume_size\s*=\s*([5-9]\d|[1-9]\d{2,})'
    ),
    InverseRegexRule(
        id="COST-017",
        name="Missing Cost and Usage Report",
        severity="Medium",
        description="No AWS Cost and Usage Report (CUR) configured. CUR provides detailed cost tracking and analysis.",
        remediation="Enable AWS Cost and Usage Reports to track spending patterns and identify optimization opportunities.",
        estimated_savings="Enables cost optimization (indirect savings)",
        pattern=r'aws_cur_report_definition',
        resource_pattern=r'provider\s*["\']aws["\']'
    ),
    RegexRule(
        id="COST-018",
        name="High DynamoDB Capacity",
        severity="Medium",
        description="High provisioned read/write capacity units for DynamoDB. May indicate overprovisioning.",
        remediation="Review actual usage metrics and reduce capacity, or switch to PAY_PER_REQUEST billing mode.",
        estimated_savings="$50-200+/month per table",
        pattern=r'(read_capacity|write_capacity)\s*=\s*([5-9]\d|\d{3,})'
    ),
    RegexRule(
        id="COST-019",
        name="Load Balancer for Single Instance",
        severity="Medium",
        description="Load balancer detected. Verify it's needed - load balancers cost $15-20/month even if unused.",
        remediation="Consider if load balancer is necessary for single-instance deployments or low-traffic applications.",
        estimated_savings="$15-25/month per load balancer",
        pattern=r'resource\s*["\']aws_(lb|elb|alb)["\']'
    ),
]

def check_rules(filepath, content):
    """Check only RegexRule rules (not InverseRegexRules) against a single file."""
    findings = []
    for rule in RULES:
        if isinstance(rule, InverseRegexRule):
            continue
            
        matches = rule.check(content)
        for match in matches:
            findings.append({
                "file": filepath,
                "rule_id": rule.id,
                "rule_name": rule.name,
                "severity": rule.severity,
                "description": rule.description,
                "remediation": rule.remediation,
                "estimated_savings": rule.estimated_savings,
                "line": match['line'],
                "match_content": match['content']
            })
    return findings
