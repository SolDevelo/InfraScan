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
            if line.lstrip().startswith(('#', '//')):
                continue
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

class CompoundInverseRule(Rule):
    """Rule that triggers when a pattern is absent AND all required resource patterns are present (directory-level)."""
    def __init__(self, id, name, severity, description, remediation, estimated_savings,
                 absent_pattern, required_patterns):
        super().__init__(id, name, severity, description, remediation, estimated_savings)
        self.absent_pattern = absent_pattern
        self.required_patterns = required_patterns  # all must be present in all_content

    def check(self, content):
        return []  # Only evaluated at directory level


class BlockAnalysisRule(Rule):
    """Base class for rules that analyse individual HCL resource blocks."""

    def _extract_blocks(self, content, resource_type):
        """Return a list of dicts with keys: name, start_line, content, first_line."""
        blocks = []
        lines = content.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            match = re.search(
                rf'resource\s*["\']({resource_type})["\'\s]+["\']([^"\']+)["\']', line
            )
            if match:
                start_line = i
                resource_name = match.group(2)
                block_lines = [line]
                brace_count = line.count('{') - line.count('}')
                i += 1
                while i < len(lines) and brace_count > 0:
                    block_lines.append(lines[i])
                    brace_count += lines[i].count('{') - lines[i].count('}')
                    i += 1
                blocks.append({
                    'name': resource_name,
                    'start_line': start_line + 1,
                    'content': '\n'.join(block_lines),
                    'first_line': lines[start_line].strip(),
                })
                continue
            i += 1
        return blocks


class RdsMultiAzNonProdRule(BlockAnalysisRule):
    """Flag RDS instances with multi_az=true whose resource name suggests a non-production environment."""
    _NON_PROD = re.compile(r'(dev|staging|stage|test|qa|nonprod|non.prod)', re.IGNORECASE)

    def check(self, content):
        matches = []
        for block in self._extract_blocks(content, r'aws_db_instance'):
            if self._NON_PROD.search(block['name']):
                if re.search(r'multi_az\s*=\s*true', block['content']):
                    matches.append({'line': block['start_line'], 'content': block['first_line']})
        return matches


class EcsNoCpuMemoryRule(BlockAnalysisRule):
    """Flag ECS task definitions that do not specify a top-level cpu or memory value."""

    def check(self, content):
        matches = []
        for block in self._extract_blocks(content, r'aws_ecs_task_definition'):
            if not re.search(r'^\s*cpu\s*=', block['content'], re.MULTILINE):
                matches.append({'line': block['start_line'], 'content': block['first_line']})
        return matches


class CwLogGroupNoRetentionRule(BlockAnalysisRule):
    """Flag CloudWatch log groups that do not set retention_in_days."""

    def check(self, content):
        matches = []
        for block in self._extract_blocks(content, r'aws_cloudwatch_log_group'):
            if not re.search(r'retention_in_days\s*=', block['content']):
                matches.append({'line': block['start_line'], 'content': block['first_line']})
        return matches


class MultipleNatGatewayRule(Rule):
    """Flag when more than one aws_nat_gateway is defined in the same file (likely redundancy)."""

    def check(self, content):
        nat_lines = [
            (i + 1, line.strip())
            for i, line in enumerate(content.splitlines())
            if re.search(r'resource\s*["\']aws_nat_gateway["\']', line)
        ]
        if len(nat_lines) > 1:
            return [{'line': ln, 'content': lc} for ln, lc in nat_lines[1:]]
        return []


class UnassociatedEipRule(Rule):
    def check(self, content):
        matches = []
        lines = content.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if re.search(r'resource\s*["\']aws_eip["\']', line):
                start_line = i
                block_lines = [line]
                
                brace_count = line.count('{') - line.count('}')
                i += 1
                while i < len(lines) and brace_count > 0:
                    block_lines.append(lines[i])
                    brace_count += lines[i].count('{') - lines[i].count('}')
                    i += 1
                
                block_content = "\n".join(block_lines)
                
                if not re.search(r'^\s*(instance|network_interface)\s*=', block_content, re.MULTILINE):
                    name_match = re.search(r'resource\s*["\']aws_eip["\']\s*["\']([^"\']+)["\']', lines[start_line])
                    is_associated = False
                    if name_match:
                        eip_name = name_match.group(1)
                        if re.search(rf'aws_eip\.{re.escape(eip_name)}(\.(id|allocation_id)|\[)', content):
                            is_associated = True
                            
                    if not is_associated:
                        matches.append({
                            "line": start_line + 1,
                            "content": lines[start_line].strip()
                        })
                continue
            i += 1
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
        name="EBS Provisioned IOPS (io1/io2)",
        severity="High",
        description="EBS volume using Provisioned IOPS (io1/io2) type. These are very expensive — io2 costs 56× more than gp3 per GB plus per-IOPS charges.",
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
    UnassociatedEipRule(
        id="COST-006",
        name="Unassociated Elastic IP",
        severity="Low",
        description="Elastic IPs are charged if not attached to a running instance or if you have more than one per instance.",
        remediation="Release unattached Elastic IPs.",
        estimated_savings="$3-4/month per IP"
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
        severity="Low",
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
        resource_pattern=r'resource\s*["\']aws_instance["\']'
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
    CwLogGroupNoRetentionRule(
        id="COST-015",
        name="CloudWatch Logs Without Retention",
        severity="Medium",
        description="CloudWatch log group without retention_in_days. Logs are kept indefinitely by default, silently growing to hundreds $/month.",
        remediation="Set appropriate retention periods for log groups (e.g., 7, 14, or 30 days).",
        estimated_savings="$5-50+/month depending on log volume"
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
    RegexRule(
        id="COST-020",
        name="RDS Old Generation Instance",
        severity="High",
        description="Usage of old generation RDS instance classes (db.t2, db.m3, db.m4, db.r3, db.r4). Newer generations are cheaper and faster.",
        remediation="Upgrade to current generation instance classes (e.g., db.t3, db.m5, db.r5, db.r6g).",
        estimated_savings="$20-100+/month per instance",
        pattern=r'instance_class\s*=\s*["\'](db\.(t2\.|m3\.|m4\.|r3\.|r4\.))'
    ),
    RegexRule(
        id="COST-021",
        name="Lambda Over-Provisioned Memory",
        severity="Medium",
        description="Lambda function with memory >= 3008 MB (the old Lambda maximum, a common cargo-cult setting). Lambda pricing scales linearly with memory; over-provisioning directly inflates costs.",
        remediation="Profile the function with AWS Lambda Power Tuning and reduce memory to the minimum needed. Most functions run fine at 256–1024 MB.",
        estimated_savings="$10-200+/month per high-traffic function",
        pattern=r'memory_size\s*=\s*(3008|[4-9]\d{3}|\d{5,})'
    ),
    RegexRule(
        id="COST-022",
        name="API Gateway REST Instead of HTTP API",
        severity="Medium",
        description="aws_api_gateway_rest_api (REST API) costs ~3.5x more per million requests than aws_apigatewayv2_api (HTTP API). Most modern use cases are supported by the HTTP API.",
        remediation="Migrate to aws_apigatewayv2_api (HTTP API v2) unless REST-specific features (usage plans, request validation, custom authorizers v1) are required.",
        estimated_savings="$1-50+/month per API depending on traffic",
        pattern=r'resource\s*["\']aws_api_gateway_rest_api["\']'
    ),
    RegexRule(
        id="COST-023",
        name="SQS Max Message Retention",
        severity="Low",
        description="SQS queue configured with the maximum 14-day (1209600 s) message retention. On high-volume queues this inflates storage costs and may indicate unprocessed message buildup.",
        remediation="Set retention to the minimum business requirement (e.g., 1–4 days for most queues) and alert on queue depth to catch processing failures early.",
        estimated_savings="$5-20+/month on high-volume queues",
        pattern=r'message_retention_seconds\s*=\s*1209600'
    ),
    RdsMultiAzNonProdRule(
        id="COST-024",
        name="RDS Multi-AZ in Non-Production Environment",
        severity="Medium",
        description="RDS instance with multi_az=true in what appears to be a non-production environment (resource name contains dev/staging/test/qa). Multi-AZ doubles the instance cost.",
        remediation="Disable multi_az for non-production databases. Reserve Multi-AZ deployments for production workloads where HA is required.",
        estimated_savings="Halves the RDS instance cost ($50-500+/month)"
    ),
    EcsNoCpuMemoryRule(
        id="COST-025",
        name="ECS Task Definition Without CPU/Memory Limits",
        severity="Medium",
        description="aws_ecs_task_definition without explicit cpu and memory limits. This leads to unpredictable cluster over-provisioning as the scheduler cannot bin-pack tasks efficiently.",
        remediation="Set cpu and memory at the task level. Start with the minimum viable values and scale up based on CloudWatch Container Insights metrics.",
        estimated_savings="Cluster right-sizing savings ($20-200+/month)"
    ),
    MultipleNatGatewayRule(
        id="COST-026",
        name="Multiple NAT Gateways (Potential Redundancy)",
        severity="Medium",
        description="More than one aws_nat_gateway defined. In development or staging environments a single NAT Gateway is usually sufficient; multiple gateways add ~$32/month each plus data-processing fees.",
        remediation="Verify that each additional NAT Gateway is needed for HA in production. For dev/staging environments consider consolidating to a single gateway.",
        estimated_savings="$32+/month per unnecessary gateway"
    ),
    CompoundInverseRule(
        id="COST-027",
        name="Missing VPC Endpoints for S3/DynamoDB",
        severity="High",
        description="NAT Gateway and S3/DynamoDB resources are present but no aws_vpc_endpoint is defined. All S3 and DynamoDB traffic is routed through the NAT Gateway, incurring per-GB data-processing charges ($0.045/GB).",
        remediation="Add Gateway VPC Endpoints for S3 (com.amazonaws.<region>.s3) and DynamoDB (com.amazonaws.<region>.dynamodb). Gateway endpoints are free and eliminate NAT data-processing charges for these services.",
        estimated_savings="$50-500+/month depending on data volume",
        absent_pattern=r'resource\s*["\']aws_vpc_endpoint["\']',
        required_patterns=[
            r'resource\s*["\']aws_nat_gateway["\']',
            r'resource\s*["\']aws_(s3_bucket|dynamodb_table)["\']',
        ]
    ),
]

def check_rules(filepath, content):
    """Check per-file rules (RegexRule and BlockAnalysisRule subclasses) against a single file."""
    findings = []
    for rule in RULES:
        if isinstance(rule, (InverseRegexRule, CompoundInverseRule)):
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
