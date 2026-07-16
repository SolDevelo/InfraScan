"""
Cost estimation module for InfraScan.
"""

import os
import re
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Pricing ───────────────────────────────────────────────────────────────────

def load_pricing() -> dict:
    """Load pricing_table.json bundled with the reporter package."""
    path = os.path.join(os.path.dirname(__file__), "pricing_table.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class SavingsResult:
    saving_low_usd:  float
    saving_high_usd: float
    before_usd:      float
    after_usd:       float
    assumptions:     list
    confidence:      str   # "high" | "medium" | "low"


@dataclass
class ResourceCost:
    resource_type:    str
    resource_name:    str
    file:             str
    line:             int
    fixed_usd_month:  float
    usage_usd_month:  float
    min_usd_month:    float  # guaranteed floor: fixed charges only (zero usage)
    total_usd_month:  float  # point estimate: fixed + expected usage
    assumptions:      list
    confidence:       str   # "high" | "medium" | "low"


# ── Usage defaults and traffic profiles (loaded from JSON) ───────────────────

def load_usage_defaults() -> Dict[str, float]:
    """Load usage_defaults.json bundled with the reporter package."""
    path = os.path.join(os.path.dirname(__file__), "usage_defaults.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_traffic_profiles() -> Dict[str, Dict[str, float]]:
    """Load traffic_profiles.json bundled with the reporter package."""
    path = os.path.join(os.path.dirname(__file__), "traffic_profiles.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Module-level constants — loaded once at import time; importable by callers.
USAGE_DEFAULTS: Dict[str, float] = load_usage_defaults()
TRAFFIC_PROFILES: Dict[str, Dict[str, float]] = load_traffic_profiles()


# ── Block extraction ──────────────────────────────────────────────────────────

def extract_all_blocks(scan_path: str) -> Dict[str, List[dict]]:
    """
    Walk all .tf files under *scan_path* and extract resource blocks.

    Returns a dict keyed by resource_type, each value being a list of block
    dicts with keys: name, file, start_line, content, first_line,
    resource_type.
    """
    blocks: Dict[str, List[dict]] = {}
    for root, _dirs, files in os.walk(scan_path):
        for fname in files:
            if not fname.endswith(".tf"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError as exc:
                logger.warning("Failed to read %s: %s", fpath, exc)
                continue
            _extract_blocks_from_content(content, fpath, blocks)
    return blocks


def _extract_blocks_from_content(
    content: str, filepath: str, blocks: Dict[str, List[dict]]
) -> None:
    """Append parsed resource blocks from *content* into *blocks*."""
    lines = content.splitlines()
    i = 0
    while i < len(lines):
        match = re.match(
            r'\s*resource\s+["\']([^"\']+)["\']\s+["\']([^"\']+)["\']',
            lines[i],
        )
        if match:
            resource_type = match.group(1)
            resource_name = match.group(2)
            start_line = i + 1  # 1-based
            block_lines = [lines[i]]
            brace_count = lines[i].count("{") - lines[i].count("}")
            i += 1
            while i < len(lines) and brace_count > 0:
                block_lines.append(lines[i])
                brace_count += lines[i].count("{") - lines[i].count("}")
                i += 1
            blocks.setdefault(resource_type, []).append(
                {
                    "name":          resource_name,
                    "file":          filepath,
                    "start_line":    start_line,
                    "content":       "\n".join(block_lines),
                    "first_line":    lines[start_line - 1].strip(),
                    "resource_type": resource_type,
                }
            )
            continue
        i += 1


def _paths_match(block_file: str, filepath: str) -> bool:
    """Compare two file paths that may be absolute vs relative.

    ``block_file`` is always an absolute path (from ``extract_all_blocks``).
    ``filepath`` may be a relative path (normalised by ``scan_directory``).
    """
    if block_file == filepath:
        return True
    # Relative path is a suffix of the absolute path after a separator.
    sep = "/"
    return block_file.endswith(sep + filepath) or block_file.replace("\\", "/").endswith(sep + filepath.replace("\\", "/"))


def _find_block(
    blocks: Dict[str, List[dict]], filepath: str, line: int
) -> Optional[dict]:
    """Return the block that spans *line* in *filepath*, or None."""
    for _rtype, blist in blocks.items():
        for block in blist:
            if not _paths_match(block["file"], filepath):
                continue
            block_line_count = block["content"].count("\n") + 1
            end_line = block["start_line"] + block_line_count
            if block["start_line"] <= line <= end_line:
                return block
    return None


# ── Traffic profile auto-detection ────────────────────────────────────────────

def detect_traffic_profile(blocks: Dict[str, List[dict]]) -> str:
    """
    Infer *small* / *medium* / *large* traffic profile from infra block counts.

    Heuristics:
    - Number of EC2 instances, Lambda functions, RDS instances, NAT gateways,
      load balancers, ECS task definitions.
    - Presence of very large instance types (8xlarge+).

    Returns one of: ``"small"``, ``"medium"``, ``"large"``.
    """
    instance_count = len(blocks.get("aws_instance", []))
    lambda_count   = len(blocks.get("aws_lambda_function", []))
    nat_count      = len(blocks.get("aws_nat_gateway", []))
    lb_count       = (
        len(blocks.get("aws_lb", []))
        + len(blocks.get("aws_alb", []))
        + len(blocks.get("aws_elb", []))
    )
    ecs_count = len(blocks.get("aws_ecs_task_definition", []))
    rds_count = len(blocks.get("aws_db_instance", []))

    large_instances = sum(
        1
        for b in blocks.get("aws_instance", [])
        if re.search(
            r'instance_type\s*=\s*["\'][^"\']*\.(8xlarge|10xlarge|12xlarge|16xlarge|24xlarge|metal)',
            b.get("content", ""),
        )
    )

    score = (
        instance_count * 2
        + lambda_count  * 1
        + nat_count     * 8
        + lb_count      * 4
        + ecs_count     * 2
        + rds_count     * 3
        + large_instances * 15
    )

    if score >= 50:
        return "large"
    if score >= 15:
        return "medium"
    return "small"


def scale_usage_defaults(
    usage: dict, profile: str, blocks: Dict[str, List[dict]]
) -> dict:
    """
    Return a new usage dict with Tier 2 profile overrides applied.

    ``nat_gb_per_day`` in the profiles represents the *total* estimated daily
    NAT transfer for the whole environment.  It scales up with compute (more
    instances → more egress), then is divided by the number of NAT gateways
    so each gateway gets an equal per-gateway share.  This prevents the
    per-gateway cost estimate from exploding when many parallel gateways are
    defined for multi-AZ redundancy.
    """
    scaled = dict(usage)
    profile_overrides = TRAFFIC_PROFILES.get(profile, TRAFFIC_PROFILES["small"])
    scaled.update(profile_overrides)

    instance_count = len(blocks.get("aws_instance", [])) + len(
        blocks.get("aws_ecs_task_definition", [])
    )
    nat_count    = max(1, len(blocks.get("aws_nat_gateway", [])))
    s3_count     = max(1, len(blocks.get("aws_s3_bucket", [])))
    lambda_count = max(1, len(blocks.get("aws_lambda_function", [])))
    apigw_count  = max(1,
        len(blocks.get("aws_api_gateway_rest_api", []))
        + len(blocks.get("aws_apigatewayv2_api", []))
    )
    ep_count  = max(1, len(blocks.get("aws_vpc_endpoint", [])))
    tgw_count = max(1, len(blocks.get("aws_ec2_transit_gateway_vpc_attachment", [])))
    lb_count  = max(1,
        len(blocks.get("aws_lb", []))
        + len(blocks.get("aws_alb", []))
        + len(blocks.get("aws_elb", []))
    )

    # Total egress scales with compute; each gateway receives an equal share.
    nat_scale = max(1.0, instance_count / 5.0)
    total_nat_gb = scaled["nat_gb_per_day"] * nat_scale
    scaled["nat_gb_per_day"] = round(total_nat_gb / nat_count, 2)

    # S3 / Lambda / API GW: profile value is the *total* across all resources; divide
    # evenly so each bucket / function / API gets a per-resource estimate.
    scaled["s3_gb_standard"]            = round(scaled["s3_gb_standard"] / s3_count, 2)
    scaled["lambda_invocations_per_mo"] = max(1, scaled["lambda_invocations_per_mo"] // lambda_count)
    scaled["api_calls_per_mo"]          = max(1, scaled["api_calls_per_mo"] // apigw_count)

    # Usage-based data params: divide total environment estimate by resource count.
    if "vpc_endpoint_data_gb_per_mo" in scaled:
        scaled["vpc_endpoint_data_gb_per_mo"] = round(scaled["vpc_endpoint_data_gb_per_mo"] / ep_count, 2)
    if "tgw_data_processed_gb_per_mo" in scaled:
        scaled["tgw_data_processed_gb_per_mo"] = round(scaled["tgw_data_processed_gb_per_mo"] / tgw_count, 2)
    if "lb_data_processed_gb" in scaled:
        scaled["lb_data_processed_gb"] = round(scaled["lb_data_processed_gb"] / lb_count, 2)

    return scaled


# ── EC2 / RDS upgrade maps ────────────────────────────────────────────────────

_EC2_UPGRADE_MAP: Dict[str, str] = {
    "t2.nano":    "t3.nano",
    "t2.micro":   "t3.micro",
    "t2.small":   "t3.small",
    "t2.medium":  "t3.medium",
    "t2.large":   "t3.large",
    "t2.xlarge":  "t3.xlarge",
    "t2.2xlarge": "t3.2xlarge",
    "m3.medium":  "m5.large",
    "m3.large":   "m5.large",
    "m4.large":   "m5.large",
    "m4.xlarge":  "m5.xlarge",
    "m4.2xlarge": "m5.2xlarge",
    "m4.4xlarge": "m5.4xlarge",
    "m4.10xlarge": "m5.8xlarge",
    "c4.large":   "c5.large",
    "c4.xlarge":  "c5.xlarge",
    "c4.2xlarge": "c5.2xlarge",
    "c4.4xlarge": "c5.2xlarge",
    "r3.large":   "r5.large",
    "r3.xlarge":  "r5.xlarge",
    "r3.2xlarge": "r5.2xlarge",
    "r3.4xlarge": "r5.2xlarge",
    "r4.large":   "r5.large",
    "r4.xlarge":  "r5.xlarge",
    "r4.2xlarge": "r5.2xlarge",
    "r4.4xlarge": "r5.2xlarge",
}

_RDS_UPGRADE_MAP: Dict[str, str] = {
    "db.t2.micro":    "db.t3.micro",
    "db.t2.small":    "db.t3.small",
    "db.t2.medium":   "db.t3.medium",
    "db.t2.large":    "db.t3.large",
    "db.t2.xlarge":   "db.t3.xlarge",
    "db.t2.2xlarge":  "db.t3.2xlarge",
    "db.m3.medium":   "db.m5.large",
    "db.m3.large":    "db.m5.large",
    "db.m4.large":    "db.m5.large",
    "db.m4.xlarge":   "db.m5.xlarge",
    "db.m4.2xlarge":  "db.m5.2xlarge",
    "db.m4.4xlarge":  "db.m5.4xlarge",
    "db.m4.10xlarge": "db.m5.12xlarge",
    "db.r3.large":    "db.r5.large",
    "db.r3.xlarge":   "db.r5.xlarge",
    "db.r3.2xlarge":  "db.r5.2xlarge",
    "db.r3.4xlarge":  "db.r5.4xlarge",
    "db.r3.8xlarge":  "db.r5.8xlarge",
    "db.r4.large":    "db.r5.large",
    "db.r4.xlarge":   "db.r5.xlarge",
    "db.r4.2xlarge":  "db.r5.2xlarge",
    "db.r4.4xlarge":  "db.r5.4xlarge",
    "db.r4.8xlarge":  "db.r5.8xlarge",
    "db.r4.16xlarge": "db.r5.16xlarge",
}


# ── Phase 1 — per-rule savings functions ─────────────────────────────────────

def _savings_cost001(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-001 EC2 old-gen → new-gen upgrade."""
    ec2 = pricing.get("ec2_instances", {})
    m = re.search(r'instance_type\s*=\s*["\']([^"\']+)["\']', block_content)
    if not m:
        return SavingsResult(0.0, 0.0, 0.0, 0.0, [], "low")
    inst = m.group(1).strip()
    before = ec2.get(inst, 0.0)
    if before == 0.0:
        before = 100.0
        conf = "low"
    else:
        conf = "high"
    new_inst = _EC2_UPGRADE_MAP.get(inst)
    if new_inst:
        after = ec2.get(new_inst, before * 0.85)
    else:
        after = before * 0.85
    saving = max(0.0, before - after)
    return SavingsResult(
        saving, saving, before, after,
        [f"{inst} → {new_inst or 'new-gen'} on-demand us-east-1"],
        conf,
    )


def _savings_cost002(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-002 Expensive instance type — rightsizing opportunity."""
    ec2_prices = pricing.get("ec2_instances", {})
    m = re.search(r'instance_type\s*=\s*["\']([^"\']+)["\']', block_content)
    inst_cost = ec2_prices.get(m.group(1).strip(), 0.0) if m else 0.0
    if inst_cost == 0.0:
        inst_cost = usage.get("_var_hints", {}).get("_ec2_fallback_cost", 500.0)
    saving_high = round(inst_cost * 0.50, 2)
    inst_name = m.group(1).strip() if m else "unknown"
    return SavingsResult(
        0.0, saving_high, inst_cost, round(inst_cost * 0.50, 2),
        [
            f"{inst_name} on-demand ${inst_cost:.2f}/mo",
            "low=$0: workload may genuinely need this capacity",
            "high=50% saving from rightsizing to a smaller type",
        ],
        "low",
    )


def _savings_cost016(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-016 Oversized root volume."""
    gp3_rate = pricing.get("ebs_per_gb_month", {}).get("gp3", 0.08)
    size_m = re.search(r'volume_size\s*=\s*(\d+)', block_content)
    size = int(size_m.group(1)) if size_m else None
    if size is None:
        # try variable resolution via sibling .tf files
        var_m = re.search(r'volume_size\s*=\s*(var\.\S+|local\.\S+)', block_content)
        if var_m:
            filepath = usage.get("_var_hints", {}).get("_filepath", "")
            size = _resolve_number_from_files(var_m.group(1), filepath)
    baseline_gb = 30
    if size is None or size <= baseline_gb:
        return SavingsResult(0.0, 0.0, 0.0, 0.0,
                             [f"volume_size not resolved or ≤{baseline_gb} GB"], "low")
    excess = size - baseline_gb
    before = round(size * gp3_rate, 2)
    after = round(baseline_gb * gp3_rate, 2)
    saving_high = round(excess * gp3_rate, 2)
    conf = "high" if size_m else "medium"
    return SavingsResult(
        0.0, saving_high, before, after,
        [
            f"{size}GB root volume; {excess}GB above {baseline_gb}GB baseline × ${gp3_rate}/GB/mo",
            "low=$0: workload may require this space",
        ],
        conf,
    )


def _savings_cost019(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-019 Load balancer for single instance."""
    hourly = pricing.get("alb_per_hour", 0.02646)
    lcu_hourly = pricing.get("alb_per_lcu_hour", 0.0093)
    lcus = usage.get("alb_lcus_per_hour", 1.0)
    before = round((hourly + lcu_hourly * lcus) * 730, 2)
    return SavingsResult(
        0.0, before, before, 0.0,
        [
            f"ALB ${hourly}/hr base + {lcus} LCU × ${lcu_hourly}/hr × 730h/mo",
            "low=$0: ALB may be required for SSL termination or path routing",
        ],
        "medium",
    )


def _savings_cost004(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-004 io1/io2 → gp3."""
    ebs          = pricing.get("ebs_per_gb_month", {})
    iops_pricing = pricing.get("ebs_iops_per_iops_month", {})
    size_m = re.search(r'(?:volume_size|size)\s*=\s*(\d+)', block_content)
    iops_m = re.search(r'\biops\s*=\s*(\d+)', block_content)
    vol_m  = re.search(r'(?:volume_type|type)\s*=\s*["\']([^"\']+)["\']', block_content)
    size: Optional[int] = int(size_m.group(1)) if size_m else None
    iops     = int(iops_m.group(1)) if iops_m else 3000
    vol_type = vol_m.group(1) if vol_m else "io1"

    if size is None:
        # Try variable resolution; default to 50
        filepath = usage.get("_filepath", "")
        var_ref_m = re.search(r'(?:volume_size|size)\s*=\s*((?:var|local)\.\S+)', block_content)
        if var_ref_m and filepath:
            resolved = _resolve_number_from_files(var_ref_m.group(1), filepath)
            if resolved is not None:
                size = resolved
    if size is None:
        size = 50

    per_gb   = ebs.get(vol_type, ebs.get("io1", 0.125))
    per_iops = iops_pricing.get(vol_type, iops_pricing.get("io1", 0.065))
    before = round(size * per_gb + iops * per_iops, 2)
    after  = round(size * ebs.get("gp3", 0.08), 2)
    saving = round(max(0.0, before - after), 2)
    conf   = "high" if (size_m and iops_m) else "medium"
    return SavingsResult(
        saving, saving, before, after,
        [f"{vol_type} {size}GB {iops}IOPS → gp3 (${before:.2f} → ${after:.2f})"],
        conf,
    )


def _savings_cost005(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-005 NAT Gateway — uncertain removal: may be required by workloads."""
    hourly = pricing.get("nat_gateway_hourly", 0.045)
    per_gb = pricing.get("nat_gateway_per_gb", 0.045)
    gb_day = usage.get("nat_gb_per_day", 10.0)
    before = round(hourly * 730 + per_gb * gb_day * 30, 2)
    return SavingsResult(
        0.0, before,   # low=0: gateway may be required; high: full cost if replaced by VPC endpoints
        before, 0.0,
        [
            f"$0.045/hr×730h + $0.045/GB×{gb_day}GB/d×30d",
            "low=$0: may be necessary; high: full replacement with VPC endpoints",
        ],
        "low",
    )


def _savings_cost006(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-006 Unassociated Elastic IP."""
    hourly = pricing.get("eip_unattached_per_hour", 0.005)
    before = hourly * 730
    return SavingsResult(
        before, before, before, 0.0,
        ["$0.005/hr × 730h/mo unattached EIP charge"],
        "high",
    )


def _savings_cost007(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-007 DynamoDB provisioned → on-demand — uncertain: on-demand may cost more under sustained load."""
    per_rcu_hr = pricing.get("dynamodb_per_rcu_hour", 0.00013)
    per_wcu_hr = pricing.get("dynamodb_per_wcu_hour", 0.00065)
    rcu_m = re.search(r'read_capacity\s*=\s*(\d+)', block_content)
    wcu_m = re.search(r'write_capacity\s*=\s*(\d+)', block_content)
    rcu = int(rcu_m.group(1)) if rcu_m else 5
    wcu = int(wcu_m.group(1)) if wcu_m else 5
    before = (rcu * per_rcu_hr + wcu * per_wcu_hr) * 730
    idle_pct = usage.get("dynamo_idle_pct", 0.70)
    saving = before * idle_pct * idle_pct
    after  = before - saving
    return SavingsResult(
        0.0, saving,   # low=0: on-demand can cost more under sustained load
        before, after,
        [
            f"RCU={rcu} WCU={wcu}, assumed {int(idle_pct*100)}% idle both dimensions",
            "low=$0: on-demand billing can exceed provisioned under steady load",
        ],
        "low",
    )


def _resolve_number_from_files(var_expr: str, filepath: str) -> Optional[int]:
    """
    Resolve a Terraform variable reference (e.g. ``var.grq["root_dev_size"]``,
    ``var.root_dev_size``, ``local.size``) to a concrete integer by scanning all
    sibling ``.tf`` files in the same directory for matching assignments.

    Returns the most-common numeric value found, or ``None`` if unresolvable.
    """
    if not filepath:
        return None

    # Extract the attribute key from expressions such as:
    #   var.grq["root_dev_size"]          → root_dev_size
    #   var.metrics["root_dev_size"]       → root_dev_size
    #   var.root_dev_size                  → root_dev_size
    #   local.volume_size                  → volume_size
    key_m = re.search(r'\["([^"]+)"\]', var_expr)
    if not key_m:
        key_m = re.search(r'(?:var|local)\.(\w+)\.(\w+)', var_expr)
        if key_m:
            key_m = type('_M', (), {'group': lambda self, n: key_m.group(n)})()
            # Use the last segment as the key
            key_m = re.search(r'\.(\w+)$', var_expr)
    if not key_m:
        key_m = re.search(r'(?:var|local)\.(\w+)', var_expr)

    if not key_m:
        return None

    key = key_m.group(1)

    # Read all sibling .tf files in the same directory
    try:
        dir_path = os.path.dirname(filepath)
        combined = ""
        for fname in sorted(os.listdir(dir_path)):
            if fname.endswith(".tf"):
                try:
                    with open(
                        os.path.join(dir_path, fname), "r", encoding="utf-8", errors="replace"
                    ) as fh:
                        combined += fh.read() + "\n"
                except Exception:
                    pass
    except Exception:
        return None

    if not combined:
        return None

    # Find all assignments: key = <integer> (quoted or unquoted key)
    values = [
        int(m)
        for m in re.findall(
            rf'["\']?{re.escape(key)}["\']?\s*=\s*(\d+)', combined
        )
    ]

    if not values:
        return None

    # Return the most common value as the representative estimate
    from collections import Counter
    return Counter(values).most_common(1)[0][0]


def _savings_cost008(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-008 EC2 detailed monitoring — fixed $2.10/instance/month."""
    before = 2.10
    return SavingsResult(
        before, before, before, 0.0,
        ["fixed $2.10/instance/month for detailed monitoring"],
        "high",
    )


def _savings_cost009(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-009 gp2 → gp3 EBS volume."""
    ebs = pricing.get("ebs_per_gb_month", {})
    size_m = re.search(r'volume_size\s*=\s*(\d+)', block_content)
    size: Optional[int] = int(size_m.group(1)) if size_m else None
    conf = "high"
    assumptions: list = []

    if size is None:
        # Try to resolve a variable reference such as var.grq["root_dev_size"]
        filepath = usage.get("_filepath", "")
        var_ref_m = re.search(r'volume_size\s*=\s*((?:var|local)\.\S+)', block_content)
        if var_ref_m and filepath:
            resolved = _resolve_number_from_files(var_ref_m.group(1), filepath)
            if resolved is not None:
                size = resolved
                conf = "medium"
                assumptions.append(
                    f"volume_size resolved from variable ({var_ref_m.group(1)} = {size}GB)"
                )

    if size is None:
        size = 50
        conf = "medium"
        assumptions.append("volume_size not found, assumed 50 GB")

    before = size * ebs.get("gp2", 0.10)
    after  = size * ebs.get("gp3", 0.08)
    saving = before - after
    assumptions.insert(0, f"{size}GB gp2→gp3 ($0.02/GB/mo saving)")
    return SavingsResult(saving, saving, before, after, assumptions, conf)


def _savings_cost010(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-010 Missing S3 Lifecycle Policy — estimate from storage tiering.

    Assumes a default bucket size of 200 GB.  Two tiering scenarios:
      low:  40 % of data transitions to Standard-IA
      high: 70 % of data transitions to Glacier
    Confidence is "low" because actual stored GB is unknown from Terraform.
    """
    per_gb_std = pricing.get("s3_per_gb_standard", 0.023)
    per_gb_ia  = pricing.get("s3_per_gb_ia",       0.0125)
    per_gb_glc = pricing.get("s3_per_gb_glacier",  0.004)
    gb         = usage.get("s3_lifecycle_gb",       200.0)  # 200 GB default

    before       = round(gb * per_gb_std, 2)
    saving_low   = round(gb * 0.40 * (per_gb_std - per_gb_ia),  2)
    saving_high  = round(gb * 0.70 * (per_gb_std - per_gb_glc), 2)
    after_high   = round(max(0.0, before - saving_high), 2)
    return SavingsResult(
        saving_low, saving_high,
        before, after_high,
        [
            f"Assumed {int(gb)}GB stored; low=40% to Standard-IA, high=70% to Glacier",
            "Actual savings depend on real data volume and access patterns",
        ],
        "low",
    )


def _savings_cost014(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-014 Route53 health check."""
    before = pricing.get("route53_health_check_per_month", 0.50)
    return SavingsResult(
        before, before, before, 0.0,
        ["$0.50/health-check/month"],
        "high",
    )


def _savings_cost015(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-015 CloudWatch Logs without retention."""
    per_gb = pricing.get("cloudwatch_logs_per_gb_stored", 0.03)
    gb_mo  = usage.get("cw_log_gb_per_month", 5.0)
    # Without retention: logs accumulate indefinitely — model as 12 months stored.
    # With 30-day retention: ~1 month stored at any time.
    before = per_gb * gb_mo * 12
    after  = per_gb * gb_mo * 1
    saving = before - after
    return SavingsResult(
        saving, saving, before, after,
        [f"{gb_mo}GB/mo ingested, no-retention≈12mo stored vs 30-day≈1mo stored"],
        "medium",
    )


def _savings_cost020(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-020 RDS old-gen → new-gen upgrade."""
    rds = pricing.get("rds_instances", {})
    m   = re.search(r'instance_class\s*=\s*["\']([^"\']+)["\']', block_content)
    if not m:
        return SavingsResult(0.0, 0.0, 0.0, 0.0, [], "low")
    inst     = m.group(1).strip()
    before   = rds.get(inst, 0.0)
    if before == 0.0:
        # Instance type not in pricing table — use a conservative floor so the
        # calculated saving is shown instead of falling back to static text.
        before = 100.0
        conf = "low"
    else:
        conf = "high"
    new_inst = _RDS_UPGRADE_MAP.get(inst)
    after    = rds.get(new_inst, before * 0.85) if new_inst else before * 0.85
    saving   = max(0.0, before - after)
    return SavingsResult(
        saving, saving, before, after,
        [f"{inst} → {new_inst or 'new-gen'} on-demand us-east-1"],
        conf,
    )


def _savings_cost021(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-021 Lambda over-provisioned memory."""
    per_gb_sec = pricing.get("lambda_per_gb_second", 0.0000166667)
    per_1m_req = pricing.get("lambda_per_1m_requests", 0.20)
    invocations = usage.get("lambda_invocations_per_mo", 1_000_000)
    duration_ms = usage.get("lambda_avg_duration_ms", 200.0)
    after_mb    = usage.get("lambda_memory_after_mb", 1024.0)

    mem_m     = re.search(r'memory_size\s*=\s*(\d+)', block_content)
    before_mb = float(mem_m.group(1)) if mem_m else 3008.0

    def _lambda_cost(mem_mb: float) -> float:
        gb_seconds = (mem_mb / 1024) * (duration_ms / 1000) * invocations
        return per_gb_sec * gb_seconds + per_1m_req * (invocations / 1_000_000)

    before = _lambda_cost(before_mb)
    after  = _lambda_cost(after_mb)
    saving = max(0.0, before - after)
    return SavingsResult(
        saving, saving, before, after,
        [
            f"{int(before_mb)}MB → {int(after_mb)}MB",
            f"{invocations/1e6:.0f}M invocations/mo, {duration_ms}ms avg",
        ],
        "medium",
    )


def _savings_cost022(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-022 API Gateway REST → HTTP API."""
    rest_per_1m = pricing.get("api_gw_rest_per_1m_calls", 3.50)
    http_per_1m = pricing.get("api_gw_http_per_1m_calls", 1.00)
    calls_mo    = usage.get("api_calls_per_mo", 1_000_000)
    before = rest_per_1m * calls_mo / 1_000_000
    after  = http_per_1m * calls_mo / 1_000_000
    saving = before - after
    return SavingsResult(
        saving, saving, before, after,
        [f"{calls_mo/1e6:.0f}M calls/mo REST→HTTP API ($3.50→$1.00 per 1M)"],
        "medium",
    )


def _savings_cost023(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-023 SQS max retention — governance flag, no direct cost delta."""
    return SavingsResult(
        0.0, 0.0, 0.0, 0.0,
        ["SQS retention has no direct per-GB cost; governance signal only"],
        "low",
    )


def _savings_cost024(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-024 RDS Multi-AZ in non-production environment."""
    rds = pricing.get("rds_instances", {})
    m   = re.search(r'instance_class\s*=\s*["\']([^"\']+)["\']', block_content)
    if not m:
        hints = usage.get("_var_hints", {})
        inst  = hints.get("instance_class")
        if not inst:
            return SavingsResult(0.0, 0.0, 0.0, 0.0, [], "low")
    else:
        inst = m.group(1).strip()
    instance_cost = rds.get(inst, 100.0)
    # Multi-AZ doubles instance cost; disabling it saves one replica.
    before = instance_cost * 2
    after  = instance_cost
    saving = instance_cost
    return SavingsResult(
        saving, saving, before, after,
        [f"{inst} multi_az=false saves one replica (${instance_cost:.2f}/mo)"],
        "high",
    )


def _savings_cost025(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-025 ECS task definition without CPU/memory limits."""
    vcpu_hr  = pricing.get("ecs_fargate_per_vcpu_hour", 0.04048)
    gb_hr    = pricing.get("ecs_fargate_per_gb_hour", 0.004445)
    over_pct = usage.get("ecs_overprovisioning_pct", 0.25)
    # Minimum viable Fargate task: 0.25 vCPU, 0.5 GB.
    min_task_cost = (vcpu_hr * 0.25 + gb_hr * 0.5) * 730
    before = min_task_cost * (1 + over_pct)
    after  = min_task_cost
    saving = min_task_cost * over_pct
    return SavingsResult(
        saving, saving, before, after,
        [
            f"min Fargate task 0.25vCPU/0.5GB (${min_task_cost:.2f}/mo)",
            f"assumed {int(over_pct*100)}% over-provisioning waste",
        ],
        "low",
    )


def _savings_cost026(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-026 Multiple NAT Gateways — saving = cost of one extra gateway."""
    hourly = pricing.get("nat_gateway_hourly", 0.045)
    before = hourly * 730  # cost of one redundant NAT GW (data excl.)
    return SavingsResult(
        before, before, before, 0.0,
        ["$0.045/hr × 730h/mo per extra NAT GW (data charges excluded)"],
        "high",
    )


def _savings_cost027(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
    """COST-027 Missing VPC Endpoints for S3/DynamoDB — uncertain: actual S3/Dynamo share unknown."""
    per_gb          = pricing.get("nat_gateway_per_gb", 0.045)
    gb_day          = usage.get("nat_gb_per_day", 10.0)
    s3_dynamo_pct   = usage.get("s3_dynamo_pct_of_nat", 0.20)
    s3_dynamo_gb_day = gb_day * s3_dynamo_pct
    before = per_gb * s3_dynamo_gb_day * 30
    return SavingsResult(
        0.0, before,   # low=0: actual S3/DynamoDB share of NAT traffic is unknown
        before, 0.0,
        [
            f"S3/DynamoDB={int(s3_dynamo_pct*100)}% of {gb_day}GB/d NAT traffic",
            f"= {s3_dynamo_gb_day:.1f}GB/d × $0.045/GB × 30d",
            "low=$0: actual traffic split to S3/DynamoDB is unobservable from config",
        ],
        "low",
    )


def _savings_zero(label: str) -> Callable:
    """Factory for governance rules with no direct cost delta."""
    def _fn(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
        return SavingsResult(0.0, 0.0, 0.0, 0.0, [label], "low")
    return _fn


def _savings_cost012_factory(total_ec2_cost: float, inferred: bool = False) -> Callable:
    """COST-012 Spot instances — fleet-level saving (counted once, not per instance)."""
    def _fn(block_content: str, pricing: dict, usage: dict) -> SavingsResult:
        low  = total_ec2_cost * 0.50
        high = total_ec2_cost * 0.90
        assumptions = [
            f"total EC2 on-demand ${total_ec2_cost:.2f}/mo",
            "Spot instances save 50–90%",
        ]
        if inferred:
            assumptions.append("instance_type unresolvable (variable) — using inferred price")
        return SavingsResult(
            low, high,
            total_ec2_cost, total_ec2_cost * 0.10,
            assumptions,
            "low" if inferred else "medium",
        )
    return _fn


# Rules that represent a fleet-level optimisation rather than a per-resource one.
# estimate_savings will only count the first finding for each of these.
_FLEET_LEVEL_RULES = {"COST-012"}


# Base SAVINGS_MODELS registry (COST-012 is built dynamically in estimate_savings).
SAVINGS_MODELS: Dict[str, Callable] = {
    "COST-001": _savings_cost001,
    "COST-003": _savings_zero("security risk — encrypting EBS has no cost delta"),
    "COST-004": _savings_cost004,
    "COST-005": _savings_cost005,
    "COST-006": _savings_cost006,
    "COST-007": _savings_cost007,
    "COST-008": _savings_cost008,
    "COST-009": _savings_cost009,
    "COST-010": _savings_cost010,
    "COST-011": _savings_zero("AWS Budget is a governance control; no direct cost delta"),
    "COST-014": _savings_cost014,
    "COST-015": _savings_cost015,
    "COST-017": _savings_zero("CUR is a governance control; no direct cost delta"),
    "COST-020": _savings_cost020,
    "COST-021": _savings_cost021,
    "COST-022": _savings_cost022,
    "COST-023": _savings_cost023,
    "COST-024": _savings_cost024,
    "COST-025": _savings_cost025,
    "COST-026": _savings_cost026,
    "COST-027": _savings_cost027,
    # COST-002 (expensive instance type), COST-016 (large root volume),
    # COST-019 (load balancer for single instance) are intentionally omitted:
    # their savings estimates are too speculative to surface in totals or per-finding.
}


# ── Phase 1 — estimate_savings ────────────────────────────────────────────────

def _build_var_hints(blocks: Dict[str, List[dict]], pricing: dict) -> dict:
    """
    Scan non-resource blocks for literal instance_type / instance_class values and
    variable ``default`` values that look like EC2/RDS types.

    Returns a hints dict with optional keys:
      ``instance_type``       — EC2 type whose price is closest to the inferred average
      ``_ec2_fallback_cost``  — average EC2 price across all found types
      ``instance_class``      — RDS type closest to the inferred average
      ``_rds_fallback_cost``  — average RDS price across all found types
    """
    ec2_prices = pricing.get("ec2_instances", {})
    rds_prices = pricing.get("rds_instances", {})

    # Scan all non-resource blocks so we don't re-count literals already handled
    # individually in each resource block.
    _resource_types = set(_RESOURCE_COST_FNS.keys())
    support = " ".join(
        b.get("content", "")
        for btype, blist in blocks.items()
        if btype not in _resource_types
        for b in blist
    )

    # Pattern 1 — explicit attribute: instance_type = "t3.medium"
    ec2_types: List[str] = re.findall(r'instance_type\s*=\s*["\']([\w.]+)["\']', support)
    # Pattern 2 — variable default: default = "t3.medium" (value is a known EC2 type)
    ec2_types += [
        t for t in re.findall(r'\bdefault\s*=\s*["\']([\w.]+)["\']', support)
        if t in ec2_prices
    ]

    rds_types: List[str] = re.findall(r'instance_class\s*=\s*["\']([\w.]+)["\']', support)
    rds_types += [
        t for t in re.findall(r'\bdefault\s*=\s*["\']([\w.]+)["\']', support)
        if t in rds_prices
    ]

    hints: dict = {}
    if ec2_types:
        avg = sum(ec2_prices.get(t, 50.0) for t in ec2_types) / len(ec2_types)
        # Store both the representative type (for display) and the average cost (for math)
        hints["instance_type"] = min(ec2_types, key=lambda t: abs(ec2_prices.get(t, 50.0) - avg))
        hints["_ec2_fallback_cost"] = avg
    if rds_types:
        avg = sum(rds_prices.get(t, 100.0) for t in rds_types) / len(rds_types)
        hints["instance_class"] = min(rds_types, key=lambda t: abs(rds_prices.get(t, 100.0) - avg))
        hints["_rds_fallback_cost"] = avg
    return hints


def estimate_savings(
    findings: List[dict],
    blocks: Dict[str, List[dict]],
    pricing: dict,
    usage: dict,
) -> dict:
    """
    Compute per-finding and aggregate savings for all cost findings.

    Returns a dict matching ScanReport.metrics["savings_estimate"].
    """
    # Build variable hints once and reuse for COST-012 fleet cost and per-finding savings.
    var_hints = _build_var_hints(blocks, pricing)
    ec2_fallback = var_hints.get("_ec2_fallback_cost", 50.0)

    # For COST-012, pre-compute total EC2 on-demand cost from all discovered blocks.
    ec2_prices = pricing.get("ec2_instances", {})
    total_ec2_cost = 0.0
    cost012_inferred = False
    for b in blocks.get("aws_instance", []):
        m = re.search(r'instance_type\s*=\s*["\']([^"\']+)["\']', b.get("content", ""))
        if m:
            total_ec2_cost += ec2_prices.get(m.group(1).strip(), 50.0)
        else:
            # instance_type is a variable/local reference — use inferred average or floor
            total_ec2_cost += ec2_fallback
            cost012_inferred = True

    models = dict(SAVINGS_MODELS)
    models["COST-012"] = _savings_cost012_factory(total_ec2_cost, inferred=cost012_inferred)

    usage_with_hints = {**usage, "_var_hints": var_hints} if var_hints else usage

    per_finding: List[dict] = []
    seen_fleet_rules: set = set()  # deduplicate fleet-level rules (e.g. COST-012)

    for finding in findings:
        rule_id    = finding.get("rule_id")
        savings_fn = models.get(rule_id)
        if savings_fn is None:
            continue

        # Fleet-level rules produce one saving for the whole fleet — only count once.
        if rule_id in _FLEET_LEVEL_RULES:
            if rule_id in seen_fleet_rules:
                continue
            seen_fleet_rules.add(rule_id)

        fpath = finding.get("file", "")
        line  = finding.get("line", 0)
        block = _find_block(blocks, fpath, line)
        block_content = block["content"] if block else ""
        # Track which block this finding belongs to for per-block cap (see below).
        block_key = (block["file"], block["start_line"]) if block else None

        # Pass the block's filepath so savings functions can resolve variable references
        # (e.g. volume_size = var.grq["root_dev_size"]) via sibling .tf files.
        usage_for_finding = {
            **usage_with_hints,
            "_filepath": block["file"] if block else fpath,
        }

        try:
            result: SavingsResult = savings_fn(block_content, pricing, usage_for_finding)
        except Exception as exc:
            logger.warning("savings_fn for %s failed: %s", rule_id, exc)
            continue

        per_finding.append(
            {
                "rule_id":    rule_id,
                "file":       fpath,
                "line":       line,
                "before_usd": round(result.before_usd, 2),
                "after_usd":  round(result.after_usd, 2),
                "saving_low":  round(result.saving_low_usd, 2),
                "saving_high": round(result.saving_high_usd, 2),
                "assumptions": result.assumptions,
                "confidence":  result.confidence,
                # Exposed so the JS can join per_finding → resource_costs exactly.
                "block_file":  block["file"]       if block else fpath,
                "block_line":  block["start_line"] if block else line,
            }
        )

    # Distribute fleet-level COST-012 saving across individual instance blocks.
    # The main loop created ONE per_finding entry (fleet total). Replace it with
    # N per-instance entries so every row in the resource cost table shows its
    # proportional Spot saving.  Aggregate sum stays identical: N x (fleet/N) = fleet.
    # Only findings that resolve to an actual resource block are distributed;
    # data source findings (e.g. data "aws_instance") are silently dropped so the
    # headline total stays consistent with the per-row table.
    cost012_idx = next(
        (i for i, pf in enumerate(per_finding) if pf["rule_id"] == "COST-012"), None
    )
    if cost012_idx is not None:
        fleet_pf = per_finding[cost012_idx]
        cost012_all = [f for f in findings if f.get("rule_id") == "COST-012"]
        # Resolve each finding to its resource block; drop those without a match.
        cost012_resolved = [
            (f, b)
            for f in cost012_all
            for b in [_find_block(blocks, f.get("file", ""), f.get("line", 0))]
            if b is not None
        ]
        # If fewer findings resolved than there are aws_instance blocks, fall back
        # to distributing across ALL instance blocks.  This handles the common case
        # where COST-012 fires once per file (the first aws_instance) but the fleet
        # actually contains several instances — without this the entire fleet saving
        # is pinned to one cheap block and the JS cap silently swallows it.
        all_instance_blocks = blocks.get("aws_instance", [])
        if len(cost012_resolved) < len(all_instance_blocks) and all_instance_blocks:
            cost012_resolved = [
                (cost012_all[0] if cost012_all else {}, b)
                for b in all_instance_blocks
            ]

        n = len(cost012_resolved)
        if n == 0:
            # No resolvable blocks — remove the entry entirely
            per_finding.pop(cost012_idx)
        else:
            # Proportional distribution: each instance saves spot_pct × its own
            # EC2 compute cost.  Using EC2-only cost (same basis as fleet_before)
            # prevents EBS storage from inflating the per-instance saving.
            fleet_before  = fleet_pf["before_usd"] or 1.0
            spot_pct_low  = fleet_pf["saving_low"]  / fleet_before
            spot_pct_high = fleet_pf["saving_high"] / fleet_before
            ec2_prices_local = pricing.get("ec2_instances", {})

            distributed = []
            for f, b in cost012_resolved:
                m2 = re.search(r'instance_type\s*=\s*["\'](\S+)["\']', b.get("content", ""))
                inst_cost = ec2_prices_local.get(m2.group(1).strip(), ec2_fallback) if m2 else ec2_fallback
                # For blocks that were synthesised (no direct finding), fall back
                # to the block's own coordinates so the UI can still render them.
                f_file = f.get("file", b["file"]) if isinstance(f, dict) and f else b["file"]
                f_line = f.get("line", b["start_line"]) if isinstance(f, dict) and f else b["start_line"]
                distributed.append({
                    "rule_id":    "COST-012",
                    "file":       f_file,
                    "line":       f_line,
                    "before_usd": round(inst_cost, 2),
                    "after_usd":  round(inst_cost * (1 - spot_pct_high), 2),
                    "saving_low":  round(inst_cost * spot_pct_low,  2),
                    "saving_high": round(inst_cost * spot_pct_high, 2),
                    "assumptions": fleet_pf["assumptions"],
                    "confidence":  fleet_pf["confidence"],
                    "block_file":  b["file"],
                    "block_line":  b["start_line"],
                })
            per_finding[cost012_idx : cost012_idx + 1] = distributed

    # Per-block savings cap
    # Multiple rules can fire on the same resource block (e.g. COST-001 and
    # COST-004 both target the same aws_instance). Their combined savings must
    # not exceed the block’s actual resource cost.
    # Fleet-level rules are excluded from this cap: their before_usd spans the
    # whole fleet, not one block, so scaling them to a single block’s cost
    # would drastically under-count the saving.
    #
    # 1. Build block_key → (resource_type, block) from all parsed blocks.
    _block_registry: Dict[tuple, tuple] = {}
    for rtype, blist in blocks.items():
        for b in blist:
            key = (b["file"], b["start_line"])
            _block_registry[key] = (rtype, b)

    # 2. Group per_finding indices by block_key, excluding fleet rules.
    groups: Dict[tuple, List[int]] = defaultdict(list)
    for i, pf in enumerate(per_finding):
        if pf["rule_id"] not in _FLEET_LEVEL_RULES:
            groups[(pf["block_file"], pf["block_line"])].append(i)

    # 3. For each block that has more than one non-fleet finding, cap and scale.
    for block_key, indices in groups.items():
        if len(indices) <= 1:
            continue  # single finding on this block — no overlap possible

        rtype_block = _block_registry.get(block_key)
        if not rtype_block:
            continue
        rtype, block = rtype_block

        cost_fn = _RESOURCE_COST_FNS.get(rtype)
        if not cost_fn:
            continue

        try:
            rc = cost_fn(block, pricing, usage)
            resource_cap = rc.total_usd_month
        except Exception:
            continue

        if resource_cap <= 0:
            continue

        sum_high = sum(per_finding[i]["saving_high"] for i in indices)
        if sum_high <= resource_cap:
            continue  # already within budget

        # Scale every non-fleet finding on this block proportionally.
        ratio = resource_cap / sum_high
        for i in indices:
            per_finding[i]["saving_low"]  = round(per_finding[i]["saving_low"]  * ratio, 2)
            per_finding[i]["saving_high"] = round(per_finding[i]["saving_high"] * ratio, 2)

    # Recompute totals from the (possibly scaled) values.
    low_total  = sum(pf["saving_low"]  for pf in per_finding)
    high_total = sum(pf["saving_high"] for pf in per_finding)
    detectable_cost = sum(f["before_usd"] for f in per_finding)

    # Coverage statistics — how many blocks are priced vs total found.
    priced_types    = set(_RESOURCE_COST_FNS.keys())
    known_free      = _ZERO_COST_TYPES
    covered_found   = set(blocks.keys()) & (priced_types | known_free)
    uncovered_found = set(blocks.keys()) - priced_types - known_free
    total_block_count   = sum(len(v) for v in blocks.values())
    covered_block_count = sum(len(blocks[t]) for t in covered_found)

    return {
        "low_usd_month":  round(low_total, 2),
        "high_usd_month": round(high_total, 2),
        "detectable_resource_cost_usd_month": round(detectable_cost, 2),
        "total_infra_cost_usd_month": None,       # populated by Phase 2
        "savings_pct_of_detectable_low":
            round(low_total  / detectable_cost * 100, 1) if detectable_cost else None,
        "savings_pct_of_detectable_high":
            round(high_total / detectable_cost * 100, 1) if detectable_cost else None,
        "savings_pct_of_total_low":  None,         # populated by Phase 2
        "savings_pct_of_total_high": None,
        "per_finding": per_finding,
        "confidence":  "medium",
        "cost_provider": "internal",
        "covered_resource_types": sorted(covered_found),
        "uncovered_resource_types": sorted(uncovered_found),
        "total_block_count":   total_block_count,
        "covered_block_count": covered_block_count,
        "total_cost_note": (
            "total_infra_cost_usd_month covers only the resource types listed in "
            "covered_resource_types. Free or config-opaque resources (VPC, IAM, "
            "Security Groups, ACM, Route Tables, etc.) are excluded."
        ),
    }


# ── Phase 2 — per-resource cost calculation ───────────────────────────────────

def _rc(
    block: dict,
    fixed: float,
    usage_cost: float,
    assumptions: List[str],
    confidence: str,
) -> ResourceCost:
    """Helper: construct a ResourceCost from a block dict and computed costs."""
    total = round(fixed + usage_cost, 2)
    return ResourceCost(
        resource_type=block["resource_type"],
        resource_name=block["name"],
        file=block["file"],
        line=block["start_line"],
        fixed_usd_month=round(fixed, 2),
        usage_usd_month=round(usage_cost, 2),
        min_usd_month=round(fixed, 2),
        total_usd_month=total,
        assumptions=assumptions,
        confidence=confidence,
    )


def _cost_aws_instance(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    ec2 = pricing.get("ec2_instances", {})
    m   = re.search(r'instance_type\s*=\s*["\']([^"\']+)["\']', block["content"])
    if m:
        inst = m.group(1).strip()
        inst_cost = ec2.get(inst, 50.0)
        conf = "high"
    else:
        # instance_type is a variable/local reference — use the inferred average cost
        hints = usage.get("_var_hints", {})
        inst  = hints.get("instance_type", "~inferred")
        inst_cost = hints.get("_ec2_fallback_cost", 50.0)
        conf  = "low" if hints.get("_ec2_fallback_cost") else "medium"

    # Root block device EBS
    size_m = re.search(
        r'root_block_device\s*\{[^}]*volume_size\s*=\s*(\d+)', block["content"], re.DOTALL
    )
    vol_m = re.search(
        r'root_block_device\s*\{[^}]*volume_type\s*=\s*["\']([^"\']+)["\']',
        block["content"], re.DOTALL,
    )
    size     = int(size_m.group(1)) if size_m else 8
    vol_type = vol_m.group(1) if vol_m else "gp3"
    ebs_cost = size * pricing.get("ebs_per_gb_month", {}).get(vol_type, 0.08)

    return _rc(
        block, inst_cost + ebs_cost, 0.0,
        [f"{inst} on-demand us-east-1", f"{vol_type} {size}GB root volume"],
        conf,
    )


def _cost_aws_db_instance(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    rds  = pricing.get("rds_instances", {})
    m    = re.search(r'instance_class\s*=\s*["\']([^"\']+)["\']', block["content"])
    if m:
        inst = m.group(1).strip()
        cost = rds.get(inst, 100.0)
        conf = "high"
    else:
        hints = usage.get("_var_hints", {})
        inst  = hints.get("instance_class", "~inferred")
        cost  = hints.get("_rds_fallback_cost", 100.0)
        conf  = "low" if hints.get("_rds_fallback_cost") else "medium"
    multi_az = bool(re.search(r'multi_az\s*=\s*true', block["content"]))
    if multi_az:
        cost *= 2
    return _rc(
        block, cost, 0.0,
        [f"{inst} on-demand us-east-1" + (" multi-AZ" if multi_az else "")],
        conf,
    )


def _cost_aws_ebs_volume(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    ebs          = pricing.get("ebs_per_gb_month", {})
    iops_pricing = pricing.get("ebs_iops_per_iops_month", {})
    content  = block["content"]
    size_m   = re.search(r'(?:size|volume_size)\s*=\s*(\d+)', content)
    vol_m    = re.search(r'(?:type|volume_type)\s*=\s*["\']([^"\']+)["\']', content)
    size: Optional[int] = int(size_m.group(1)) if size_m else None
    vol_type = vol_m.group(1) if vol_m else "gp3"

    if size is None:
        # Try to resolve variable reference such as var.foo["volume_size"]
        size_var_m = re.search(r'(?:size|volume_size)\s*=\s*((?:var|local)\.\S+)', content)
        if size_var_m:
            resolved = _resolve_number_from_files(size_var_m.group(1), block.get("file", ""))
            if resolved is not None:
                size = resolved

    if size is None:
        size = 20

    cost      = size * ebs.get(vol_type, 0.08)
    iops_cost = 0.0
    iops      = 0
    if vol_type in ("io1", "io2"):
        iops_m    = re.search(r'\biops\s*=\s*(\d+)', content)
        iops      = int(iops_m.group(1)) if iops_m else 3000
        iops_cost = iops * iops_pricing.get(vol_type, iops_pricing.get("io1", 0.065))
    conf = "high" if (size_m and vol_m) else ("medium" if (size_m or vol_m) else "low")
    assumptions = [f"{vol_type} {size}GB"]
    if iops:
        assumptions.append(f"{iops} IOPS")
    return _rc(block, round(cost + iops_cost, 2), 0.0, assumptions, conf)


def _cost_aws_nat_gateway(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    hourly  = pricing.get("nat_gateway_hourly", 0.045)
    per_gb  = pricing.get("nat_gateway_per_gb", 0.045)
    gb_day  = usage.get("nat_gb_per_day", 10.0)
    fixed   = hourly * 730
    usage_c = per_gb * gb_day * 30
    return _rc(
        block, fixed, usage_c,
        [f"$0.045/hr fixed + $0.045/GB × {gb_day}GB/d × 30d data"],
        "medium",
    )


def _cost_aws_eip(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    hourly = pricing.get("eip_unattached_per_hour", 0.005)
    cost   = hourly * 730
    return _rc(block, cost, 0.0, ["$0.005/hr × 730h/mo (unattached)"], "high")


def _cost_aws_lb(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    hourly  = pricing.get("alb_per_hour", 0.0225)
    per_lcu = pricing.get("alb_per_lcu_hour", 0.008)
    data_gb = usage.get("lb_data_processed_gb", 10.0)
    fixed   = hourly * 730
    # Processed bytes dimension: 1 LCU = 1 GB/hr; estimate from monthly total
    lcu_hr  = data_gb / 730
    usage_c = round(per_lcu * lcu_hr * 730, 2)
    return _rc(
        block, round(fixed, 2), usage_c,
        [
            f"${hourly}/hr × 730h/mo base",
            f"~{lcu_hr:.3f} LCU/hr from {data_gb}GB/mo processed (LCU approx)",
        ],
        "low",
    )


def _cost_aws_lambda_function(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    per_gb_sec  = pricing.get("lambda_per_gb_second", 0.0000166667)
    per_1m_req  = pricing.get("lambda_per_1m_requests", 0.20)
    invocations = usage.get("lambda_invocations_per_mo", 1_000_000)
    duration_ms = usage.get("lambda_avg_duration_ms", 200.0)
    mem_m       = re.search(r'memory_size\s*=\s*(\d+)', block["content"])
    mem_mb      = float(mem_m.group(1)) if mem_m else 128.0
    gb_seconds  = (mem_mb / 1024) * (duration_ms / 1000) * invocations
    compute_cost = per_gb_sec * gb_seconds
    req_cost     = per_1m_req * (invocations / 1_000_000)
    conf = "medium"
    return _rc(
        block, 0.0, round(compute_cost + req_cost, 4),
        [f"{int(mem_mb)}MB, {invocations/1e6:.0f}M invocations/mo, {duration_ms}ms avg"],
        conf,
    )


def _cost_aws_cloudwatch_log_group(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    per_gb_ingested = pricing.get("cloudwatch_logs_per_gb_ingested", 0.50)
    per_gb_stored   = pricing.get("cloudwatch_logs_per_gb_stored", 0.03)
    gb_mo           = usage.get("cw_log_gb_per_month", 5.0)
    ret_m           = re.search(r'retention_in_days\s*=\s*(\d+)', block["content"])
    ret_days        = int(ret_m.group(1)) if ret_m else 0  # 0 = forever
    stored_gb       = gb_mo * (ret_days / 30.0) if ret_days else gb_mo * 12
    ingestion_cost  = per_gb_ingested * gb_mo
    storage_cost    = per_gb_stored * stored_gb
    return _rc(
        block, 0.0, round(ingestion_cost + storage_cost, 4),
        [
            f"{gb_mo}GB/mo ingested",
            f"retention={'forever' if not ret_days else f'{ret_days}d'}",
        ],
        "medium",
    )


def _cost_aws_s3_bucket(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    per_gb    = pricing.get("s3_per_gb_standard", 0.023)
    gb        = usage.get("s3_gb_standard", 50.0)
    usage_c   = per_gb * gb
    return _rc(
        block, 0.0, round(usage_c, 4),
        [f"{gb}GB Standard storage (lifecycle/request charges excluded)"],
        "low",
    )


def _cost_aws_dynamodb_table(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    per_rcu_hr = pricing.get("dynamodb_per_rcu_hour", 0.00013)
    per_wcu_hr = pricing.get("dynamodb_per_wcu_hour", 0.00065)
    billing_m  = re.search(r'billing_mode\s*=\s*["\']([^"\']+)["\']', block["content"])
    mode       = billing_m.group(1).upper() if billing_m else "PROVISIONED"
    if mode == "PAY_PER_REQUEST":
        return _rc(
            block, 0.0, 0.0,
            ["on-demand mode (usage-dependent, no static estimate)"],
            "low",
        )
    rcu_m = re.search(r'read_capacity\s*=\s*(\d+)', block["content"])
    wcu_m = re.search(r'write_capacity\s*=\s*(\d+)', block["content"])
    rcu   = int(rcu_m.group(1)) if rcu_m else 5
    wcu   = int(wcu_m.group(1)) if wcu_m else 5
    cost  = (rcu * per_rcu_hr + wcu * per_wcu_hr) * 730
    return _rc(
        block, cost, 0.0,
        [f"PROVISIONED RCU={rcu} WCU={wcu}"],
        "high" if (rcu_m and wcu_m) else "medium",
    )


def _cost_aws_ecs_task_definition(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    vcpu_hr  = pricing.get("ecs_fargate_per_vcpu_hour", 0.04048)
    gb_hr    = pricing.get("ecs_fargate_per_gb_hour", 0.004445)
    cpu_m    = re.search(r'^\s*cpu\s*=\s*["\']?(\d+)', block["content"], re.MULTILINE)
    mem_m    = re.search(r'^\s*memory\s*=\s*["\']?(\d+)', block["content"], re.MULTILINE)
    cpu_units = int(cpu_m.group(1)) if cpu_m else 256
    mem_mb    = int(mem_m.group(1)) if mem_m else 512
    vcpu      = cpu_units / 1024
    mem_gb    = mem_mb / 1024
    cost      = (vcpu_hr * vcpu + gb_hr * mem_gb) * 730
    conf      = "high" if (cpu_m and mem_m) else "low"
    return _rc(
        block, cost, 0.0,
        [f"{vcpu}vCPU {mem_gb:.2f}GB Fargate"],
        conf,
    )


def _cost_aws_api_gateway_rest_api(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    per_1m   = pricing.get("api_gw_rest_per_1m_calls", 3.50)
    calls_mo = usage.get("api_calls_per_mo", 1_000_000)
    return _rc(
        block, 0.0, round(per_1m * calls_mo / 1_000_000, 4),
        [f"{calls_mo/1e6:.0f}M calls/mo REST API"],
        "low",
    )


def _cost_aws_apigatewayv2_api(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    per_1m   = pricing.get("api_gw_http_per_1m_calls", 1.00)
    calls_mo = usage.get("api_calls_per_mo", 1_000_000)
    return _rc(
        block, 0.0, round(per_1m * calls_mo / 1_000_000, 4),
        [f"{calls_mo/1e6:.0f}M calls/mo HTTP API"],
        "low",
    )


def _cost_aws_kinesis_stream(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    shard_hr = pricing.get("kinesis_shard_per_hour", 0.015)
    shard_m  = re.search(r'shard_count\s*=\s*(\d+)', block["content"])
    shards   = int(shard_m.group(1)) if shard_m else 1
    cost     = shard_hr * shards * 730
    return _rc(
        block, cost, 0.0,
        [f"{shards} shard(s) × $0.015/hr × 730h/mo"],
        "high" if shard_m else "medium",
    )


def _cost_aws_route53_health_check(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    cost = pricing.get("route53_health_check_per_month", 0.50)
    return _rc(block, cost, 0.0, ["$0.50/health-check/month"], "high")


def _cost_aws_rds_cluster_instance(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    """Aurora cluster instance — shares the rds_instances price table."""
    rds = pricing.get("rds_instances", {})
    m   = re.search(r'instance_class\s*=\s*["\']([^"\']+)["\']', block["content"])
    inst = m.group(1).strip() if m else "db.t3.medium"
    cost = rds.get(inst, 0.0)
    conf = "high" if m else "medium"
    return _rc(block, cost, 0.0, [f"{inst} Aurora instance us-east-1"], conf)


def _cost_aws_elasticache_replication_group(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    elasticache = pricing.get("elasticache_instances", {})
    m          = re.search(r'node_type\s*=\s*["\']([^"\']+)["\']', block["content"])
    node_type  = m.group(1).strip() if m else "cache.t3.micro"
    per_node   = elasticache.get(node_type, 30.0)
    rep_m      = re.search(r'(?:num_cache_clusters|replicas_per_node_group)\s*=\s*(\d+)', block["content"])
    nodes      = int(rep_m.group(1)) if rep_m else 1
    conf       = "high" if (m and rep_m) else "medium" if m else "low"
    return _rc(block, per_node * nodes, 0.0, [f"{node_type} × {nodes} nodes (ElastiCache)"], conf)


def _cost_aws_elasticache_cluster(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    elasticache = pricing.get("elasticache_instances", {})
    m          = re.search(r'node_type\s*=\s*["\']([^"\']+)["\']', block["content"])
    node_type  = m.group(1).strip() if m else "cache.t3.micro"
    per_node   = elasticache.get(node_type, 30.0)
    num_m      = re.search(r'num_cache_nodes\s*=\s*(\d+)', block["content"])
    nodes      = int(num_m.group(1)) if num_m else 1
    conf       = "high" if (m and num_m) else "medium" if m else "low"
    return _rc(block, per_node * nodes, 0.0, [f"{node_type} × {nodes} nodes (ElastiCache)"], conf)


def _cost_aws_cloudwatch_metric_alarm(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    cost = pricing.get("cloudwatch_alarm_per_month", 0.10)
    return _rc(block, cost, 0.0, ["$0.10/alarm/month (standard metrics)"], "high")


def _cost_aws_eks_cluster(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    hourly = pricing.get("eks_cluster_per_hour", 0.10)
    cost   = hourly * 730
    return _rc(block, cost, 0.0, ["$0.10/hr × 730h/mo (control plane only; node costs separate)"], "high")


def _cost_aws_secretsmanager_secret(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    base_mo  = pricing.get("secretsmanager_secret_per_month", 0.40)
    per_10k  = pricing.get("secretsmanager_per_10k_api_calls", 0.05)
    requests = usage.get("secretsmanager_requests_per_mo", 10000)
    req_cost = per_10k * (requests / 10000)
    return _rc(
        block, base_mo, round(req_cost, 4),
        [
            "$0.40/secret/month",
            f"$0.05/10k API calls × {requests/1000:.0f}K calls/mo",
        ],
        "medium",
    )


def _cost_aws_vpc_endpoint(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    ep_type_m = re.search(r'vpc_endpoint_type\s*=\s*["\']([^"\']+)["\']', block["content"])
    ep_type   = ep_type_m.group(1).upper() if ep_type_m else "Interface"
    if ep_type == "Gateway":
        return _rc(block, 0.0, 0.0, ["Gateway endpoint — free (S3/DynamoDB)"], "high")
    hourly  = pricing.get("vpc_endpoint_per_hour", 0.01)
    per_gb  = pricing.get("vpc_endpoint_per_gb", 0.01)
    data_gb = usage.get("vpc_endpoint_data_gb_per_mo", 20.0)
    fixed   = hourly * 730
    usage_c = per_gb * data_gb
    return _rc(
        block, round(fixed, 2), round(usage_c, 4),
        [f"Interface $0.01/hr × 730h + $0.01/GB × {data_gb}GB/mo data processed"],
        "medium",
    )


def _cost_aws_wafv2_web_acl(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    cost = pricing.get("wafv2_web_acl_per_month", 5.0)
    return _rc(block, cost, 0.0, ["$5.00/ACL/month REGIONAL (rule/request charges excluded)"], "medium")


def _cost_aws_msk_cluster(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    msk_prices   = pricing.get("msk_brokers", {})
    broker_m     = re.search(r'instance_type\s*=\s*["\']([^"\']+)["\']', block["content"])
    broker_type  = broker_m.group(1).strip() if broker_m else "kafka.m5.large"
    per_hr       = msk_prices.get(broker_type, pricing.get("msk_m5_large_per_hour", 0.212))
    count_m      = re.search(r'number_of_broker_nodes\s*=\s*(\d+)', block["content"])
    brokers      = int(count_m.group(1)) if count_m else 3
    cost         = per_hr * brokers * 730
    conf         = "high" if (broker_m and count_m) else "medium"
    return _rc(block, cost, 0.0, [f"{broker_type} × {brokers} brokers (MSK)"], conf)


def _cost_aws_opensearch_domain(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    os_prices = pricing.get("opensearch_instances", {})
    m         = re.search(r'instance_type\s*=\s*["\']([^"\']+)["\']', block["content"])
    inst_type = m.group(1).strip() if m else "t3.small.search"
    per_hr    = os_prices.get(inst_type, 0.036)
    count_m   = re.search(r'instance_count\s*=\s*(\d+)', block["content"])
    count     = int(count_m.group(1)) if count_m else 1
    cost      = per_hr * count * 730
    conf      = "high" if m else "medium"
    return _rc(block, cost, 0.0, [f"{inst_type} × {count} nodes (OpenSearch)"], conf)


def _cost_aws_redshift_cluster(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    rs_prices = pricing.get("redshift_nodes", {})
    m         = re.search(r'node_type\s*=\s*["\']([^"\']+)["\']', block["content"])
    node_type = m.group(1).strip() if m else "dc2.large"
    per_hr    = rs_prices.get(node_type, 0.25)
    count_m   = re.search(r'number_of_nodes\s*=\s*(\d+)', block["content"])
    nodes     = int(count_m.group(1)) if count_m else 1
    cost      = per_hr * nodes * 730
    conf      = "high" if m else "medium"
    return _rc(block, cost, 0.0, [f"{node_type} × {nodes} nodes (Redshift)"], conf)


def _cost_aws_sfn_state_machine(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    transitions = usage.get("sfn_transitions_per_mo", 100_000)
    per_1k      = pricing.get("sfn_per_1k_state_transitions", 0.025)
    cost        = transitions / 1000 * per_1k
    return _rc(block, 0.0, round(cost, 4), [f"{transitions/1000:.0f}K transitions/mo (Standard Workflow)"], "low")


def _cost_aws_route53_zone(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    cost = pricing.get("route53_hosted_zone_per_month", 0.50)
    return _rc(block, cost, 0.0, ["$0.50/hosted zone/month (first 25 zones)"], "high")


# ── New cost functions ────────────────────────────────────────────────────────

def _cost_aws_kms_key(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    cost = pricing.get("kms_key_per_month", 1.0)
    return _rc(block, cost, 0.0, ["$1.00/key/month + API call charges"], "high")


def _cost_aws_efs_file_system(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    per_gb = pricing.get("efs_per_gb_month", 0.30)
    gb     = usage.get("efs_gb_stored", 100.0)
    return _rc(block, round(per_gb * gb, 2), 0.0,
               [f"Standard storage ${per_gb}/GB-mo × {gb}GB assumed"], "low")


def _cost_aws_ec2_transit_gateway(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    per_hr      = pricing.get("tgw_attachment_per_hour", 0.05)
    attachments = usage.get("tgw_attachments", 1)
    cost        = per_hr * 730 * attachments
    return _rc(block, round(cost, 2), 0.0,
               [f"${per_hr}/attachment/hr × {attachments} attachment(s) × 730h/mo"], "low")


def _cost_aws_ec2_transit_gateway_vpc_attachment(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    per_hr  = pricing.get("tgw_attachment_per_hour", 0.05)
    per_gb  = pricing.get("tgw_data_per_gb", 0.02)
    data_gb = usage.get("tgw_data_processed_gb_per_mo", 50.0)
    fixed   = per_hr * 730
    usage_c = per_gb * data_gb
    return _rc(
        block, round(fixed, 2), round(usage_c, 2),
        [f"$0.05/hr × 730h/mo + $0.02/GB × {data_gb}GB/mo data processed"],
        "medium",
    )


def _cost_aws_cloudwatch_dashboard(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    cost = pricing.get("cloudwatch_dashboard_per_month", 3.0)
    return _rc(block, cost, 0.0, ["$3.00/dashboard/month (first 3 dashboards free)"], "high")


def _cost_aws_ecr_repository(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    per_gb = pricing.get("ecr_per_gb_month", 0.10)
    gb     = usage.get("ecr_gb_stored", 10.0)
    return _rc(block, round(per_gb * gb, 2), 0.0,
               [f"$0.10/GB-mo × {gb}GB image storage assumed"], "low")


def _cost_aws_cloudfront_distribution(block: dict, pricing: dict, usage: dict) -> ResourceCost:
    per_10k_https = pricing.get("cloudfront_per_10k_https_requests", 0.0075)
    per_gb_out    = pricing.get("cloudfront_per_gb_transfer_out", 0.085)
    requests_mo   = usage.get("cloudfront_requests_per_mo", 1_000_000)
    gb_out_mo     = usage.get("cloudfront_gb_out_per_mo", 50.0)
    req_cost      = per_10k_https * (requests_mo / 10_000)
    transfer_cost = per_gb_out * gb_out_mo
    return _rc(
        block, 0.0, round(req_cost + transfer_cost, 2),
        [
            f"{requests_mo/1e6:.0f}M HTTPS requests/mo",
            f"{gb_out_mo}GB transfer out/mo",
        ],
        "low",
    )


# Known-free resource types — these carry no fixed monthly charge.
# Listed here so coverage stats don't treat them as "unpriced".
_ZERO_COST_TYPES: frozenset = frozenset({
    # IAM
    "aws_iam_role", "aws_iam_policy", "aws_iam_role_policy",
    "aws_iam_role_policy_attachment", "aws_iam_user", "aws_iam_user_policy",
    "aws_iam_user_policy_attachment", "aws_iam_access_key", "aws_iam_group",
    "aws_iam_group_policy", "aws_iam_group_membership", "aws_iam_group_policy_attachment",
    "aws_iam_instance_profile", "aws_iam_service_linked_role",
    "aws_iam_openid_connect_provider", "aws_iam_saml_provider",
    "aws_iam_account_password_policy",
    # VPC / networking (free — data transfer billed separately)
    "aws_vpc", "aws_subnet", "aws_internet_gateway", "aws_vpn_gateway",
    "aws_customer_gateway", "aws_vpn_connection",
    "aws_route_table", "aws_route_table_association", "aws_route",
    "aws_main_route_table_association", "aws_default_route_table",
    "aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule",
    "aws_vpc_security_group_egress_rule",
    "aws_network_acl", "aws_network_acl_rule",
    "aws_default_network_acl", "aws_default_security_group",
    "aws_network_interface", "aws_network_interface_attachment",
    "aws_flow_log",
    "aws_db_subnet_group", "aws_db_parameter_group",
    "aws_rds_cluster_parameter_group", "aws_rds_cluster", "aws_rds_global_cluster",
    "aws_rds_cluster_endpoint",
    # EKS sub-resources (node compute billed at EC2 rates)
    "aws_eks_addon", "aws_eks_identity_provider_config",
    "aws_eks_node_group", "aws_eks_fargate_profile",
    "aws_eks_access_entry", "aws_eks_access_policy_association",
    # Compute sub-resources
    "aws_autoscaling_group", "aws_autoscaling_attachment",
    "aws_autoscaling_notification", "aws_autoscaling_schedule",
    "aws_autoscaling_policy", "aws_autoscaling_lifecycle_hook",
    "aws_launch_template", "aws_launch_configuration",
    "aws_key_pair", "aws_ami",
    "aws_placement_group", "aws_spot_fleet_request",
    # Load balancer sub-resources (LB itself is priced)
    "aws_lb_listener", "aws_lb_listener_rule", "aws_lb_target_group",
    "aws_lb_target_group_attachment", "aws_alb_listener", "aws_alb_target_group",
    "aws_lb_cookie_stickiness_policy",
    # API Gateway sub-resources (REST API is priced)
    "aws_api_gateway_api_key", "aws_api_gateway_deployment",
    "aws_api_gateway_integration", "aws_api_gateway_integration_response",
    "aws_api_gateway_method", "aws_api_gateway_method_response",
    "aws_api_gateway_method_settings", "aws_api_gateway_model",
    "aws_api_gateway_resource", "aws_api_gateway_stage",
    "aws_api_gateway_usage_plan", "aws_api_gateway_usage_plan_key",
    "aws_api_gateway_account", "aws_api_gateway_base_path_mapping",
    "aws_api_gateway_domain_name", "aws_api_gateway_vpc_link",
    "aws_api_gateway_authorizer", "aws_api_gateway_gateway_response",
    "aws_api_gateway_request_validator",
    # S3 sub-resources (bucket itself is priced)
    "aws_s3_bucket_policy", "aws_s3_bucket_acl",
    "aws_s3_bucket_versioning", "aws_s3_bucket_cors_configuration",
    "aws_s3_bucket_lifecycle_configuration", "aws_s3_bucket_notification",
    "aws_s3_bucket_server_side_encryption_configuration",
    "aws_s3_bucket_replication_configuration",
    "aws_s3_bucket_ownership_controls", "aws_s3_bucket_public_access_block",
    "aws_s3_bucket_object", "aws_s3_object", "aws_s3_bucket_logging",
    "aws_s3_bucket_metric", "aws_s3_bucket_intelligent_tiering_configuration",
    # Lambda sub-resources
    "aws_lambda_permission", "aws_lambda_event_source_mapping",
    "aws_lambda_alias", "aws_lambda_layer_version",
    "aws_lambda_code_signing_config",
    # CloudWatch sub-resources
    "aws_cloudwatch_event_rule", "aws_cloudwatch_event_target",
    "aws_cloudwatch_event_bus", "aws_cloudwatch_event_permission",
    "aws_cloudwatch_log_subscription_filter",
    "aws_cloudwatch_log_metric_filter", "aws_cloudwatch_log_resource_policy",
    "aws_cloudwatch_log_stream", "aws_cloudwatch_composite_alarm",
    # SNS/SQS — usage-based only; fixed cost is zero
    "aws_sns_topic", "aws_sns_topic_subscription", "aws_sns_topic_policy",
    "aws_sqs_queue", "aws_sqs_queue_policy",
    # ElastiCache sub-resources
    "aws_elasticache_subnet_group", "aws_elasticache_parameter_group",
    "aws_elasticache_security_group",
    # ACM
    "aws_acm_certificate", "aws_acm_certificate_validation",
    # Route53 sub-resources (zone itself is priced)
    "aws_route53_record",
    # RAM
    "aws_ram_resource_share", "aws_ram_resource_association",
    "aws_ram_principal_association",
    # SSM
    "aws_ssm_parameter", "aws_ssm_document",
    "aws_ssm_patch_baseline", "aws_ssm_patch_group",
    "aws_ssm_association", "aws_ssm_maintenance_window",
    # ECR sub-resources
    "aws_ecr_lifecycle_policy", "aws_ecr_repository_policy",
    # EFS sub-resources
    "aws_efs_mount_target", "aws_efs_access_point",
    # Misc governance / config (no direct monthly charge)
    "aws_budgets_budget",
    "aws_organizations_account", "aws_organizations_organization",
    "aws_organizations_policy", "aws_organizations_policy_attachment",
    "aws_organizations_organizational_unit",
    "aws_service_quota",
    "aws_cloudformation_stack", "aws_cloudformation_stack_set",
    "aws_servicecatalog_portfolio",
    # Tags / meta
    "aws_default_tags", "aws_provider",
    # EIP sub-resources
    "aws_eip_association",
    # Volume sub-resources
    "aws_volume_attachment",
    # KMS sub-resources (key itself is priced)
    "aws_kms_alias", "aws_kms_key_policy", "aws_kms_grant",
    # Secrets Manager sub-resources
    "aws_secretsmanager_secret_version",
    # Classic ELB sub-resources
    "aws_load_balancer_policy", "aws_load_balancer_listener_policy",
    # Auto Scaling sub-resources (compute is billed via EC2 instances)
    "aws_appautoscaling_target", "aws_appautoscaling_policy",
    # IAM sub-resources
    "aws_iam_user_login_profile", "aws_iam_user_ssh_key",
    # Miscellaneous AWS sub-resources
    "aws_lambda_function_event_invoke_config",
    "aws_db_event_subscription",
    "aws_ec2_tag",
    "aws_cloudfront_origin_access_identity",
    "aws_vpc_endpoint_route_table_association",
    # Non-AWS providers — Terraform creates these but they carry no AWS cost
    "null_resource", "local_file",
    "random_password", "random_string", "random_id", "random_integer",
    "time_sleep", "time_rotating",
    # Kubernetes provider (cost is in EKS cluster / node EC2 instances)
    "kubernetes_cluster_role", "kubernetes_cluster_role_binding",
    "kubernetes_config_map", "kubernetes_config_map_v1",
    "kubernetes_deployment", "kubernetes_namespace",
    "kubernetes_role", "kubernetes_role_binding",
    "kubernetes_secret", "kubernetes_service",
    "kubernetes_service_account", "kubernetes_storage_class_v1",
    # Helm provider (chart installs — AWS cost is in underlying resources)
    "helm_release",
    # Cloudflare provider — separate billing, not AWS
    "cloudflare_dns_record", "cloudflare_record",
    "cloudflare_load_balancer", "cloudflare_load_balancer_pool",
    "cloudflare_load_balancer_monitor",
    # Sub-resources confirmed uncovered in practice
    "aws_backup_plan", "aws_backup_selection", "aws_backup_vault",
    "aws_ec2_transit_gateway_peering_attachment",
    "aws_ec2_transit_gateway_route",
    "aws_s3_bucket_website_configuration",
    "aws_vpc_endpoint_service",
    # EC2 network observability — no direct AWS charge
    "aws_ec2_instance_connect_endpoint",
    "aws_ec2_traffic_mirror_filter",
    "aws_ec2_traffic_mirror_filter_rule",
    "aws_ec2_traffic_mirror_session",
    "aws_ec2_traffic_mirror_target",
})

# Registry of per-resource-type cost functions.
_RESOURCE_COST_FNS: Dict[str, Callable] = {
    "aws_instance":                        _cost_aws_instance,
    "aws_db_instance":                     _cost_aws_db_instance,
    "aws_rds_cluster_instance":            _cost_aws_rds_cluster_instance,
    "aws_ebs_volume":                      _cost_aws_ebs_volume,
    "aws_nat_gateway":                     _cost_aws_nat_gateway,
    "aws_eip":                             _cost_aws_eip,
    "aws_lb":                              _cost_aws_lb,
    "aws_alb":                             _cost_aws_lb,
    "aws_elb":                             _cost_aws_lb,
    "aws_lambda_function":                 _cost_aws_lambda_function,
    "aws_cloudwatch_log_group":            _cost_aws_cloudwatch_log_group,
    "aws_cloudwatch_metric_alarm":         _cost_aws_cloudwatch_metric_alarm,
    "aws_s3_bucket":                       _cost_aws_s3_bucket,
    "aws_dynamodb_table":                  _cost_aws_dynamodb_table,
    "aws_ecs_task_definition":             _cost_aws_ecs_task_definition,
    "aws_eks_cluster":                     _cost_aws_eks_cluster,
    "aws_elasticache_cluster":             _cost_aws_elasticache_cluster,
    "aws_elasticache_replication_group":   _cost_aws_elasticache_replication_group,
    "aws_msk_cluster":                     _cost_aws_msk_cluster,
    "aws_opensearch_domain":               _cost_aws_opensearch_domain,
    "aws_elasticsearch_domain":            _cost_aws_opensearch_domain,   # alias
    "aws_redshift_cluster":                _cost_aws_redshift_cluster,
    "aws_secretsmanager_secret":           _cost_aws_secretsmanager_secret,
    "aws_vpc_endpoint":                    _cost_aws_vpc_endpoint,
    "aws_wafv2_web_acl":                   _cost_aws_wafv2_web_acl,
    "aws_sfn_state_machine":               _cost_aws_sfn_state_machine,
    "aws_api_gateway_rest_api":            _cost_aws_api_gateway_rest_api,
    "aws_apigatewayv2_api":               _cost_aws_apigatewayv2_api,
    "aws_kinesis_stream":                  _cost_aws_kinesis_stream,
    "aws_route53_health_check":            _cost_aws_route53_health_check,
    "aws_route53_zone":                    _cost_aws_route53_zone,
    "aws_kms_key":                         _cost_aws_kms_key,
    "aws_efs_file_system":                 _cost_aws_efs_file_system,
    "aws_ec2_transit_gateway":             _cost_aws_ec2_transit_gateway,
    "aws_ec2_transit_gateway_vpc_attachment": _cost_aws_ec2_transit_gateway_vpc_attachment,
    "aws_cloudwatch_dashboard":            _cost_aws_cloudwatch_dashboard,
    "aws_ecr_repository":                  _cost_aws_ecr_repository,
    "aws_cloudfront_distribution":         _cost_aws_cloudfront_distribution,
}


def estimate_total_cost(
    blocks: Dict[str, List[dict]], pricing: dict, usage: dict
) -> List[ResourceCost]:
    """
    Compute a monthly cost for every resource block whose type has a cost
    function registered in *_RESOURCE_COST_FNS*.

    Returns a list of :class:`ResourceCost` objects.
    """
    var_hints = _build_var_hints(blocks, pricing)
    usage_with_hints = {**usage, "_var_hints": var_hints} if var_hints else usage

    results: List[ResourceCost] = []
    for resource_type, cost_fn in _RESOURCE_COST_FNS.items():
        for block in blocks.get(resource_type, []):
            try:
                rc = cost_fn(block, pricing, usage_with_hints)
                results.append(rc)
            except Exception as exc:
                logger.warning(
                    "cost_fn for %s %s failed: %s",
                    resource_type, block.get("name"), exc,
                )
    return results


# ── Phase 3 — Markdown / summary formatters ──────────────────────────────────

def _fmt_usd(n: float) -> str:
    """Format a dollar amount; show '<$1' for positive sub-dollar values."""
    if 0 < n < 1:
        return "<$1"
    return f"${n:,.0f}"


def _findings_section_md(
    title: str,
    findings: List[dict],
    limit: Optional[int],
    always_expanded: bool = False,
    total: Optional[int] = None,
) -> List[str]:
    """
    Render a list of findings as a Markdown section.

    When *always_expanded* is True the section has no <details> wrapper.
    Otherwise it is wrapped in a collapsible <details> block.
    *limit* controls how many rows appear; None = all.  0 = omit entirely.
    *total* is the untruncated count (shown in the header as "X of Y").
    Rows beyond the limit are replaced with "… and N more — see full report".
    """
    if limit == 0 or not findings:
        return []

    shown = findings if limit is None else findings[:limit]
    overflow = len(findings) - len(shown)

    rows: List[str] = []
    for f in shown:
        sev  = f.get("severity", "").upper()
        rid  = f.get("rule_id") or f.get("check_id", "")
        fname = os.path.basename(f.get("file", "") or f.get("image", ""))
        line_n = f.get("line", "")
        loc = f"{fname}:{line_n}" if line_n else fname
        raw_desc = f.get("description", f.get("name", ""))
        # Normalise: collapse whitespace/newlines, escape pipe (table breaker)
        desc = " ".join(raw_desc.replace("\r", "").replace("\n", " ").split())
        desc = desc.replace("|", "\u2502")[:90]
        rows.append(f"| {sev} | {rid} | {loc} | {desc} |")

    table = [
        f"| Severity | Rule | Location | Description |",
        "|---|---|---|---|",
    ] + rows

    if overflow > 0:
        table.append(f"| | | | _\u2026 and {overflow} more \u2014 see full report_ |")

    displayed = len(shown)
    real_total = total if total is not None else len(findings)
    count_str = f"{displayed} of {real_total}" if real_total > displayed else str(real_total)

    if always_expanded:
        header = f"### {title} ({count_str})"
        return [header, ""] + table + [""]

    return [
        f"<details>",
        f"<summary><b>{title} ({count_str})</b></summary>",
        "",
    ] + table + [
        "",
        "</details>",
        "",
    ]


def format_ci_summary_md(
    report_dict: dict,
    ci_limits: Optional[Dict[str, Dict[str, Optional[int]]]] = None,
    baseline: Optional[dict] = None,
    run_url: str = "",
) -> str:
    """
    Return GitHub-flavoured Markdown for the GitHub Actions step summary.

    Security-first layout:
      1. Grade overview (always visible)
      2. CRITICAL findings — all scanners — always expanded
      3. HIGH findings — <details> collapsed, scanner limit applied
      4. MEDIUM findings (IaC) — <details> collapsed, scanner limit applied
      5. MEDIUM findings (containers) — omitted by default (limit=0)
      6. Cost line (always visible)
      7. Cost savings opportunities — <details> always collapsed

    *ci_limits* is a dict keyed by category ("cost", "security", "container")
    mapping to the scanner's CI_SEVERITY_LIMITS dict.  Falls back to base
    defaults when not supplied.

    *baseline* is a previously saved report_dict used to compute deltas.
    """
    _DEFAULT_LIMITS: Dict[str, Optional[int]] = {
        "critical": None, "high": None, "medium": 10, "low": 0, "info": 0,
    }
    limits_by_cat = ci_limits or {}

    def _limits(cat: str) -> Dict[str, Optional[int]]:
        return {**_DEFAULT_LIMITS, **(limits_by_cat.get(cat) or {})}

    overall = report_dict.get("overall", {})
    cost_g  = report_dict.get("cost", {})
    sec_g   = report_dict.get("security", {})
    cont_g  = report_dict.get("container", {})
    findings = report_dict.get("findings", {})
    metrics  = report_dict.get("metrics", {})
    savings  = metrics.get("savings_estimate", {})

    lines: List[str] = ["## 🔍 InfraScan", ""]

    # ── 1. Grade overview ─────────────────────────────────────────────────────
    grade_rows: List[str] = []
    def _grade_row(name: str, g: dict) -> None:
        if not g or g.get("max_score", 0) == 0:
            return
        letter = g.get("letter", "?")
        pct    = g.get("percentage", 0)
        bd     = g.get("severity_breakdown", {})
        parts = []
        if bd.get("critical"): parts.append(f"🔴 {bd['critical']} critical")
        if bd.get("high"):     parts.append(f"{bd['high']} high")
        if bd.get("medium"):   parts.append(f"{bd['medium']} medium")
        detail = ", ".join(parts) if parts else "clean"
        grade_rows.append(f"| {name} | **{letter}** ({pct}%) | {detail} |")

    _grade_row("Overall",   overall)
    _grade_row("Security",  sec_g)
    _grade_row("Cost",      cost_g)
    _grade_row("Containers", cont_g)

    if grade_rows:
        lines += ["| Category | Grade | Findings |", "|---|---|---|"] + grade_rows + [""]

    # ── 2. Infrastructure cost / baseline delta ──────────────────────────────
    total_cost_early = savings.get("total_infra_cost_usd_month")
    if total_cost_early:
        base_cost_early = None
        if baseline:
            base_cost_early = (baseline.get("metrics", {})
                               .get("savings_estimate", {})
                               .get("total_infra_cost_usd_month"))
        if base_cost_early:
            delta_e = round(total_cost_early - base_cost_early, 2)
            delta_str_e = (f"**+{_fmt_usd(delta_e)}/mo \u26a0\ufe0f**" if delta_e > 0
                           else f"**{_fmt_usd(delta_e)}/mo \u2705**" if delta_e < 0
                           else "no change")
            lines += [
                "| | Baseline | This PR | Delta |",
                "|---|---|---|---|",
                f"| Infra cost | {_fmt_usd(base_cost_early)}/mo"
                f" | {_fmt_usd(total_cost_early)}/mo | {delta_str_e} |",
                "",
            ]
        else:
            lines += [f"**Infrastructure cost:** {_fmt_usd(total_cost_early)}/mo", ""]

    # ── 3 & 4. Security + container findings by severity ─────────────────────
    all_sec  = list(findings.get("security", []))
    all_cont = list(findings.get("container", []))
    all_cost = list(findings.get("cost", []))

    def _by_sev(lst: List[dict], sev: str) -> List[dict]:
        return [f for f in lst if f.get("severity", "").lower() == sev]

    sec_lim  = _limits("security")
    cont_lim = _limits("container")
    cost_lim = _limits("cost")

    # CRITICAL — always expanded, all sources
    crit_all = (
        _by_sev(all_sec, "critical") +
        _by_sev(all_cont, "critical") +
        _by_sev(all_cost, "critical")
    )
    if crit_all:
        lines += _findings_section_md("CRITICAL findings", crit_all,
                                       limit=None, always_expanded=True)
    else:
        lines += ["✅ No critical findings", ""]

    # HIGH — collapsed; track total before per-category caps
    high_sec_all  = _by_sev(all_sec, "high")
    high_cont_all = _by_sev(all_cont, "high")
    high_cost_all = _by_sev(all_cost, "high")
    total_high = len(high_sec_all) + len(high_cont_all) + len(high_cost_all)
    high_sec_lim  = sec_lim.get("high")
    high_cont_lim = cont_lim.get("high")
    high_cost_lim = cost_lim.get("high")
    high_all = (
        (high_sec_all  if high_sec_lim  is None else high_sec_all[:high_sec_lim]) +
        (high_cont_all if high_cont_lim is None else high_cont_all[:high_cont_lim]) +
        (high_cost_all if high_cost_lim is None else high_cost_all[:high_cost_lim])
    )
    if high_all:
        lines += _findings_section_md("HIGH findings", high_all,
                                       limit=len(high_all),
                                       always_expanded=False,
                                       total=total_high)

    # MEDIUM — collapsed; containers omitted when limit=0
    med_sec_all  = _by_sev(all_sec, "medium")
    med_cont_all = _by_sev(all_cont, "medium")
    med_cost_all = _by_sev(all_cost, "medium")
    med_cont_limit = cont_lim.get("medium", 0)
    med_sec  = med_sec_all[:sec_lim.get("medium") or 0]
    med_cont = med_cont_all[:(med_cont_limit or 0)]
    med_cost = med_cost_all[:cost_lim.get("medium") or 0]
    total_med = len(med_sec_all) + len(med_cont_all) + len(med_cost_all)

    shown_med = med_sec + med_cont + med_cost
    if shown_med:
        lines += _findings_section_md("MEDIUM findings",
                                       shown_med,
                                       limit=len(shown_med),
                                       always_expanded=False,
                                       total=total_med)
    if med_cont_limit == 0 and med_cont_all:
        lines += [f"_ℹ️ {len(med_cont_all)} container MEDIUM CVEs omitted "
                  f"\u2014 see full HTML report._", ""]

    # ── 5. Cost savings separator ────────────────────────────────────────────
    lines.append("---")
    lines.append("")

    # ── 5. Cost savings — always collapsed ────────────────────────────────────
    per_finding = sorted(
        [f for f in savings.get("per_finding", []) if f.get("saving_high", 0) > 0],
        key=lambda f: f.get("saving_high", 0),
        reverse=True,
    )
    if per_finding:
        lo = savings.get("low_usd_month", 0)
        hi = savings.get("high_usd_month", 0)
        saving_str = _fmt_usd(lo) if lo == hi else f"{_fmt_usd(lo)}–{_fmt_usd(hi)}"
        # Build rule_id → human-readable name from the cost findings list
        rule_names: Dict[str, str] = {
            f.get("rule_id", ""): f.get("rule_name", "")
            for f in all_cost if f.get("rule_id") and f.get("rule_name")
        }
        rows_md = ["| Rule | Description | File | Saving/month |", "|---|---|---|---|"]
        for pf in per_finding[:10]:
            s_lo   = pf.get("saving_low", 0)
            s_hi   = pf.get("saving_high", 0)
            rid    = pf.get("rule_id", "")
            rname  = rule_names.get(rid, "")
            fname  = os.path.basename(pf.get("file", ""))
            line_n = pf.get("line", "")
            s_str  = _fmt_usd(s_lo) if s_lo == s_hi else f"{_fmt_usd(s_lo)}–{_fmt_usd(s_hi)}"
            rows_md.append(f"| {rid} | {rname} | {fname}:{line_n} | {s_str} |")
        lines += [
            "<details>",
            f"<summary>Cost savings opportunities: {saving_str}/mo</summary>",
            "",
        ] + rows_md + ["", "</details>", ""]

    # no run_url link in step summary — you're already on the run page

    return "\n".join(lines)


def format_pr_comment_md(
    report_dict: dict,
    baseline: Optional[dict] = None,
    alert_on: str = "critical",
    run_url: str = "",
) -> str:
    """
    Return a compact PR comment.  Always posts at least a brief summary so the
    team knows InfraScan ran; detailed sections are added when actionable:
    - new CRITICAL findings (always shown),
    - new HIGH findings when alert_on='critical_high',
    - cost delta > $5/mo or > 10%.
    """
    findings = report_dict.get("findings", {})
    metrics  = report_dict.get("metrics", {})
    savings  = metrics.get("savings_estimate", {})
    overall  = report_dict.get("overall", {})

    all_findings = (
        list(findings.get("security", [])) +
        list(findings.get("container", [])) +
        list(findings.get("cost", []))
    )

    def _by_sev(sev: str) -> List[dict]:
        return [f for f in all_findings if f.get("severity", "").lower() == sev]

    crits = _by_sev("critical")
    highs = _by_sev("high")

    # Compute cost delta
    total_cost = savings.get("total_infra_cost_usd_month", 0)
    base_cost  = 0.0
    if baseline:
        base_cost = (baseline.get("metrics", {})
                     .get("savings_estimate", {})
                     .get("total_infra_cost_usd_month", 0))
    cost_delta = round(total_cost - base_cost, 2) if base_cost else 0.0
    cost_delta_pct = round(cost_delta / base_cost * 100, 1) if base_cost else 0.0

    # Delta-aware new finding detection
    baseline_findings: List[dict] = []
    if baseline:
        bf = baseline.get("findings", {})
        baseline_findings = (
            list(bf.get("security", [])) +
            list(bf.get("container", [])) +
            list(bf.get("cost", []))
        )
    base_keys = {
        (f.get("rule_id") or f.get("check_id", ""), f.get("file", ""))
        for f in baseline_findings
    }
    new_crits = [f for f in crits if
                 (f.get("rule_id") or f.get("check_id",""), f.get("file","")) not in base_keys]
    new_highs = [f for f in highs if
                 (f.get("rule_id") or f.get("check_id",""), f.get("file","")) not in base_keys]

    # When there's no baseline, treat all critical/high as "new"
    if not baseline:
        new_crits = crits
        new_highs = highs

    has_actionable = bool(new_crits)
    if alert_on == "critical_high":
        has_actionable = has_actionable or bool(new_highs)
    has_actionable = has_actionable or (cost_delta > 5 or cost_delta_pct > 10)

    letter = overall.get("letter", "?")
    pct    = overall.get("percentage", 0)
    lines  = [f"## 🔍 InfraScan: {letter} ({pct}%)", ""]

    # ── Grade overview table (always) ─────────────────────────────────────────
    cost_g = report_dict.get("cost", {})
    sec_g  = report_dict.get("security", {})
    cont_g = report_dict.get("container", {})

    def _grade_row(name: str, g: dict) -> Optional[str]:
        if not g or g.get("max_score", 0) == 0:
            return None
        gl  = g.get("letter", "?")
        gp  = g.get("percentage", 0)
        bd  = g.get("severity_breakdown", {})
        parts = []
        if bd.get("critical"): parts.append(f"🔴 {bd['critical']} critical")
        if bd.get("high"):     parts.append(f"{bd['high']} high")
        if bd.get("medium"):   parts.append(f"{bd['medium']} medium")
        detail = ", ".join(parts) if parts else "✅ clean"
        return f"| {name} | **{gl}** ({gp}%) | {detail} |"

    grade_rows = [r for r in [
        _grade_row("Overall",    overall),
        _grade_row("Security",   sec_g),
        _grade_row("Cost",       cost_g),
        _grade_row("Containers", cont_g),
    ] if r]
    if grade_rows:
        lines += ["| Category | Grade | Findings |", "|---|---|---|"] + grade_rows + [""]

    # ── Infrastructure cost line ───────────────────────────────────────────────
    if base_cost and cost_delta != 0:
        delta_str = f"**+{_fmt_usd(cost_delta)}/mo ⚠️**" if cost_delta > 0 else f"**{_fmt_usd(cost_delta)}/mo ✅**"
        lines += [
            "| | Baseline | This PR | Delta |",
            "|---|---|---|---|",
            f"| Infra cost | {_fmt_usd(base_cost)}/mo | {_fmt_usd(total_cost)}/mo | {delta_str} |",
            "",
        ]
    elif total_cost:
        lines += [f"**Infrastructure cost:** {_fmt_usd(total_cost)}/mo", ""]

    if not has_actionable:
        # Clean summary — confirms the scan ran without noise
        lines.append("✅ No new critical findings.")
        if run_url:
            lines += ["", f"→ [Full report in Actions summary]({run_url}) (HTML artifact also attached)"]
        return "\n".join(lines)

    # New CRITICAL findings
    if new_crits:
        lines += [f"### 🔴 New CRITICAL findings ({len(new_crits)})",
                  "| Rule | File | Description |", "|---|---|---|"]
        for f in new_crits[:10]:
            rid   = f.get("rule_id") or f.get("check_id", "")
            fname = os.path.basename(f.get("file", "") or f.get("image", ""))
            line_n = f.get("line", "")
            loc   = f"{fname}:{line_n}" if line_n else fname
            desc  = (f.get("description", f.get("name", "")))[:70]
            lines.append(f"| {rid} | {loc} | {desc} |")
        if len(new_crits) > 10:
            lines.append(f"| | | _… and {len(new_crits)-10} more_ |")
        lines.append("")

    # New HIGH findings (only when alert_on=critical_high)
    if alert_on == "critical_high" and new_highs:
        lines += [f"### 🟠 New HIGH findings ({len(new_highs)})",
                  "| Rule | File | Description |", "|---|---|---|"]
        for f in new_highs[:5]:
            rid   = f.get("rule_id") or f.get("check_id", "")
            fname = os.path.basename(f.get("file", "") or f.get("image", ""))
            line_n = f.get("line", "")
            loc   = f"{fname}:{line_n}" if line_n else fname
            desc  = (f.get("description", f.get("name", "")))[:70]
            lines.append(f"| {rid} | {loc} | {desc} |")
        if len(new_highs) > 5:
            lines.append(f"| | | _… and {len(new_highs)-5} more_ |")
        lines.append("")

    if run_url:
        lines.append(f"→ [Full report in Actions summary]({run_url}) (HTML artifact also attached)")

    return "\n".join(lines)


def format_savings_summary_md(
    savings_estimate: dict,
    overall_grade: Optional[str] = None,
    overall_pct: Optional[float] = None,
    security_findings: Optional[List[dict]] = None,
    container_findings: Optional[List[dict]] = None,
) -> str:
    """Deprecated — use format_ci_summary_md() instead."""
    fake_report = {
        "overall": {"letter": overall_grade, "percentage": overall_pct},
        "findings": {
            "security": security_findings or [],
            "container": container_findings or [],
        },
        "metrics": {"savings_estimate": savings_estimate or {}},
    }
    return format_ci_summary_md(fake_report)
