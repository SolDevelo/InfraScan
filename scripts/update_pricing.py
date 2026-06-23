#!/usr/bin/env python3
"""
Update reporter/pricing_table.json with current AWS on-demand prices.

Uses the public AWS Bulk Pricing JSON endpoints -- no credentials, no boto3.
The EC2 regional file is ~40 MB compressed; others are typically 5-20 MB each.
All files are cached to /tmp so re-runs in the same session skip the download.

Usage:
    python3 scripts/update_pricing.py [--region us-east-1] [--dry-run] [--no-cache]

No extra dependencies beyond Python 3 stdlib.
"""

import argparse
import gzip
import hashlib
import json
import logging
import os
import sys
import tempfile
import urllib.request
from datetime import date
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

_PRICING_BASE = "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws"

_REGION_NAME: Dict[str, str] = {
    "us-east-1":      "US East (N. Virginia)",
    "us-east-2":      "US East (Ohio)",
    "us-west-1":      "US West (N. California)",
    "us-west-2":      "US West (Oregon)",
    "eu-west-1":      "Europe (Ireland)",
    "eu-central-1":   "Europe (Frankfurt)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
}

_EC2_TYPES = [
    "t2.nano", "t2.micro", "t2.small", "t2.medium", "t2.large", "t2.xlarge", "t2.2xlarge",
    "t3.nano", "t3.micro", "t3.small", "t3.medium", "t3.large", "t3.xlarge", "t3.2xlarge",
    "m3.medium", "m3.large",
    "m4.large", "m4.xlarge", "m4.2xlarge", "m4.4xlarge", "m4.10xlarge",
    "m5.large", "m5.xlarge", "m5.2xlarge", "m5.4xlarge", "m5.8xlarge",
    "c4.large", "c4.xlarge", "c4.2xlarge", "c4.4xlarge", "c4.8xlarge",
    "c5.large", "c5.xlarge", "c5.2xlarge",
    "r3.large", "r3.xlarge", "r3.2xlarge", "r3.4xlarge", "r3.8xlarge",
    "r4.large", "r4.xlarge", "r4.2xlarge", "r4.4xlarge", "r4.8xlarge", "r4.16xlarge",
    "r5.large", "r5.xlarge", "r5.2xlarge", "r5.8xlarge", "r5.12xlarge", "r5.24xlarge",
]

_RDS_CLASSES = [
    "db.t2.micro", "db.t2.small", "db.t2.medium", "db.t2.large", "db.t2.xlarge", "db.t2.2xlarge",
    "db.t3.micro", "db.t3.small", "db.t3.medium", "db.t3.large", "db.t3.xlarge", "db.t3.2xlarge",
    "db.m3.medium", "db.m3.large",
    "db.m4.large", "db.m4.xlarge", "db.m4.2xlarge", "db.m4.4xlarge", "db.m4.10xlarge",
    "db.m5.large", "db.m5.xlarge", "db.m5.2xlarge", "db.m5.4xlarge", "db.m5.8xlarge", "db.m5.12xlarge",
    "db.r3.large", "db.r3.xlarge", "db.r3.2xlarge", "db.r3.4xlarge", "db.r3.8xlarge",
    "db.r4.large", "db.r4.xlarge", "db.r4.2xlarge", "db.r4.4xlarge", "db.r4.8xlarge", "db.r4.16xlarge",
    "db.r5.large", "db.r5.xlarge", "db.r5.2xlarge", "db.r5.4xlarge", "db.r5.8xlarge", "db.r5.16xlarge",
]

_ELASTICACHE_TYPES = [
    "cache.t3.micro", "cache.t3.small", "cache.t3.medium",
    "cache.m5.large", "cache.m5.xlarge",
    "cache.r5.large", "cache.r5.xlarge",
    "cache.r6g.large", "cache.r6g.xlarge",
]

_OPENSEARCH_TYPES = [
    "t3.small.search", "t3.medium.search",
    "m5.large.search", "m5.xlarge.search",
    "r5.large.search", "r5.xlarge.search",
    "r6g.large.search", "r6g.xlarge.search",
]

_REDSHIFT_TYPES = [
    "dc2.large", "dc2.8xlarge",
    "ds2.xlarge", "ds2.8xlarge",
    "ra3.xlplus", "ra3.4xlarge", "ra3.16xlarge",
]

_MSK_TYPES = [
    "kafka.t3.small",
    "kafka.m5.large", "kafka.m5.xlarge", "kafka.m5.2xlarge", "kafka.m5.4xlarge",
    "kafka.m6g.large", "kafka.m6g.xlarge",
]


def _fetch_json(url: str, no_cache: bool = False) -> dict:
    cache_key  = hashlib.md5(url.encode()).hexdigest()
    cache_path = os.path.join(tempfile.gettempdir(), f"infrascan_pricing_{cache_key}.json")

    if not no_cache and os.path.exists(cache_path):
        logger.info("Using cached %s", url)
        with open(cache_path, "r", encoding="utf-8") as f:
            return json.load(f)

    logger.info("Downloading %s ...", url)
    req = urllib.request.Request(url, headers={"Accept-Encoding": "gzip"})
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            raw      = resp.read()
            encoding = resp.headers.get("Content-Encoding", "")
    except Exception as exc:
        sys.exit(f"Failed to download {url}: {exc}")

    if encoding == "gzip" or raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)

    data = json.loads(raw)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return data


def _on_demand_price(data: dict, sku: str) -> Optional[float]:
    for term in data.get("terms", {}).get("OnDemand", {}).get(sku, {}).values():
        for dim in term.get("priceDimensions", {}).values():
            try:
                p = float(dim["pricePerUnit"]["USD"])
                if p > 0:
                    return p
            except (KeyError, ValueError):
                pass
    return None


#  EC2 + EBS 

def fetch_ec2_prices(data: dict, region_name: str) -> Dict[str, float]:
    wanted  = set(_EC2_TYPES)
    sku_map: Dict[str, str] = {}
    for sku, prod in data.get("products", {}).items():
        attrs = prod.get("attributes", {})
        if (
            attrs.get("instanceType") in wanted
            and attrs.get("operatingSystem") == "Linux"
            and attrs.get("tenancy") == "Shared"
            and attrs.get("preInstalledSw") == "NA"
            and attrs.get("capacitystatus") == "Used"
            and attrs.get("location") == region_name
        ):
            sku_map[attrs["instanceType"]] = sku

    prices: Dict[str, float] = {}
    for itype in _EC2_TYPES:
        sku = sku_map.get(itype)
        if not sku:
            logger.warning("  EC2 %-20s - SKU not found, keeping existing", itype)
            continue
        p = _on_demand_price(data, sku)
        if p is None:
            logger.warning("  EC2 %-20s - price not found, keeping existing", itype)
            continue
        prices[itype] = round(p * 730, 2)
        logger.info("  EC2 %-20s $%.6f/hr -> $%.2f/mo", itype, p, prices[itype])
    return prices


def fetch_ebs_prices(data: dict, region_name: str) -> Tuple[Dict[str, float], Dict[str, float]]:
    vol_types = {"gp2", "gp3", "io1", "io2", "st1", "sc1"}
    gb_skus:   Dict[str, str] = {}
    iops_skus: Dict[str, str] = {}

    for sku, prod in data.get("products", {}).items():
        attrs = prod.get("attributes", {})
        if attrs.get("location") != region_name:
            continue
        vol = attrs.get("volumeApiName", "")
        fam = prod.get("productFamily", "")
        if fam == "Storage" and vol in vol_types:
            gb_skus[vol] = sku
        elif fam == "System Operation" and attrs.get("group") == "EBS IOPS" and vol in {"io1", "io2"}:
            iops_skus[vol] = sku

    per_gb: Dict[str, float] = {}
    for vol in sorted(vol_types):
        sku = gb_skus.get(vol)
        if not sku:
            logger.warning("  EBS %-6s GB  - SKU not found, keeping existing", vol)
            continue
        p = _on_demand_price(data, sku)
        if p is not None:
            per_gb[vol] = round(p, 4)
            logger.info("  EBS %-6s GB  $%.4f/GB-mo", vol, p)
        else:
            logger.warning("  EBS %-6s GB  - price not found, keeping existing", vol)

    per_iops: Dict[str, float] = {}
    for vol in ["io1", "io2"]:
        sku = iops_skus.get(vol)
        if not sku:
            continue
        p = _on_demand_price(data, sku)
        if p is not None:
            per_iops[vol] = round(p, 5)
            logger.info("  EBS %-6s IOPS $%.5f/IOPS-mo", vol, p)

    return per_gb, per_iops


#  RDS 

def fetch_rds_prices(data: dict, region_name: str) -> Dict[str, float]:
    wanted  = set(_RDS_CLASSES)
    sku_map: Dict[str, str] = {}
    for sku, prod in data.get("products", {}).items():
        attrs = prod.get("attributes", {})
        if (
            attrs.get("instanceType") in wanted
            and attrs.get("databaseEngine") == "MySQL"
            and attrs.get("deploymentOption") == "Single-AZ"
            and attrs.get("location") == region_name
        ):
            sku_map[attrs["instanceType"]] = sku

    prices: Dict[str, float] = {}
    for cls in _RDS_CLASSES:
        sku = sku_map.get(cls)
        if not sku:
            logger.warning("  RDS %-25s - SKU not found, keeping existing", cls)
            continue
        p = _on_demand_price(data, sku)
        if p is None:
            logger.warning("  RDS %-25s - price not found, keeping existing", cls)
            continue
        prices[cls] = round(p * 730, 2)
        logger.info("  RDS %-25s $%.6f/hr -> $%.2f/mo", cls, p, prices[cls])
    return prices


#  ElastiCache 

def fetch_elasticache_prices(data: dict, region_name: str) -> Dict[str, float]:
    wanted  = set(_ELASTICACHE_TYPES)
    sku_map: Dict[str, str] = {}
    for sku, prod in data.get("products", {}).items():
        attrs = prod.get("attributes", {})
        if (
            attrs.get("instanceType") in wanted
            and attrs.get("cacheEngine") == "Redis"
            and attrs.get("location") == region_name
            and prod.get("productFamily") == "Cache Instance"
        ):
            sku_map[attrs["instanceType"]] = sku

    prices: Dict[str, float] = {}
    for itype in _ELASTICACHE_TYPES:
        sku = sku_map.get(itype)
        if not sku:
            logger.warning("  ElastiCache %-25s - SKU not found, keeping existing", itype)
            continue
        p = _on_demand_price(data, sku)
        if p is None:
            logger.warning("  ElastiCache %-25s - price not found, keeping existing", itype)
            continue
        prices[itype] = round(p * 730, 2)
        logger.info("  ElastiCache %-25s $%.6f/hr -> $%.2f/mo", itype, p, prices[itype])
    return prices


#  OpenSearch / Elasticsearch â”€

def fetch_opensearch_prices(data: dict, region_name: str) -> Dict[str, float]:
    # The bulk pricing API still uses the legacy "AmazonES" service code.
    # productFamily is "Amazon Elasticsearch Service Instance" for both ES and OpenSearch instances.
    wanted  = set(_OPENSEARCH_TYPES)
    sku_map: Dict[str, str] = {}
    for sku, prod in data.get("products", {}).items():
        attrs = prod.get("attributes", {})
        if (
            attrs.get("instanceType") in wanted
            and attrs.get("location") == region_name
            and "Elasticsearch" in prod.get("productFamily", "")
        ):
            sku_map[attrs["instanceType"]] = sku

    prices: Dict[str, float] = {}
    for itype in _OPENSEARCH_TYPES:
        sku = sku_map.get(itype)
        if not sku:
            logger.warning("  OpenSearch %-25s - SKU not found, keeping existing", itype)
            continue
        p = _on_demand_price(data, sku)
        if p is None:
            logger.warning("  OpenSearch %-25s - price not found, keeping existing", itype)
            continue
        prices[itype] = round(p * 730, 2)
        logger.info("  OpenSearch %-25s $%.6f/hr -> $%.2f/mo", itype, p, prices[itype])
    return prices


#  Redshift â”€

def fetch_redshift_prices(data: dict, region_name: str) -> Dict[str, float]:
    wanted  = set(_REDSHIFT_TYPES)
    sku_map: Dict[str, str] = {}
    for sku, prod in data.get("products", {}).items():
        attrs = prod.get("attributes", {})
        if (
            attrs.get("instanceType") in wanted
            and attrs.get("location") == region_name
            and prod.get("productFamily") == "Compute Instance"
            and "Redshift" in attrs.get("servicecode", "")
        ):
            sku_map[attrs["instanceType"]] = sku

    prices: Dict[str, float] = {}
    for itype in _REDSHIFT_TYPES:
        sku = sku_map.get(itype)
        if not sku:
            logger.warning("  Redshift %-20s - SKU not found, keeping existing", itype)
            continue
        p = _on_demand_price(data, sku)
        if p is None:
            logger.warning("  Redshift %-20s - price not found, keeping existing", itype)
            continue
        prices[itype] = round(p * 730, 2)
        logger.info("  Redshift %-20s $%.6f/hr -> $%.2f/mo", itype, p, prices[itype])
    return prices


#  MSK (Kafka) 

def fetch_msk_prices(data: dict, region_name: str) -> Dict[str, float]:
    wanted  = set(_MSK_TYPES)
    sku_map: Dict[str, str] = {}
    for sku, prod in data.get("products", {}).items():
        attrs = prod.get("attributes", {})
        if (
            attrs.get("instanceType") in wanted
            and attrs.get("location") == region_name
        ):
            sku_map[attrs["instanceType"]] = sku

    prices: Dict[str, float] = {}
    for itype in _MSK_TYPES:
        sku = sku_map.get(itype)
        if not sku:
            logger.warning("  MSK %-25s - SKU not found, keeping existing", itype)
            continue
        p = _on_demand_price(data, sku)
        if p is None:
            logger.warning("  MSK %-25s - price not found, keeping existing", itype)
            continue
        prices[itype] = round(p * 730, 2)
        logger.info("  MSK %-25s $%.6f/hr -> $%.2f/mo", itype, p, prices[itype])
    return prices


#  main â”€

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Update InfraScan pricing_table.json from AWS public pricing (no credentials needed)"
    )
    ap.add_argument("--region",   default="us-east-1")
    ap.add_argument("--dry-run",  action="store_true", help="Print changes without writing")
    ap.add_argument("--no-cache", action="store_true", help="Ignore /tmp cache, re-download")
    args = ap.parse_args()

    region_name = _REGION_NAME.get(args.region)
    if not region_name:
        sys.exit(
            f"Unknown region '{args.region}'. Supported: {', '.join(_REGION_NAME)}. "
            "Add it to _REGION_NAME in this script."
        )

    if args.no_cache:
        for fname in os.listdir(tempfile.gettempdir()):
            if fname.startswith("infrascan_pricing_"):
                os.remove(os.path.join(tempfile.gettempdir(), fname))

    pricing_path = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reporter", "pricing_table.json")
    )
    with open(pricing_path, "r", encoding="utf-8") as f:
        table = json.load(f)

    ec2_url         = f"{_PRICING_BASE}/AmazonEC2/current/{args.region}/index.json"
    rds_url         = f"{_PRICING_BASE}/AmazonRDS/current/{args.region}/index.json"
    elasticache_url = f"{_PRICING_BASE}/AmazonElastiCache/current/{args.region}/index.json"
    opensearch_url  = f"{_PRICING_BASE}/AmazonES/current/{args.region}/index.json"
    redshift_url    = f"{_PRICING_BASE}/AmazonRedshift/current/{args.region}/index.json"
    msk_url         = f"{_PRICING_BASE}/AmazonMSK/current/{args.region}/index.json"

    logger.info("=== EC2 + EBS ===")
    ec2_data = _fetch_json(ec2_url, args.no_cache)
    for k, v in fetch_ec2_prices(ec2_data, region_name).items():
        table["ec2_instances"][k] = v
    per_gb, per_iops = fetch_ebs_prices(ec2_data, region_name)
    for k, v in per_gb.items():
        table["ebs_per_gb_month"][k] = v
    for k, v in per_iops.items():
        table["ebs_iops_per_iops_month"][k] = v

    logger.info("=== RDS ===")
    rds_data = _fetch_json(rds_url, args.no_cache)
    for k, v in fetch_rds_prices(rds_data, region_name).items():
        table["rds_instances"][k] = v

    logger.info("=== ElastiCache ===")
    ec_data = _fetch_json(elasticache_url, args.no_cache)
    ec_prices = fetch_elasticache_prices(ec_data, region_name)
    if ec_prices:
        if "elasticache_instances" not in table:
            table["elasticache_instances"] = {}
        for k, v in ec_prices.items():
            table["elasticache_instances"][k] = v

    logger.info("=== OpenSearch ===")
    os_data = _fetch_json(opensearch_url, args.no_cache)
    os_prices = fetch_opensearch_prices(os_data, region_name)
    if os_prices:
        if "opensearch_instances" not in table:
            table["opensearch_instances"] = {}
        for k, v in os_prices.items():
            table["opensearch_instances"][k] = v

    logger.info("=== Redshift ===")
    rs_data = _fetch_json(redshift_url, args.no_cache)
    rs_prices = fetch_redshift_prices(rs_data, region_name)
    if rs_prices:
        if "redshift_nodes" not in table:
            table["redshift_nodes"] = {}
        for k, v in rs_prices.items():
            table["redshift_nodes"][k] = v

    logger.info("=== MSK ===")
    msk_data = _fetch_json(msk_url, args.no_cache)
    msk_prices = fetch_msk_prices(msk_data, region_name)
    if msk_prices:
        if "msk_brokers" not in table:
            table["msk_brokers"] = {}
        for k, v in msk_prices.items():
            table["msk_brokers"][k] = v

    table["version"] = date.today().isoformat()
    table["region"]  = args.region

    if args.dry_run:
        print(json.dumps(table, indent=2))
        logger.info("Dry-run: no file written.")
        return

    with open(pricing_path, "w", encoding="utf-8") as f:
        json.dump(table, f, indent=2)
        f.write("\n")

    logger.info("Written %s  (version: %s)", pricing_path, table["version"])


if __name__ == "__main__":
    main()

