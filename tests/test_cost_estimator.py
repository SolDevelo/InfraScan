
import json
from pathlib import Path

from reporter.cost_estimator import (
    load_pricing,
    load_usage_defaults,
    _cost_aws_instance,
    _cost_aws_ebs_volume,
    _cost_aws_nat_gateway,
    estimate_total_cost,
)

def test_load_pricing():
    pricing = load_pricing()

    pricing_file = (
        Path(__file__).resolve().parents[1]
        / "reporter"
        / "pricing_table.json"
    )

    with pricing_file.open(encoding="utf-8") as file:
        expected_pricing = json.load(file)

    assert isinstance(pricing, dict)
    assert pricing
    assert pricing == expected_pricing


def test_load_usage_defaults():
    usage = load_usage_defaults()

    usage_file = (
        Path(__file__).resolve().parents[1]
        / "reporter"
        / "usage_defaults.json"
    )

    with usage_file.open(encoding="utf-8") as file:
        expected_usage = json.load(file)

    assert isinstance(usage, dict)
    assert usage
    assert usage == expected_usage


def test_ec2_instance_monthly_cost():
    pricing = load_pricing()
    usage = load_usage_defaults()

    block = {
        "resource_type": "aws_instance",
        "name": "test_instance",
        "file": "main.tf",
        "start_line": 1,
        "content": 'resource "aws_instance" "test_instance" {\n'
                   '  instance_type = "t3.micro"\n'
                   '}'
    }

    result = _cost_aws_instance(block, pricing, usage)

    assert result.resource_type == "aws_instance"
    assert result.resource_name == "test_instance"
    assert result.fixed_usd_month == 8.23
    assert result.usage_usd_month == 0
    assert result.total_usd_month == 8.23
    assert result.confidence == "high"


def test_ebs_volume_monthly_cost():
    pricing = load_pricing()
    usage = load_usage_defaults()

    block = {
        "resource_type": "aws_ebs_volume",
        "name": "test_volume",
        "file": "main.tf",
        "start_line": 1,
        "content": 'resource "aws_ebs_volume" "test_volume" {\n'
                   '  size = 100\n'
                   '  type = "gp3"\n'
                   '}'
    }

    result = _cost_aws_ebs_volume(block, pricing, usage)

    assert result.resource_type == "aws_ebs_volume"
    assert result.fixed_usd_month == 8.00
    assert result.usage_usd_month == 0
    assert result.total_usd_month == 8.00
    assert result.confidence == "high"


def test_nat_gateway_monthly_cost():
    pricing = load_pricing()
    usage = load_usage_defaults()

    block = {
        "resource_type": "aws_nat_gateway",
        "name": "test_nat",
        "file": "main.tf",
        "start_line": 1,
        "content": 'resource "aws_nat_gateway" "test_nat" {}'
    }

    result = _cost_aws_nat_gateway(block, pricing, usage)

    assert result.resource_type == "aws_nat_gateway"
    assert result.fixed_usd_month == 32.85
    assert result.usage_usd_month == 13.50
    assert result.total_usd_month == 46.35
    assert result.confidence == "medium"


def test_estimate_total_cost_multiple_resources():
    pricing = load_pricing()
    usage = load_usage_defaults()

    blocks = {
        "aws_instance": [
            {
                "resource_type": "aws_instance",
                "name": "web_server",
                "file": "main.tf",
                "start_line": 1,
                "content": 'resource "aws_instance" "web_server" {\n'
                           '  instance_type = "t3.micro"\n'
                           '}'
            }
        ],
        "aws_ebs_volume": [
            {
                "resource_type": "aws_ebs_volume",
                "name": "data_volume",
                "file": "main.tf",
                "start_line": 5,
                "content": 'resource "aws_ebs_volume" "data_volume" {\n'
                           '  size = 100\n'
                           '  type = "gp3"\n'
                           '}'
            }
        ],
        "aws_nat_gateway": [
            {
                "resource_type": "aws_nat_gateway",
                "name": "main_nat",
                "file": "main.tf",
                "start_line": 10,
                "content": 'resource "aws_nat_gateway" "main_nat" {}'
            }
        ]
    }

    results = estimate_total_cost(blocks, pricing, usage)

    assert len(results) == 3

    costs = {
        resource.resource_type: resource.total_usd_month
        for resource in results
    }

    assert costs["aws_instance"] == 8.23
    assert costs["aws_ebs_volume"] == 8.00
    assert costs["aws_nat_gateway"] == 46.35

    total_cost = sum(resource.total_usd_month for resource in results)

    assert round(total_cost, 2) == 62.58


def test_estimate_total_cost_empty_resources():
    pricing = load_pricing()
    usage = load_usage_defaults()

    results = estimate_total_cost({}, pricing, usage)

    assert results == []
