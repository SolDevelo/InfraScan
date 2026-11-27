import pytest

from reporter.cost_estimator import (
    load_pricing,
    load_usage_defaults,
    _cost_aws_instance,
    _cost_aws_ebs_volume,
    _cost_aws_nat_gateway,
    estimate_total_cost,
)

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

    expected_cost = round(
        pricing["ec2_instances"]["t3.micro"]
        + 8 * pricing["ebs_per_gb_month"]["gp3"],
        2,
    )

    assert result.resource_type == "aws_instance"
    assert result.resource_name == "test_instance"
    assert result.fixed_usd_month == pytest.approx(expected_cost)
    assert result.usage_usd_month == 0
    assert result.total_usd_month == pytest.approx(expected_cost)
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

    expected_cost = round(
        100 * pricing["ebs_per_gb_month"]["gp3"],
        2,
    )

    assert result.resource_type == "aws_ebs_volume"
    assert result.fixed_usd_month == pytest.approx(expected_cost)
    assert result.usage_usd_month == 0
    assert result.total_usd_month == pytest.approx(expected_cost)
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

    expected_fixed_cost = pricing["nat_gateway_hourly"] * 730

    expected_usage_cost = (
        pricing["nat_gateway_per_gb"]
        * usage["nat_gb_per_day"]
        * 30
    )

    expected_total_cost = round(
        expected_fixed_cost + expected_usage_cost,
        2,
    )

    assert result.resource_type == "aws_nat_gateway"
    assert result.fixed_usd_month == pytest.approx(
        round(expected_fixed_cost, 2)
    )
    assert result.usage_usd_month == pytest.approx(
        round(expected_usage_cost, 2)
    )
    assert result.total_usd_month == pytest.approx(expected_total_cost)
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

    expected_ec2_cost = round(
        pricing["ec2_instances"]["t3.micro"]
        + 8 * pricing["ebs_per_gb_month"]["gp3"],
        2,
    )

    expected_ebs_cost = round(
        100 * pricing["ebs_per_gb_month"]["gp3"],
        2,
    )

    expected_nat_cost = round(
        pricing["nat_gateway_hourly"] * 730
        + pricing["nat_gateway_per_gb"]
        * usage["nat_gb_per_day"] * 30,
        2,
    )

    assert costs["aws_instance"] == pytest.approx(expected_ec2_cost)
    assert costs["aws_ebs_volume"] == pytest.approx(expected_ebs_cost)
    assert costs["aws_nat_gateway"] == pytest.approx(expected_nat_cost)

    total_cost = sum(resource.total_usd_month for resource in results)

    expected_total_cost = round(
        expected_ec2_cost + expected_ebs_cost + expected_nat_cost,
        2,
    )

    assert round(total_cost, 2) == pytest.approx(expected_total_cost)


def test_estimate_total_cost_empty_resources():
    pricing = load_pricing()
    usage = load_usage_defaults()

    results = estimate_total_cost({}, pricing, usage)

    assert results == []
