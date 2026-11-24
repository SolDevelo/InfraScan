import pytest

from rules.definitions import RULES, RegexRule
from scanner.parser import scan_directory_level

REGEX_RULE_CASES = [
    (
        "COST-001",
        'instance_type = "t2.micro"',
        'instance_type = "t3.micro"'
    ),
    (
        "COST-002",
        'instance_type = "m5.8xlarge"',
        'instance_type = "m5.large"'
    ),
    (
        "COST-003",
        "encrypted = false",
        "encrypted = true"
    ),
    (
        "COST-004",
        'type = "io2"',
        'type = "gp3"'
    ),
    (
        "COST-005",
        'resource "aws_nat_gateway" "main" {}',
        'resource "aws_instance" "main" {}'
    ),
    (
        "COST-007",
        'billing_mode = "PROVISIONED"',
        'billing_mode = "PAY_PER_REQUEST"'
    ),
    (
        "COST-008",
        "monitoring = true",
        "monitoring = false"
    ),
    (
        "COST-009",
        'volume_type = "gp2"',
        'volume_type = "gp3"'
    ),
    (
        "COST-013",
        'storage_account_type = "Premium_LRS"',
        'storage_account_type = "Standard_LRS"'
    ),
    (
        "COST-014",
        'resource "aws_route53_health_check" "main" {}',
        'resource "aws_route53_record" "main" {}'
    ),
    (
        "COST-016",
        "volume_size = 100",
        "volume_size = 20"
    ),
    (
        "COST-018",
        "read_capacity = 100",
        "read_capacity = 20"
    ),
    (
        "COST-019",
        'resource "aws_lb" "main" {}',
        'resource "aws_instance" "main" {}'
    ),
    (
        "COST-020",
        'instance_class = "db.t2.micro"',
        'instance_class = "db.t3.micro"'
    ),
    (
        "COST-021",
        "memory_size = 3008",
        "memory_size = 1024"
    ),
    (
        "COST-022",
        'resource "aws_api_gateway_rest_api" "main" {}',
        'resource "aws_apigatewayv2_api" "main" {}'
    ),
    (
        "COST-023",
        "message_retention_seconds = 1209600",
        "message_retention_seconds = 345600"
    ),
]


@pytest.mark.parametrize(
    "rule_id, matching_content, nonmatching_content",
    REGEX_RULE_CASES
)
def test_regex_rule_matches(rule_id, matching_content, nonmatching_content):
    rule = next(rule for rule in RULES if rule.id == rule_id)

    assert isinstance(rule, RegexRule)

    result = rule.check(matching_content)

    assert len(result) == 1
    assert result[0]["line"] == 1
    assert result[0]["content"] == matching_content


@pytest.mark.parametrize(
    "rule_id, matching_content, nonmatching_content",
    REGEX_RULE_CASES
)
def test_regex_rule_does_not_match(rule_id, matching_content, nonmatching_content):
    rule = next(rule for rule in RULES if rule.id == rule_id)

    result = rule.check(nonmatching_content)

    assert result == []


@pytest.mark.parametrize(
    "rule_id, matching_content, nonmatching_content",
    REGEX_RULE_CASES
)
@pytest.mark.parametrize("comment_prefix", ["#", "//"])
def test_regex_rule_ignores_comments(
    rule_id, matching_content, nonmatching_content, comment_prefix
):
    rule = next(rule for rule in RULES if rule.id == rule_id)

    content = f"    {comment_prefix} {matching_content}"

    result = rule.check(content)

    assert result == []


SPECIAL_RULE_CASES = [
    (
        "COST-006",
        'resource "aws_eip" "unused" {}',
        'resource "aws_eip" "used" {\n'
        '  instance = aws_instance.main.id\n'
        '}'
    ),
    (
        "COST-010",
        'resource "aws_s3_bucket" "main" {}',
        'resource "aws_s3_bucket" "main" {}\n'
        'resource "aws_s3_bucket_lifecycle_configuration" "main" {}'
    ),
    (
        "COST-011",
        'provider "aws" {}',
        'provider "aws" {}\n'
        'resource "aws_budgets_budget" "main" {}'
    ),
    (
        "COST-012",
        'resource "aws_instance" "main" {}',
        'resource "aws_instance" "main" {}\n'
        'resource "aws_spot_instance_request" "spot" {}'
    ),
    (
        "COST-015",
        'resource "aws_cloudwatch_log_group" "main" {}',
        'resource "aws_cloudwatch_log_group" "main" {\n'
        '  retention_in_days = 14\n'
        '}'
    ),
    (
        "COST-017",
        'provider "aws" {}',
        'provider "aws" {}\n'
        'resource "aws_cur_report_definition" "main" {}'
    ),
    (
        "COST-024",
        'resource "aws_db_instance" "dev_database" {\n'
        '  multi_az = true\n'
        '}',
        'resource "aws_db_instance" "dev_database" {\n'
        '  multi_az = false\n'
        '}'
    ),
    (
        "COST-025",
        'resource "aws_ecs_task_definition" "main" {\n'
        '  family = "example"\n'
        '}',
        'resource "aws_ecs_task_definition" "main" {\n'
        '  cpu = "256"\n'
        '  memory = "512"\n'
        '}'
    ),
    (
        "COST-026",
        'resource "aws_nat_gateway" "first" {}\n'
        'resource "aws_nat_gateway" "second" {}',
        'resource "aws_nat_gateway" "first" {}'
    ),
]


@pytest.mark.parametrize(
    "rule_id, matching_content, nonmatching_content",
    SPECIAL_RULE_CASES
)
def test_special_rule_matches(
    rule_id, matching_content, nonmatching_content
):
    rule = next(rule for rule in RULES if rule.id == rule_id)

    result = rule.check(matching_content)

    assert len(result) >= 1
    assert result[0]["line"] >= 1
    assert result[0]["content"]


@pytest.mark.parametrize(
    "rule_id, matching_content, nonmatching_content",
    SPECIAL_RULE_CASES
)
def test_special_rule_does_not_match(
    rule_id, matching_content, nonmatching_content
):
    rule = next(rule for rule in RULES if rule.id == rule_id)

    result = rule.check(nonmatching_content)

    assert result == []


def test_cost_027_detects_missing_vpc_endpoint(tmp_path):
    terraform_file = tmp_path / "main.tf"

    terraform_file.write_text(
        'resource "aws_nat_gateway" "main" {}\n'
        'resource "aws_s3_bucket" "main" {}\n',
        encoding="utf-8"
    )

    rule = next(rule for rule in RULES if rule.id == "COST-027")

    findings = scan_directory_level(
        str(tmp_path),
        [str(terraform_file)],
        [rule]
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "COST-027"
    assert findings[0]["file"] == str(terraform_file)
    assert findings[0]["line"] == 1


def test_cost_027_does_not_match_with_vpc_endpoint(tmp_path):
    terraform_file = tmp_path / "main.tf"

    terraform_file.write_text(
        'resource "aws_nat_gateway" "main" {}\n'
        'resource "aws_s3_bucket" "main" {}\n'
        'resource "aws_vpc_endpoint" "s3" {}\n',
        encoding="utf-8"
    )

    rule = next(rule for rule in RULES if rule.id == "COST-027")

    findings = scan_directory_level(
        str(tmp_path),
        [str(terraform_file)],
        [rule]
    )

    assert findings == []


def test_cost_027_does_not_match_without_s3_or_dynamodb(tmp_path):
    terraform_file = tmp_path / "main.tf"

    terraform_file.write_text(
        'resource "aws_nat_gateway" "main" {}\n',
        encoding="utf-8"
    )

    rule = next(rule for rule in RULES if rule.id == "COST-027")

    findings = scan_directory_level(
        str(tmp_path),
        [str(terraform_file)],
        [rule]
    )

    assert findings == []

