from __future__ import annotations

from src.common.mappings import map_aws_security_hub_finding, map_gcp_scc_finding


def test_map_aws_security_hub_finding_minimal():
    finding = {
        "Id": "abc",
        "Title": "Test",
        "AwsAccountId": "123456789012",
        "Region": "us-east-1",
        "Resources": [{"Id": "arn:aws:ec2:...:instance/i-123", "Type": "AwsEc2Instance"}],
        "Severity": {"Label": "LOW"},
    }
    m = map_aws_security_hub_finding(finding)
    assert m["provider"] == "aws"
    assert m["finding_id"] == "abc"
    assert m["severity"] == "LOW"


def test_map_gcp_scc_finding_minimal():
    msg = {
        "finding": {
            "name": "orgs/123/findings/abc",
            "category": "PUBLIC_BUCKET",
            "severity": "LOW",
            "resourceName": "//storage.googleapis.com/projects/_/buckets/demo",
            "state": "ACTIVE",
        }
    }
    m = map_gcp_scc_finding(msg)
    assert m["provider"] == "gcp"
    assert m["title"] == "PUBLIC_BUCKET"
    assert m["severity"] == "LOW"
