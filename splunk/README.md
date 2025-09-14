# Sample Splunk Saved Searches and Dashboard for MCSPM

This directory contains Splunk configurations to help you get started with the Multi-Cloud Security Posture Management data.

## Saved Searches

### High Severity Findings Alert
```spl
index=main sourcetype="mcspm:finding" severity_score>=3 
| eval urgency=case(severity_score=4,"critical",severity_score=3,"high",1=1,"medium") 
| stats count by provider, severity, urgency, account_id, project_id 
| where count > 5 
| eval alert_message="High volume of critical findings detected"
```

### Compliance Status Summary  
```spl
index=main sourcetype="mcspm:finding" compliance=*
| stats count by compliance, provider, account_id, project_id
| eval compliance_status=case(compliance="PASSED","✓ Compliant",compliance="FAILED","✗ Non-Compliant",1=1,"⚠ Unknown")
```

### Resource Type Risk Analysis
```spl
index=main sourcetype="mcspm:finding" 
| stats count as finding_count, avg(severity_score) as avg_severity by resource_type, provider
| eval risk_level=case(avg_severity>=3,"High Risk",avg_severity>=2,"Medium Risk",1=1,"Low Risk")
| sort -finding_count
```

## Dashboard JSON

The `mcspm_dashboard.json` file contains a complete Splunk dashboard with:
- Real-time finding counts by provider and severity
- Geographic distribution of findings by AWS region/GCP zone
- Top 10 resource types with security issues
- Compliance trending over time
- MITRE ATT&CK technique mapping
- Executive summary panels

Import this dashboard via Settings > User Interface > Views in Splunk.

## Alerts

Recommended alert configurations:
1. **Critical Findings**: Trigger when severity_score=4 findings > 10 in 15 minutes
2. **Compliance Drift**: Trigger when compliance="FAILED" count increases > 20% hourly
3. **New Attack Patterns**: Trigger on first occurrence of new finding categories per account/project

## Data Models

Consider accelerating these searches by creating data models for:
- Security findings (by provider, severity, resource type)
- Compliance status (by framework, control, resource)
- Attack timeline (by technique, resource, account)