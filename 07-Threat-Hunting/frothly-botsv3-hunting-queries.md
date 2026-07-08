# Threat Hunting Scenarios - Frothly BOTSv3 Campaign
**Author:** Insiyah Bhatia  
**Date:** 2026-07-02  
**Dataset:** index=botsv3  
**Coverage:** IR-2018-001, IR-2018-002, IR-2026-0701-001



## Scenario 1: IMDS Credential Theft Detection

### Hypothesis
An adversary who gains code execution on an EC2 instance will query the Instance Metadata Service (169.254.169.254) to steal IAM role credentials before pivoting to the AWS control plane.

### SPL - IMDS HTTP Queries
```spl
index="botsv3" sourcetype="stream:http" dest_ip="169.254.169.254"
| table _time host src_ip dest_ip uri_path http_method status bytes_in bytes_out
| search uri_path="*iam/security-credentials*"
| sort _time
```

### SPL - Subsequent CloudTrail Activity (post-IMDS)
```spl
index="botsv3" sourcetype="aws:cloudtrail"
| search [| inputlookup imds_affected_hosts | fields accessKeyId]
| stats dc(eventName) as api_count, dc(awsRegion) as regions,
         values(eventName) as api_calls, values(sourceIPAddress) as src_ips
         by userIdentity.accessKeyId, _time
| sort _time
```

### Sigma Rule
Refer to `03-Sigma/aws_iam_reconnaissance_burst.yml`

### Baseline
- Normal IMDS access: AWS SDKs, CloudWatch agent, SSM agent, custom apps
- Alert on: IMDS queries from unknown process names, outside expected application profiles, followed by AWS API calls



## Scenario 2: Multi-Region RunInstances Sweep

### Hypothesis
An attacker with compromised AWS credentials will attempt to provision compute across multiple regions to maximize resource hijacking (cryptomining, botnet) yield before credentials are revoked.

### SPL - Regional Distinct Count
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventSource="ec2.amazonaws.com" eventName="RunInstances"
| bin _time span=10m
| stats dc(awsRegion) as distinct_regions, count as attempts,
         values(errorCode) as error_codes, values(sourceIPAddress) as src_ips,
         values(awsRegion) as regions_targeted
         by userIdentity.accessKeyId, _time
| where distinct_regions >= 5
| sort _time
```

### SPL - All RunInstances Error Code Distribution
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventSource="ec2.amazonaws.com" eventName="RunInstances"
| stats count by errorCode
| sort - count
```

### Sigma Rule
Refer to `03-Sigma/aws_ec2_runinstances_multi_region_sweep.yml`

### Baseline
- Normal: Infrastructure-as-code deployments within 1-3 regions
- Alert on: 5+ regions in 10 minutes from same access key



## Scenario 3: IAM Reconnaissance & Privilege Escalation Attempts

### Hypothesis
After credential compromise, an attacker will enumerate the identity's permissions and attempt persistence/privilege escalation via IAM API calls before pivoting to resource hijacking.

### SPL - IAM Sensitive API Burst
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventSource="iam.amazonaws.com"
  eventName IN ("GetCallerIdentity","ListAccessKeys","CreateAccessKey",
                "DeleteAccessKey","CreateUser","GetSessionToken")
| bin _time span=60s
| stats dc(eventName) as distinct_sensitive_calls,
         values(eventName) as actions_called,
         values(errorCode) as outcomes
         by userIdentity.accessKeyId, _time
| where distinct_sensitive_calls >= 4
| sort _time
```

### SPL - AccessDenied Error Frequency by User
```spl
index="botsv3" sourcetype="aws:cloudtrail" errorCode="AccessDenied"
  eventSource="iam.amazonaws.com"
| stats count by userIdentity.userName, eventName, sourceIPAddress
| sort - count
```

### Sigma Rule
Refer to `03-Sigma/aws_iam_reconnaissance_burst.yml`

### Baseline
- Normal: CI/CD pipelines creating/deleting keys at expected intervals
- Alert on: Mixed success+denied calls indicating enumeration



## Scenario 4: Drive-By Cryptominer Delivery via S3

### Hypothesis
An attacker who discovers a publicly writable S3 bucket will upload a cryptominer payload and inject it into a website to mine from visiting browsers.

### SPL - S3 ACL Changes
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
| table _time userIdentity.userName userIdentity.accessKeyId
         requestParameters.bucketName sourceIPAddress
| sort _time
```

### SPL - Cryptominer DNS Resolutions
```spl
index="botsv3" sourcetype="stream:dns" (query="*coinhive*" OR query="*monero*"
  OR query="*cryptoloot*" OR query="*minr*" OR query="*webmine*")
| table _time host query query_type answer
| sort _time
```

### SPL - Symantec Cryptominer Detections
```spl
index="botsv3" sourcetype="symantec:ep:security:file" signature="*coinminer*"
| table _time host user_name file_path signature_name signature_id
| sort _time
```

### SPL - Endpoint HTTP Session with Forum + DNS Correlation
```spl
index="botsv3" host="BSTOLL-L" sourcetype="stream:http" dest_ip="54.67.127.227"
| table _time uri_path status bytes_in
| search uri_path!="/pkiops*" uri_path!="/MF*"
```

### Baseline
- Normal: Occasional S3 ACL changes by storage admins
- Alert on: Public ACL grants by non-admin users or outside change windows



## Scenario 5: Non-Standard Port C2 Beaconing

### Hypothesis
Adversaries will use non-ephemeral, non-standard TCP ports for C2 communication to evade egress filtering.

### SPL - Outbound Traffic on Port 9998
```spl
index="botsv3" dest_port=9998
| table _time host src_ip dest_ip dest_port bytes_in bytes_out
| sort _time
```

### Zeek Rule
Refer to `06-Zeek/zeek-c2-beacon-detection.zeek`

### Snort Rule
Refer to `05-Snort/snort-c2-port9998.rules`

### Baseline
- Normal: Zero expected traffic on port 9998 in a brewery company environment
- Any traffic on port 9998 is suspicious



## Hunting Runbook Summary

| Priority | Scenario | Key Data Sources | Trigger |
|----------|----------|-----------------|---------|
| P0 | IMDS credential theft | stream:http, aws:cloudtrail | IMDS query + subsequent CloudTrail API calls |
| P0 | Multi-region RunInstances | aws:cloudtrail | 5+ distinct awsRegion in 10m by same accessKeyId |
| P1 | IAM recon burst | aws:cloudtrail | 4+ sensitive IAM calls in 60s by same accessKeyId |
| P1 | Drive-by cryptominer | stream:dns, symantec:ep:security:file | Cryptomining domain resolution + AV blocks |
| P2 | Non-standard port C2 | stream:tcp, stream:udp | Traffic on port 9998 or other unusual ports |



## Analytics & Correlations Across Incidents

### All Suspicious CloudTrail Activity (Single Pane)
```spl
index="botsv3" sourcetype="aws:cloudtrail"
  (eventName="RunInstances" OR eventName="PutBucketAcl" OR
   eventName IN ("GetCallerIdentity","CreateAccessKey","DeleteAccessKey",
                 "CreateUser","ListAccessKeys","GetSessionToken"))
| eval suspicious_type = case(
    eventName="RunInstances", "Resource Hijacking",
    eventName="PutBucketAcl", "S3 Misconfiguration",
    match(eventName,"GetCallerIdentity|ListAccessKeys|GetSessionToken"), "IAM Recon",
    match(eventName,"CreateAccessKey|DeleteAccessKey|CreateUser"), "Persistence Attempt",
    true(), "Other")
| stats count by suspicious_type, userIdentity.userName, eventName, errorCode, sourceIPAddress, awsRegion
| sort - count
```

### All Endpoints with Cryptomining or C2 Activity
```spl
index="botsv3" (sourcetype="stream:dns" query="*coinhive*") OR
  (sourcetype="symantec:ep:security:file" signature="*coinminer*") OR
  (sourcetype="stream:tcp" dest_port=9998)
| eval indicator_type = case(
    sourcetype="stream:dns", "Cryptominer DNS",
    sourcetype="symantec:ep:security:file", "AV Detection",
    sourcetype="stream:tcp" AND dest_port=9998, "C2 Traffic",
    true(), "Other")
| stats dc(indicator_type) as indicator_count,
         values(indicator_type) as indicators
         by host
| where indicator_count >= 1
```

*All queries tested against BOTSv3 dataset (index=botsv3). Adjust time ranges and field names for other environments.*