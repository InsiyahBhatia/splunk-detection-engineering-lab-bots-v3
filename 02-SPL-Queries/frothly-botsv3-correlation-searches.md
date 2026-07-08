# Correlation Searches - Frothly BOTSv3 Campaign
**Author:** Insiyah Bhatia  
**Date:** 2026-07-02  
**Dataset:** index=botsv3  
**Purpose:** Cross-data-source correlation searches linking CloudTrail, endpoint, DNS, and network telemetry to detect multi-stage attack chains.



## CS-001: IMDS Credential Theft > Cloud API Abuse

### Description
Correlates IMDS queries (stream:http) with subsequent CloudTrail activity to identify credential theft followed by AWS API abuse from the same instance.

### SPL
```spl
index="botsv3" (sourcetype="stream:http" dest_ip="169.254.169.254" uri_path="*iam/security-credentials*") OR (sourcetype="aws:cloudtrail" userIdentity.accessKeyId="AKIAJOGCDXJ5NW5PXUPA")
| eval event_type = case(sourcetype="stream:http", "IMDS_QUERY", sourcetype="aws:cloudtrail", "CLOUDTRAIL_API")
| eval details = case(
    sourcetype="stream:http", "IMDS credential query on " + host,
    sourcetype="aws:cloudtrail" AND errorCode="AccessDenied", eventName + " (" + errorCode + ")",
    sourcetype="aws:cloudtrail", eventName + " (success)"
)
| table _time event_type host details userIdentity.accessKeyId userIdentity.arn
| sort _time
```

**Note:** The `join` by `host` approach does not work here because CloudTrail logs show the log aggregator host (e.g. `splunk.froth.ly`) and the `stream:http` logs show the actual instance hostname (e.g. `mars.i-08e52f8b5a034012d`). The timeline-based correlation above uses time-adjacent event grouping instead and has been verified against IR-2018-001 where `mars` IMDS queries at 14:40:22 were followed by `web_admin` CloudTrail API calls at 14:46:12.

### MITRE ATT&CK
- T1552.005 - Cloud Instance Metadata API (precursor)
- T1078.004 - Valid Accounts: Cloud Accounts (subsequent)
- T1496 - Resource Hijacking (subsequent)

### Risk
Critical - directly confirms credential theft to cloud control plane pivot.



## CS-002: IAM Recon Burst > Multi-Region RunInstances

### Description
Correlates a burst of IAM sensitive API calls with subsequent multi-region RunInstances attempts from the same access key ID - the exact pattern observed in IR-2018-001.

### SPL
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventSource IN ("iam.amazonaws.com", "ec2.amazonaws.com")
| bin _time span=30m
| eval phase = case(
    eventSource="iam.amazonaws.com" AND eventName IN ("GetCallerIdentity","ListAccessKeys","CreateAccessKey","DeleteAccessKey","CreateUser","GetSessionToken"), "reconnaissance",
    eventSource="ec2.amazonaws.com" AND eventName="RunInstances", "exploitation",
    true(), "other")
| stats dc(eventName) as api_count, values(eventName) as api_calls, values(awsRegion) as regions, values(errorCode) as errors, values(phase) as phases, values(userIdentity.accessKeyId) as keys_used by userIdentity.arn, _time
| search phases="reconnaissance" phases="exploitation"
```

**Note:** Group by `userIdentity.arn` rather than `accessKeyId` because STS tokens minted from a compromised key have a different `accessKeyId` than the original long-term key, but inherit the same ARN. This was observed in IR-2018-001 where IAM recon used `AKIAJOGCDXJ5NW5PXUPA` and RunInstances used `ASIAZB6TMXZ7LL6JBJQA`, both under `arn:aws:iam::622676721278:user/web_admin`.

### MITRE ATT&CK
- T1580 - Cloud Infrastructure Discovery (recon)
- T1078.004 - Valid Accounts: Cloud Accounts (exploitation)
- T1496 - Resource Hijacking (exploitation)

### Risk
Critical - demonstrates full attack chain from enumeration to resource hijacking.



## CS-003: S3 Public ACL > Cryptominer Delivery > DNS Resolution

### Description
Correlates an S3 bucket ACL change with subsequent cryptominer DNS resolutions from employee endpoints - the chain observed in IR-2018-002.

### SPL
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
| eval acl_time = _time
| table _time userIdentity.userName requestParameters.bucketName sourceIPAddress as acl_ip
| join type=outer
    [ search index="botsv3" sourcetype="stream:dns" (query="*coinhive*" OR query="*monero*")
      | eval dns_time = _time
      | table _time host query query_type answer
      | rename host as dns_host ]
| eval time_from_acl = dns_time - acl_time
| where time_from_acl >= 0 AND time_from_acl <= 3600
| sort acl_time
```

### MITRE ATT&CK
- T1530 - Data from Cloud Storage (ACL change)
- T1608 - Stage Capabilities (payload upload)
- T1189 - Drive-By Compromise (browser infection)
- T1496 - Resource Hijacking (mining)

### Risk
High - links infrastructure misconfiguration to endpoint compromise.



## CS-004: C2 Beaconing on Non-Standard Port > Large Data Transfer

### Description
Identifies hosts with persistent non-standard port beaconing followed by large outbound data transfers - indicating established C2 followed by data exfiltration or second-stage download.

### SPL
```spl
index="botsv3" sourcetype="stream:tcp" dest_port=9998
| bin _time span=30m
| stats sum(bytes_in) as total_bytes_in, sum(bytes_out) as total_bytes_out, dc(dest_ip) as c2_ips, values(dest_ip) as c2_ip_list, count as beacon_count by host, _time
| where beacon_count >= 3
| eval suspicious = case(
    total_bytes_out > 50000, "POSSIBLE EXFILTRATION",
    total_bytes_in > 1000000, "POSSIBLE SECOND STAGE",
    true(), "C2 BEACONING ONLY")
| table _time host beacon_count c2_ips c2_ip_list total_bytes_in total_bytes_out suspicious
```

### MITRE ATT&CK
- T1571 - Non-Standard Port (beaconing)
- T1041 - Exfiltration Over C2 Channel (large outbound)
- T1105 - Ingress Tool Transfer (large inbound)

### Risk
High - persistent C2 with large transfers indicates active post-exploitation.



## CS-005: AWS API Errors by Access Key - Privilege Escalation Attempts

### Description
Identifies access keys that generate a mix of AccessDenied and success errors across IAM and EC2 APIs - indicating an attacker probing permission boundaries (as seen in IR-2018-001 and IR-2026-0701-001).

### SPL
```spl
index="botsv3" sourcetype="aws:cloudtrail"
| stats count by userIdentity.accessKeyId, eventSource, eventName, errorCode
| stats values(eventName) as apis_called, values(errorCode) as error_codes, dc(eventName) as distinct_apis, count(eval(errorCode="AccessDenied")) as denied_count, count(eval(isnull(errorCode) OR errorCode="")) as success_count by userIdentity.accessKeyId
| where denied_count > 0 AND success_count > 0
| eval risk_score = distinct_apis * denied_count
| sort - risk_score
```

### MITRE ATT&CK
- T1078.004 - Valid Accounts
- T1580 - Cloud Infrastructure Discovery

### Risk
High - mixed success/denied API calls suggest credential abuse with permission probing.



## Correlation Search Summary

| ID | Name | Data Sources | Time Window | Risk |
|----|------|-------------|-------------|------|
| CS-001 | IMDS > Cloud API Abuse | stream:http, aws:cloudtrail | 15m | Critical |
| CS-002 | IAM Recon > RunInstances | aws:cloudtrail | 30m | Critical |
| CS-003 | S3 ACL > Cryptominer | aws:cloudtrail, stream:dns | 60m | High |
| CS-004 | C2 Beaconing > Large Transfer | stream:tcp | 30m | High |
| CS-005 | Mixed API Errors - Permission Probe | aws:cloudtrail | N/A | High |
