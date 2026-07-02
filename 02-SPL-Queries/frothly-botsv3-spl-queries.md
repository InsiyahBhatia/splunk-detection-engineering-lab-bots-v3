# Splunk SPL Queries - Frothly BOTSv3 Investigation
**Author:** Insiyah Bhatia  
**Date:** 2026-07-02  
**Dataset:** index=botsv3  
**Purpose:** Standalone queries used during IR-2018-001, IR-2018-002, and IR-2026-0701-001 analysis

---

## 1. Initial Triage & Identity Discovery

### 1.1 Find the AKIA Key Used
```spl
index="botsv3" sourcetype="aws:cloudtrail" userIdentity.userName="web_admin"
  userIdentity.accessKeyId="AKIA*"
| table _time eventName userIdentity.accessKeyId sourceIPAddress
| sort _time
```

### 1.2 IAM User Activity Summary
```spl
index="botsv3" sourcetype="aws:cloudtrail" userIdentity.userName="web_admin"
| stats count by eventName, eventSource, errorCode
| sort - count
```

### 1.3 All Activity by Compromised STS Token (ASIA)
```spl
index="botsv3" "ASIAZB6TMXZ7LL6JBJQA"
| stats dc(awsRegion) as regions_touched,
         dc(sourceIPAddress) as ips_used,
         count(eval(eventName="RunInstances")) as runinstances_attempts,
         values(errorCode) as outcomes,
         values(eventName) as api_calls,
         values(sourceIPAddress) as src_ips
```

### 1.4 Confirm IMDS Query
```spl
index="botsv3" host="mars.i-08e52f8b5a034012d" sourcetype="stream:http"
  earliest="08/20/2018:00:00:00" latest="08/20/2018:14:46:12"
| table _time src_ip dest_ip dest_port uri_path http_method status
```

---

## 2. CloudTrail - EC2

### 2.1 Multi-Region RunInstances Sweep
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventSource="ec2.amazonaws.com"
  eventName="RunInstances"
| bin _time span=10m
| stats dc(awsRegion) as distinct_regions, count as attempts,
         values(errorCode) as outcomes, values(sourceIPAddress) as source_ips,
         values(awsRegion) as regions, values(instanceType) as instance_types
         by userIdentity.accessKeyId, _time
| where distinct_regions >= 5
```

### 2.2 RunInstances Error Code Distribution
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventSource="ec2.amazonaws.com"
  eventName="RunInstances"
| stats count by errorCode
| sort - count
```

### 2.3 RunInstances by Region
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventSource="ec2.amazonaws.com"
  eventName="RunInstances"
| stats count by awsRegion
| sort - count
```

### 2.4 RunInstances Source IPs
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventSource="ec2.amazonaws.com"
  eventName="RunInstances"
| stats count by sourceIPAddress, userAgent, awsRegion
| sort - count
```

### 2.5 RunInstances with Instance Types
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventSource="ec2.amazonaws.com"
  eventName="RunInstances"
| spath requestParameters
| stats count by requestParameters{}.instanceType, awsRegion, errorCode
| sort - count
```

---

## 3. CloudTrail - IAM

### 3.1 IAM Sensitive API Burst Detection
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
```

### 3.2 All IAM Errors by User
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventSource="iam.amazonaws.com"
  errorCode="AccessDenied"
| stats count by userIdentity.userName, eventName, sourceIPAddress
| sort - count
```

### 3.3 IAM Event Timeline
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventSource="iam.amazonaws.com"
  userIdentity.userName="web_admin"
| table _time eventName errorCode sourceIPAddress userAgent
| sort _time
```

---

## 4. CloudTrail - S3

### 4.1 S3 PutBucketAcl Events
```spl
index="botsv3" sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
| table _time userIdentity.userName requestParameters.bucketName
         requestParameters.AccessControlPolicy sourceIPAddress
| sort _time
```

### 4.2 S3 Bucket Activity Summary
```spl
index="botsv3" sourcetype="aws:cloudtrail"
  requestParameters.bucketName="frothlywebcode"
| stats count by eventName, userIdentity.userName, errorCode
| sort - count
```

### 4.3 S3 Access Logs (If Available)
```spl
index="botsv3" sourcetype="aws:s3:accesslogs"
  bucket="frothlywebcode"
| table _time requester operation key remote_ip http_status bytes_sent
```

---

## 5. Network - C2 Beaconing

### 5.1 All Traffic on Port 9998
```spl
index="botsv3" dest_port=9998
| table _time host src_ip dest_ip dest_port bytes_in bytes_out
| sort _time
```

### 5.2 Mars Host Traffic Summary
```spl
index="botsv3" host="mars.i-08e52f8b5a034012d"
| eval type = case(
    sourcetype="stream:tcp", "TCP",
    sourcetype="stream:http", "HTTP",
    sourcetype="stream:dns", "DNS",
    sourcetype="aws:cloudtrail", "CloudTrail",
    true(), sourcetype)
| stats count by type, dest_ip, dest_port
| sort - count
```

### 5.3 C2 Beacon Frequency
```spl
index="botsv3" host="mars.i-08e52f8b5a034012d" dest_ip="34.215.24.225"
  dest_port=9998
| bin _time span=5m
| stats count as beacon_count, sum(bytes_in) as total_in,
         sum(bytes_out) as total_out
| where beacon_count > 0
```

---

## 6. Network - DNS

### 6.1 Cryptominer Domain Queries
```spl
index="botsv3" sourcetype="stream:dns"
  (query="*coinhive*" OR query="*monero*" OR query="*cryptoloot*"
   OR query="*minr*" OR query="*webmine*")
| table _time host query query_type answer
| sort _time
```

### 6.2 All Coinhive Subdomain Resolutions
```spl
index="botsv3" sourcetype="stream:dns" query="*coinhive*"
| stats count by query, answer, host
| sort - count
```

---

## 7. Endpoint - Symantec EP

### 7.1 All Cryptominer AV Detections
```spl
index="botsv3" sourcetype="symantec:ep:security:file"
  signature="*coinminer*"
| table _time host user_name file_path signature_name signature_id
| sort _time
```

### 7.2 BTUN-L Detection Details (IR-2018-002)
```spl
index="botsv3" host="BTUN-L" sourcetype="symantec:ep:security:file"
  earliest="08/20/2018:19:00:00" latest="08/20/2018:19:30:00"
| table _time user_name file_path signature_name signature_id
```

### 7.3 All Symantec Detections Summary
```spl
index="botsv3" sourcetype="symantec:ep:security:file"
| stats count by host, signature_name
| sort - count
```

---

## 8. Endpoint - HTTP Browsing

### 8.1 BSTOLL-L Forum Visit (IR-2018-002)
```spl
index="botsv3" host="BSTOLL-L" sourcetype="stream:http"
  earliest="08/20/2018:18:31:00" latest="08/20/2018:19:10:00"
| table _time dest_ip uri_path status bytes_in
| search uri_path!="/pkiops*" uri_path!="/MF*"
```

### 8.2 All HTTP Traffic to brewertalk.com
```spl
index="botsv3" sourcetype="stream:http" dest_ip="54.67.127.227"
| stats count by host, uri_path, status
| sort - count
```

---

## 9. OSQuery - IR Response

### 9.1 aws_ir Execution Evidence
```spl
index="botsv3" sourcetype="osquery:results" "AKIAJOGCDXJ5NW5PXUPA"
| table _time host name columns.cmdline columns.pid
```

### 9.2 All osquery Process Events on Mars
```spl
index="botsv3" host="mars.i-08e52f8b5a034012d" sourcetype="osquery:results"
| table _time name columns.cmdline columns.pid columns.parent
| sort _time
```

---

## 10. Cross-Data-Source Correlations

### 10.1 Timeline - All Incident Activity in One View
```spl
index="botsv3"
  (sourcetype="aws:cloudtrail" eventName IN
    ("RunInstances","PutBucketAcl","GetSessionToken","GetCallerIdentity",
     "ListAccessKeys","CreateAccessKey","CreateUser")) OR
  (sourcetype="stream:tcp" dest_port=9998) OR
  (sourcetype="stream:dns" query="*coinhive*") OR
  (sourcetype="stream:http" dest_ip="169.254.169.254") OR
  (sourcetype="osquery:results" columns.cmdline="*aws_ir*") OR
  (sourcetype="symantec:ep:security:file" signature="*coinminer*")
| eval category = case(
    eventName="RunInstances", "EC2 Sweep",
    eventName="PutBucketAcl", "S3 ACL Change",
    eventName IN ("GetCallerIdentity","ListAccessKeys","CreateAccessKey",
                  "DeleteAccessKey","CreateUser","GetSessionToken"), "IAM",
    sourcetype="stream:tcp" AND dest_port=9998, "C2",
    sourcetype="stream:dns" AND (query="*coinhive*" OR query="*monero*"), "Miner",
    sourcetype="stream:http" AND dest_ip="169.254.169.254", "IMDS",
    sourcetype="osquery:results" AND columns.cmdline="*aws_ir*", "IR",
    sourcetype="symantec:ep:security:file" AND signature="*coinminer*", "AV",
    true(), "Other")
| timechart count by category span=15m
```

### 10.2 Infected Endpoints - All Indicators
```spl
index="botsv3"
  (sourcetype="stream:dns" query="*coinhive*") OR
  (sourcetype="symantec:ep:security:file" signature="*coinminer*") OR
  (sourcetype="stream:tcp" dest_port=9998)
| eval indicator = case(
    sourcetype="stream:dns", "Miner DNS",
    sourcetype="symantec:ep:security:file", "AV Block",
    sourcetype="stream:tcp" AND dest_port=9998, "C2 Traffic",
    true(), "Other")
| stats dc(indicator) as indicator_types,
         values(indicator) as indicators,
         count as total_events
         by host
| where indicator_types >= 1
```

### 10.3 All Suspicious CloudTrail Activity
```spl
index="botsv3" sourcetype="aws:cloudtrail"
  (eventName="RunInstances" OR eventName="PutBucketAcl" OR
   eventName IN ("GetCallerIdentity","CreateAccessKey","DeleteAccessKey",
                 "CreateUser","ListAccessKeys","GetSessionToken"))
| eval category = case(
    eventName="RunInstances", "Resource Hijacking",
    eventName="PutBucketAcl", "S3 Misconfig",
    match(eventName,"GetCallerIdentity|ListAccessKeys|GetSessionToken"), "Recon",
    match(eventName,"CreateAccessKey|DeleteAccessKey|CreateUser"), "Persistence",
    true(), "Other")
| stats count by category, userIdentity.userName, eventName, errorCode,
               sourceIPAddress, awsRegion
| sort - count
```

---

## Query Reference

| # | Query Name | Report | Data Source | MITRE |
|---|-----------|--------|-------------|-------|
| 1.1 | AKIA Key Discovery | IR-2018-001 | aws:cloudtrail | - |
| 2.1 | Multi-Region Sweep | IR-2018-001 / IR-2026-0701-001 | aws:cloudtrail | T1496, T1526 |
| 3.1 | IAM Recon Burst | IR-2018-001 | aws:cloudtrail | T1580 |
| 4.1 | S3 ACL Changes | IR-2018-002 | aws:cloudtrail | T1530 |
| 5.1 | Port 9998 Traffic | IR-2018-001 | stream:tcp | T1571 |
| 6.1 | Miner DNS | IR-2018-002 | stream:dns | T1496 |
| 7.1 | AV Detections | IR-2018-002 | symantec:ep | T1496 |
| 8.1 | Forum Visit | IR-2018-002 | stream:http | T1189 |
| 9.1 | IR Tooling | IR-2018-001 | osquery:results | - |
| 10.1 | Master Timeline | All | All | All |
