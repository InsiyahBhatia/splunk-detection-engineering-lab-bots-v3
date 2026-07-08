# Consolidated Indicators of Compromise (IOCs)
**Campaign:** Frothly BOTSv3 Incident Series (August 20, 2018)  
**Analyst:** Insiyah Bhatia  
**Date Compiled:** 2026-07-02  
**Source Incidents:** IR-2018-001, IR-2018-002, IR-2026-0701-001  
**Classification:** TLP:AMBER



## Network Indicators

| Type | Value | Context | Incident | Confidence |
|------|-------|---------|----------|------------|
| IPv4 | `34.215.24.225` | C2 server - payload delivery, beaconing, exfiltration | IR-2018-001 | High |
| TCP Port | `9998` | Non-standard C2 port used for all mars host communications | IR-2018-001 | High |
| IPv4 | `54.67.127.227` | brewertalk.com web server - forum delivering Coinhive miner | IR-2018-002 | High |
| IPv4 | `35.153.154.221` | Source IP for RunInstances sweep (recon phase) | IR-2018-001 / IR-2026-0701-001 | High |
| IPv4 | `139.198.18.205` | Source IP for RunInstances sweep (hijack phase) | IR-2018-001 / IR-2026-0701-001 | High |
| IPv4 | `107.77.212.175` | bstoll's IP - source of both PutBucketAcl calls (accidental) | IR-2018-002 | High |



## Domain Indicators

| Type | Value | Context | Incident | Confidence |
|------|-------|---------|----------|------------|
| Domain | `coinhive.com` | Monero browser mining service (defunct 2019) | IR-2018-002 | High |
| Domain | `ws001.coinhive.com` | Coinhive WebSocket mining pool endpoint | IR-2018-002 | High |
| Domain | `ws005.coinhive.com` | Coinhive WebSocket mining pool endpoint | IR-2018-002 | High |
| Domain | `ws011.coinhive.com` | Coinhive WebSocket mining pool endpoint | IR-2018-002 | High |
| Domain | `ws014.coinhive.com` | Coinhive WebSocket mining pool endpoint | IR-2018-002 | High |
| Domain | `brewertalk.com` | Frothly beer community forum (54.67.127.227) - miner delivery vector | IR-2018-002 | High |



## Host & Identity Indicators

| Type | Value | Context | Incident | Confidence |
|------|-------|---------|----------|------------|
| EC2 Instance ID | `i-08e52f8b5a034012d` | Compromised host `mars` - initial malware delivery target | IR-2018-001 | High |
| Hostname | `mars` | EC2 instance name (via instance ID correlation) | IR-2018-001 | High |
| Hostname | `BSTOLL-L` | Employee endpoint (bstoll) - browsed brewertalk.com, resolved Coinhive domains | IR-2018-002 | High |
| Hostname | `MKRAEUS-L` | Employee endpoint (mkraeus) - resolved Coinhive domains | IR-2018-002 | High |
| Hostname | `BTUN-L` | Employee endpoint (BillyTun) - Symantec blocked JSCoinminer | IR-2018-002 | High |
| IAM User | `web_admin` | Identity whose credentials were abused (long-term AKIA + STS token) | IR-2018-001 / IR-2026-0701-001 | High |
| IAM User | `bstoll` | Employee who accidentally misconfigured S3 bucket ACL | IR-2018-002 | High |
| IAM User | `mkraeus` | Employee associated with MKRAEUS-L endpoint | IR-2018-002 | Medium |
| IAM User | `BillyTun` | User logged into BTUN-L when miner blocked | IR-2018-002 | Medium |



## Credential & Token Indicators

| Type | Value | Context | Incident | Confidence |
|------|-------|---------|----------|------------|
| Access Key ID (AKIA) | `AKIAJOGCDXJ5NW5PXUPA` | Long-term IAM key for web_admin - stolen via IMDS, revoked at 15:00:53 | IR-2018-001 | High |
| Access Key ID (ASIA) | `ASIAZB6TMXZ7LL6JBJQA` | STS temporary session token minted from stolen AKIA - used for all downstream abuse | IR-2018-001 / IR-2026-0701-001 | High |
| IAM Role | `EC2InstanceRole` | Instance profile attached to mars - source of stolen IMDS credentials | IR-2018-001 | High |



## File & Payload Indicators

| Type | Value | Context | Incident | Confidence |
|------|-------|---------|----------|------------|
| Payload Size | `~11.7 MB` | Initial malicious payload delivered to mars at 14:34:11 | IR-2018-001 | High |
| Payload Size | `347 KB` | Initial C2 check-in response from mars at 14:34:13 | IR-2018-001 | High |
| Payload Size | `2.9 MB inbound / 59 KB outbound` | Second large transfer at 18:24:34 - possible second stage/exfil | IR-2018-001 | Medium |
| S3 Bucket | `frothlywebcode` | Publicly writable for 56 min; hosted Coinhive JS payload | IR-2018-002 | High |
| Filename Pattern | `*.js` (Coinhive miner) | Malicious JavaScript uploaded to frothlywebcode - exact filename unknown (S3 access log parsing gap) | IR-2018-002 | Medium |



## Tooling & Behavioral Indicators

| Type | Value | Context | Incident | Confidence |
|------|-------|---------|----------|------------|
| User-Agent | `Boto3/1.7.44 Python/2.7.12 Linux/4.4.0-1063-aws Botocore/1.10.44` | Attacker tooling fingerprint (recon phase) | IR-2018-001 | High |
| User-Agent | `Boto3/1.7.42 Python/2.7.12 Linux/4.4.0-131-generic Botocore/1.10.42` | Attacker tooling fingerprint (RunInstances sweep phase) - distinct host | IR-2018-001 | High |
| Tool | `aws_ir` | Defender IR tool - `aws_ir key-compromise --access-key-id AKIAJOGCDXJ5NW5PXUPA --plugins disableaccess_key` executed at 15:00:53, 15:03:59, 15:05:01 | IR-2018-001 | High (defender) |
| AV Signature | `JSCoinminer Download 6` (SID 30356) | Symantec EP detection on BTUN-L at 19:12:22 | IR-2018-002 | High |
| AV Signature | `JSCoinminer Download 8` (SID 30358) | Symantec EP detection on BTUN-L at 19:13:24 | IR-2018-002 | High |



## MITRE ATT&CK Technique Summary by Incident

| Technique ID | Technique Name | IR-2018-001 | IR-2018-002 | IR-2026-0701-001 |
|--------------|----------------|-------------|-------------|------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | ✓ | | ✓ |
| T1105 | Ingress Tool Transfer | ✓ | | |
| T1571 | Non-Standard Port | ✓ | | |
| T1552.005 | Cloud Instance Metadata API | ✓ | | |
| T1580 | Cloud Infrastructure Discovery | ✓ | | ✓ |
| T1136.003 | Create Account: Cloud Account | ✓ | | |
| T1098.001 | Additional Cloud Credentials | ✓ | | |
| T1070 | Indicator Removal | ✓ | | |
| T1496 | Resource Hijacking | ✓ | ✓ | ✓ |
| T1041 | Exfiltration Over C2 Channel | ✓ | | |
| T1189 | Drive-By Compromise | | ✓ | |
| T1608 | Stage Capabilities | | ✓ | |
| T1530 | Data from Cloud Storage | | ✓ | |
| T1087.003 | Account Discovery | | | ✓ |
| T1526 | Cloud Service Discovery | | | ✓ |
| T1552.001 | Credentials In Files | | | ✓ |



## Detection Rules Referenced

| Rule File | Rule ID | Technique Coverage |
|-----------|---------|-------------------|
| `03-Sigma/aws_ec2_runinstances_multi_region_sweep.yml` | `9d2c7f4a-1e6b-4f3a-8b2d-5c9a7e1f4d6b` | T1496, T1526 |
| `03-Sigma/aws_iam_reconnaissance_burst.yml` | `7a3f1e2c-4b8d-4a1f-9c6e-2d5f8a1b3c9e` | T1580, T1087.003 |
| `04-YARA/yara-coinhive-miner.yar` | - | T1496 (Coinhive JS) |
| `05-Snort/snort-c2-port9998.rules` | - | T1571, T1105 |
| `06-Zeek/zeek-c2-beacon-detection.zeek` | - | T1571 |
| `06-Zeek/zeek-imds-credential-theft.zeek` | - | T1552.005 |



## Evidence Gaps (Consolidated)

| Gap | Incident | Impact |
|-----|----------|--------|
| Initial host compromise vector for `mars` unknown | IR-2018-001 | Cannot determine patient zero or full blast radius |
| `web_admin` account creation not in CloudTrail | IR-2018-001 | Credential issuance timeline incomplete |
| `34.215.24.225` ownership unconfirmed | IR-2018-001 | Threat actor attribution not possible |
| 18:24 transfer content unknown (exfil vs. second stage) | IR-2018-001 | Cannot confirm data loss |
| S3 access logs `bucket_name` field not parseable | IR-2018-002 | Cannot confirm payload filename, upload size, attacker IP |
| How attacker discovered open S3 bucket unknown | IR-2018-002 | Attribution and scanner campaign unclear |
| BSTOLL-L / MKRAEUS-L miner containment status unconfirmed | IR-2018-002 | Unknown if mining continued post-bucket closure |
| brewertalk.com server-side logs not in dataset | IR-2018-002 | Cannot confirm script injection method |
| Root cause of `web_admin` credential compromise unknown | IR-2026-0701-001 | Phishing vs. leak vs. other vector undetermined |



## Recommended Blocking / Hunting Actions

### Immediate Blocks (P0)
- **IP:** `34.215.24.225` - all egress at perimeter and SG level
- **Port:** `9998/TCP` - deny outbound except approved exceptions
- **Domains:** `coinhive.com`, `ws001.coinhive.com`, `ws005.coinhive.com`, `ws011.coinhive.com`, `ws014.coinhive.com` - DNS sinkhole
- **Credentials:** `AKIAJOGCDXJ5NW5PXUPA` (revoked), `ASIAZB6TMXZ7LL6JBJQA` (expired) - add to deny lists

### Hunting Queries (Splunk SPL)

```spl
-- Hunt for IMDS credential theft (IR-2018-001 pattern)
index="botsv3" sourcetype="stream:http" dest_ip="169.254.169.254" uri_path="*iam/security-credentials*"
| table _time host src_ip dest_ip uri_path http_method status

-- Hunt for multi-region RunInstances sweep (IR-2018-001 / IR-2026-0701-001)
index="botsv3" sourcetype="aws:cloudtrail" eventSource="ec2.amazonaws.com" eventName="RunInstances"
| bin _time span=10m
| stats dc(awsRegion) as regions, count as attempts, values(errorCode) as errors, values(sourceIPAddress) as ips by userIdentity.accessKeyId, _time
| where regions >= 5

-- Hunt for IAM reconnaissance burst (IR-2018-001 / IR-2026-0701-001)
index="botsv3" sourcetype="aws:cloudtrail" eventSource="iam.amazonaws.com"
  eventName IN ("GetCallerIdentity","ListAccessKeys","CreateAccessKey","DeleteAccessKey","CreateUser","GetSessionToken")
| bin _time span=1m
| stats dc(eventName) as distinct_calls, values(eventName) as actions, values(errorCode) as outcomes by userIdentity.accessKeyId, _time
| where distinct_calls >= 4

-- Hunt for Coinhive DNS resolutions (IR-2018-002)
index="botsv3" sourcetype="stream:dns" (query="*coinhive*" OR query="*monero*")
| table _time host query

-- Hunt for S3 public ACL changes (IR-2018-002)
index="botsv3" sourcetype="aws:cloudtrail" eventName=PutBucketAcl
| table _time userIdentity.userName requestParameters.bucketName requestParameters.AccessControlPolicy sourceIPAddress
```

*All IOCs extracted from raw BOTSv3 telemetry via Splunk queries documented in each incident report. No third-party intel feeds used. Confidence ratings: High = directly observed in dataset; Medium = inferred from correlated events.*