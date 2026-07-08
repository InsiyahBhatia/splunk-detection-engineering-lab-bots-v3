# Incident Report: EC2 Compromise & AWS Credential Abuse via IMDS
**Report ID:** IR-2018-001  
**Severity:** CRITICAL  
**Status:** Contained (Host Not Remediated)  
**Analyst:** Insiyah Bhatia  
**Date of Analysis:** 2026-07-02  
**Incident Date:** 2018-08-20  
**Dataset:** BOTS v3 - Splunk Boss of the SOC (index=botsv3)

## Executive Summary

On August 20, 2018, EC2 instance `mars.i-08e52f8b5a034012d` received a malicious payload (~11.7MB) from external IP `34.215.24.225` over non-standard port 9998. The malware subsequently queried the AWS Instance Metadata Service (IMDS) to steal temporary IAM credentials attached to the instance role. Using these credentials, the attacker minted an STS session token and conducted a systematic privilege escalation attempt followed by a multi-region EC2 resource hijacking sweep across 15 AWS regions (576 attempts). All resource provisioning attempts were blocked by IAM policy or AWS service quotas - no instances were successfully launched. Frothly's security team detected and revoked the stolen credentials within 14 minutes using `aws_ir`. However, the C2 channel on the compromised host remained active for at least 4 hours after credential revocation, indicating the underlying host compromise was not remediated within the dataset window.

## Timeline of Events

| Time (UTC) | Event | Source | MITRE Technique |
|---|---|---|---|
| 14:34:11 | Mars receives ~11.7MB payload from `34.215.24.225:9998` | stream:tcp | T1105 - Ingress Tool Transfer |
| 14:34:13 | 347KB sent back to C2 - initial check-in confirmed | stream:tcp | T1571 - Non-Standard Port |
| 14:40:23 | Malware queries IMDS `/latest/meta-data/iam/security-credentials/EC2InstanceRole` (HTTP 200) | stream:http | T1552.005 - Cloud Instance Metadata API |
| 14:46:12 | `GetSessionToken` called with AKIA key - STS token `ASIAZB6TMXZ7LL6JBJQA` minted | aws:cloudtrail | T1078.004 - Valid Accounts: Cloud |
| 14:46:12 | IAM enumeration burst: 6 API calls in <1 second (`GetCallerIdentity`, `GetSessionToken`, `ListAccessKeys`, `CreateAccessKey`, `DeleteAccessKey`, `CreateUser`) - all via Boto3 | aws:cloudtrail | T1580 - Cloud Infrastructure Discovery |
| 14:46:12 | `CreateUser` (my_db_user) and `CreateAccessKey` denied - persistence attempt blocked | aws:cloudtrail | T1136.003 - Create Account: Cloud |
| 14:47-14:57 | Multi-region `RunInstances` sweep - 576 attempts across 15 regions from 2 IPs | aws:cloudtrail | T1496 - Resource Hijacking |
| 15:00:53 | Frothly runs `aws_ir key-compromise --access-key-id AKIAJOGCDXJ5NW5PXUPA --plugins disableaccess_key` | osquery:results | - (IR Response) |
| 15:03:59 | `aws_ir` re-executed (confirmation retry) | osquery:results | - |
| 15:05:01 | `aws_ir` re-executed (confirmation retry) | osquery:results | - |
| 16:28:09 | C2 beacon to `34.215.24.225:9998` (74/54 bytes) - host still compromised | stream:tcp | T1571 |
| 16:33:38 | C2 beacon continues | stream:tcp | T1571 |
| 18:24:34 | Second large transfer - 2.9MB inbound, 59KB outbound (possible second stage) | stream:tcp | T1041 - Exfiltration Over C2 |

**Detection-to-containment time: 14 minutes** (credential revocation only; host not cleaned)

## Attack Chain

```
[External C2: 34.215.24.225:9998]
        |
        | 14:34 - 11.7MB payload delivered (non-standard port 9998)
        v
[EC2: mars.i-08e52f8b5a034012d]
        |
        | 14:40 - Malware queries IMDS
        | GET 169.254.169.254/latest/meta-data/iam/security-credentials/EC2InstanceRole
        | HTTP 200 > credentials returned
        v
[Stolen IAM Credentials: AKIAJOGCDXJ5NW5PXUPA (web_admin)]
        |
        | 14:46 - GetSessionToken > mints ASIA token
        |
        ├── IAM Enumeration (6 calls, 1 second, Boto3 scripted)
        |       CreateUser > AccessDenied
        |       CreateAccessKey > AccessDenied
        |       DeleteAccessKey > AccessDenied
        |
        └── Multi-region RunInstances sweep
                15 regions | 576 attempts | 2 source IPs
                Blocked by: IAM policy (most regions)
                            InstanceLimitExceeded (some regions) < EC2 permission PASSED
                            InsufficientInstanceCapacity (some regions) < EC2 permission PASSED
                Result: 0 instances launched
        
[Frothly IR - 15:00:53]
        aws_ir disables AKIA key on mars host
        C2 channel NOT terminated - beacons continue at 16:28, 16:33, 18:24
```

## Root Cause

**EC2 Instance Metadata Service (IMDS) Credential Theft**

The `mars.i-08e52f8b5a034012d` EC2 instance was compromised via malware delivered over TCP port 9998 from `34.215.24.225`. The malware queried the AWS IMDS endpoint at `169.254.169.254/latest/meta-data/iam/security-credentials/EC2InstanceRole` at 14:40:23 UTC, receiving HTTP 200 with temporary credentials for the `EC2InstanceRole` attached to the instance. These credentials (`AKIAJOGCDXJ5NW5PXUPA`) were then used to mint an STS session token and conduct downstream privilege escalation and resource hijacking attempts.

**How the host itself was initially compromised:** Unknown - no exploit or initial access event was found in available telemetry prior to the 14:34 payload delivery. This represents a **detection gap**: the initial vector (phishing, vulnerable service, prior compromise) was not captured in the dataset window.

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| IP | `34.215.24.225` | C2 server - payload delivery + beaconing |
| Port | `9998/TCP` | Non-standard C2 port |
| Host | `mars.i-08e52f8b5a034012d` | Compromised EC2 instance |
| IAM User | `web_admin` | Identity whose credentials were abused |
| Access Key | `AKIAJOGCDXJ5NW5PXUPA` | Long-term AKIA key - now revoked |
| STS Token | `ASIAZB6TMXZ7LL6JBJQA` | Temporary token minted from stolen key |
| Source IPs | `35.153.154.221`, `139.198.18.205` | IPs used during RunInstances sweep |
| User-Agent | `Boto3/1.7.44 Python/2.7.12 Linux/4.4.0-1063-aws Botocore/1.10.44` | Attacker tooling fingerprint |
 | Tool | `aws_ir` | Defender IR tool (not attacker - positive finding) |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | - | Unknown | Pre-dataset; not captured in telemetry |
| Command & Control | Non-Standard Port | T1571 | Port 9998 beaconing to 34.215.24.225 |
| Command & Control | Ingress Tool Transfer | T1105 | 11.7MB payload received at 14:34 |
| Credential Access | Unsecured Credentials: Cloud Instance Metadata API | **T1552.005** | IMDS query at 14:40:23, HTTP 200 |
| Discovery | Cloud Infrastructure Discovery | T1580 | IAM enumeration burst at 14:46:12 |
| Persistence | Create Account: Cloud Account | T1136.003 | CreateUser (my_db_user) - denied |
| Persistence | Account Manipulation: Additional Cloud Credentials | T1098.001 | CreateAccessKey attempt - denied |
| Privilege Escalation | Valid Accounts: Cloud Accounts | T1078.004 | STS token minted, used across 15 regions |
| Impact | Resource Hijacking | T1496 | 576 RunInstances attempts - 0 successful |
 | Exfiltration | Exfiltration Over C2 Channel | T1041 | 2.9MB second transfer at 18:24 |

## Controls Assessment

### Controls That Worked ✓
- **IAM least-privilege policy** - blocked `CreateUser`, `CreateAccessKey`, `DeleteAccessKey` attempts on `web_admin`
- **EC2 instance quotas** - prevented mass instance provisioning in quota-limited regions
- **osquery process monitoring** - captured `aws_ir` execution and exposed attacker key ID in process telemetry
- **Rapid IR response** - `aws_ir` invoked within 14 minutes of credential abuse detection

### Controls That Failed or Were Missing ✗
- **IMDSv1 in use** - IMDSv2 (session-oriented, PUT-then-GET) would have prevented unauthenticated IMDS queries from malware
- **Overpermissive EC2 instance role** - `EC2InstanceRole` had sufficient permissions to call `GetSessionToken` and attempt `RunInstances`; should be scoped to minimum required permissions
- **No host-level isolation** - C2 channel remained active for 4+ hours after credential revocation; the host was not quarantined
- **No network egress filtering** - outbound connection to `34.215.24.225:9998` was not blocked by perimeter controls
 - **CloudTrail gap** - `web_admin` IAM user creation (2018-08-19) has no corresponding CloudTrail `CreateUser` event; credential issuance was not audited

## Evidence Gaps

| Gap | Impact |
|---|---|
| Initial host compromise vector unknown | Cannot determine patient zero or full blast radius |
| `web_admin` account creation not in CloudTrail | Credential issuance timeline incomplete |
| `34.215.24.225` ownership unconfirmed | Threat actor attribution not possible from available data |
 | Second large transfer at 18:24 (2.9MB) - content unknown | Cannot confirm exfiltration vs. second stage payload |

## Recommendations

### Immediate (P0)
1. **Enforce IMDSv2** on all EC2 instances - blocks IMDS credential harvesting by requiring session tokens
2. **Isolate and reimage `mars.i-08e52f8b5a034012d`** - C2 channel active 4 hours post-containment means the host is still compromised
3. **Block `34.215.24.225`** at perimeter firewall and all security group egress rules

### Short-term (P1)
4. **Scope EC2 instance roles to least privilege** - `EC2InstanceRole` should not have `sts:GetSessionToken` or `ec2:RunInstances` unless explicitly required
5. **Enable CloudTrail in all regions with log file validation** - 15-region sweep went partially undetected due to regional logging gaps
6. **Deploy VPC Flow Log alerting on IMDS access** - any process querying `169.254.169.254` outside of expected application paths should alert

### Long-term (P2)
7. **Deploy network egress filtering** - outbound connections on non-standard ports (9998) should require explicit allow-listing
8. **Secrets scanning on EC2 instances** - periodic osquery `process_envs` and file scans for AWS key patterns
 9. **AWS GuardDuty** - would have detected `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` automatically

## Queries Used (SPL Reference)

```spl
-- Find AKIA key
index="botsv3" sourcetype="aws:cloudtrail" userIdentity.userName="web_admin" userIdentity.accessKeyId="AKIA*" | table _time eventName userIdentity.accessKeyId sourceIPAddress | sort _time

-- Confirm IMDS query
index="botsv3" host="mars.i-08e52f8b5a034012d" sourcetype="stream:http" earliest="08/20/2018:00:00:00" latest="08/20/2018:14:46:12" | table _time src_ip dest_ip dest_port uri_path http_method status

-- C2 traffic on port 9998
index="botsv3" host="mars.i-08e52f8b5a034012d" dest_ip="34.215.24.225" dest_port=9998 | table _time sourcetype bytes_in bytes_out

-- Full blast radius of STS token
index="botsv3" "ASIAZB6TMXZ7LL6JBJQA" | stats dc(awsRegion) as regions_touched, dc(sourceIPAddress) as ips_used, count(eval(eventName="RunInstances")) as runinstances_attempts, values(errorCode) as outcomes

-- IR response confirmation
index="botsv3" sourcetype="osquery:results" "AKIAJOGCDXJ5NW5PXUPA" | table _time host name columns.cmdline
```

*Report generated from hands-on investigation of BOTS v3 dataset. All findings verified against raw telemetry - no claims made without supporting query evidence.*