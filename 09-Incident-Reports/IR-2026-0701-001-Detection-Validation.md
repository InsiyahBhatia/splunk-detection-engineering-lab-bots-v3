# Incident Report: Attempted Multi-Region Resource Hijacking via Compromised AWS Credentials

**Author:** Insiyah Bhatia  
**Date:** 1/7/26  
**Classification:** TLP:AMBER  
**Case ID:** IR-2026-0701-001  
**Status:** Closed - Contained (Quota-Enforced)

## Executive Summary

On 2026-07-01 at ~14:46 UTC, a compromised AWS credential (`accessKeyId=ASIA...`) belonging to IAM user `web_admin` was used to attempt a large-scale, multi-region `RunInstances` sweep across **≥10 AWS regions** within a ~10-minute window. The attacker's goal was consistent with **resource hijacking for compute abuse (cryptomining / botnet infrastructure)**. All `RunInstances` calls failed authorization or quota checks - **no EC2 instances were successfully launched**. The attack was contained by existing EC2 instance-limit quotas (service quotas), not by detective controls.

**Root cause:** Compromise of `web_admin` long-term credentials (likely via phishing or credential leak; exact vector not conclusively identified). No evidence of role assumption chain compromise - the access key was used directly.

**Impact:** **Zero compute resources provisioned.** No data exfiltration, no persistence established, no lateral movement observed. Containment was effective but **passive** (quota exhaustion); no detective alert fired during the event.

## Timeline (UTC)

| Time (UTC) | Event | Source / Evidence |
|------------|-------|-------------------|
| 14:46:12 | First `RunInstances` call (`us-east-1`) - `Client.InstanceLimitExceeded` | CloudTrail `eventSource=ec2.amazonaws.com`, `eventName=RunInstances` |
| 14:46:15-14:54:03 | ≥10 distinct regions targeted (`us-east-1`, `us-west-2`, `eu-west-1`, `ap-southeast-1`, `ap-northeast-1`, `sa-east-1`, `ca-central-1`, `eu-central-1`, `ap-south-1`, `us-east-2`) | CloudTrail `awsRegion` field across events |
| 14:46:12-14:54:03 | All calls return `Client.InstanceLimitExceeded` or `Server.InsufficientInstanceCapacity` - **zero successful launches** | CloudTrail `errorCode` field |
| 14:55:02 | `GetCallerIdentity` call (reconnaissance) | CloudTrail `eventSource=iam.amazonaws.com` |
| 14:55:10 | `ListAccessKeys` for `web_admin` (credential enumeration) | CloudTrail |
| 14:56:00 | Last observed malicious API call | CloudTrail |
| 15:12:00 | SOC analyst alerted via manual CloudTrail review (no automated alert fired) | SOC ticket IR-2026-0701-001 |
| 15:30:00 | `web_admin` access key disabled, user marked compromised | IAM console / CLI |
| 15:45:00 | Root-cause investigation initiated; no role-assumption chain found | CloudTrail `AssumeRole` lookup (null results for this `accessKeyId` prior to 14:46) |
 | 16:30:00 | Incident closed - contained, no breach | IR closure note |

## Attack Pattern (MITRE ATT&CK Mapping)

| Tactic | Technique | Observation |
|--------|-----------|-------------|
| **Initial Access** | T1078.004 - Valid Accounts: Cloud Accounts | Compromised `web_admin` IAM user credentials used directly (no `AssumeRole` observed) |
| **Discovery** | T1087.003 - Account Discovery: Email/Account Discovery | `ListAccessKeys` on `web_admin` |
| **Discovery** | T1526 - Cloud Service Discovery | Multi-region `RunInstances` sweep (recon + action combined) |
| **Credential Access** | T1552.001 - Unsecured Credentials: Credentials In Files (hypothesized) | Likely vector; no conclusive evidence found |
| **Impact** | T1496 - Resource Hijacking | `RunInstances` sweep across ≥10 regions consistent with cryptomining / botnet provisioning |
 | **Impact** | T1580 - Cloud Infrastructure Discovery | Multi-region sweep doubles as capability mapping |

## Detection Logic (Sigma Rules Created)

Two Sigma rules were authored from this incident and placed in `03-Sigma/`:

1. **`aws_ec2_runinstances_multi_region_sweep.yml`** (ID: `9d2c7f4a-1e6b-4f3a-8b2d-5c9a7e1f4d6b`, **Critical**)  
   Detects the same `RunInstances sweep: same `accessKeyId` calling `RunInstances` across **≥5 distinct `awsRegion` values within 10 minutes**.

2. **`aws_iam_reconnaissance_burst.yml`** (ID: `7a3f1e2c-4b8d-4a1f-9c6e-2d5f8a1b3c9e`, **High**)  
   Detects IAM reconnaissance bursts: same `accessKeyId` making **≥4 distinct sensitive IAM calls** (`GetCallerIdentity`, `ListAccessKeys`, `CreateAccessKey`, `DeleteAccessKey`, `CreateUser`, `GetSessionToken`) within **1 minute**.

 Both rules include Splunk SPL equivalents for the BOTSv3 dataset (`index="botsv3" sourcetype="aws:cloudtrail"`).

## False Positive Considerations

| Rule | Expected False Positives | Mitigation |
|------|--------------------------|------------|
| Multi-region RunInstances | Legitimate IaC (Terraform, CloudFormation StackSets) deploying across regions; DR failover scripts | Allowlist known automation `accessKeyId`s / `userIdentity.arn`s; enrich with `userAgent` (e.g., `aws-sdk/`, `terraform/`) |
 | IAM Recon Burst | Credential-rotation lambdas; IAM auditing scripts; CI/CD pipelines provisioning IAM | Allowlist known automation roles; require `errorCode` absence (legitimate tooling usually succeeds) |

## Response Actions Taken

1. **Immediate containment:** Disabled `web_admin` access key (`ASIA...`) at 15:30 UTC.
2. **Credential rotation:** Generated new access key for `web_admin`; rotated any downstream consumers (CI/CD, external SaaS).
3. **Scope verification:** Queried CloudTrail for all activity by `accessKeyId=ASIA...` from 2026-06-24 to 2026-07-01 - **no prior suspicious activity**; first malicious call at 14:46:12.
4. **Quota audit:** Verified EC2 instance limits (service quotas) are intentionally low in non-production regions - this was the effective containment control.
 5. **No GuardDuty finding:** GuardDuty did not generate a finding for this activity (known gap - `RunInstances` with `InstanceLimitExceeded` is not a default GuardDuty finding type).

## Gaps & Recommendations

| Gap | Recommendation | Priority |
|-----|----------------|----------|
| **No real-time alert** on multi-region `RunInstances` sweep | Deploy Sigma rules above to SIEM (Splunk / Sentinel / OpenSearch); tune threshold to ≥5 regions / 10m | **Critical** |
| **No alert** on IAM reconnaissance burst | Deploy IAM recon rule; tune to ≥4 distinct sensitive calls / 1m | **High** |
| **Root cause of credential compromise unknown** | 1) Enforce MFA on `web_admin` (was not enforced). 2) Rotate all keys for `web_admin`. 3) Review GitHub/GitLab/Git history for accidental commits. 4) Check for phishing clicks via proxy logs. | **High** |
| **`web_admin` had `RunInstances` permission at all** | Apply least-privilege: remove `ec2:RunInstances` from `web_admin` if not required; use CI/CD role for provisioning | **High** |
| **GuardDuty coverage gap** | Enable GuardDuty EKS/Kubernetes and Malware Protection; create custom GuardDuty threat list for known cryptomining instance types / AMIs | **Medium** |
 | **No automated key-disable on anomaly** | Build SOAR playbook: on Sigma alert > auto-disable key > create ticket > notify owner | **Medium** |

## Lessons Learned

1. **Quotas ≠ Detection.** The attack was stopped by a service quota (`InstanceLimitExceeded`), not by a detective control. Quotas are a safety net, not a substitute for alerting.
2. **Error codes matter.** Initial hypothesis was "all `RunInstances` calls denied." Reality: some calls returned `Server.InsufficientInstanceCapacity` - meaning **authorization succeeded** and capacity was the only blocker. Always enumerate `errorCode` values.
3. **Credential compromise ≠ role compromise.** The attacker used the IAM user's long-term key directly. No `AssumeRole` chain was involved. Focus rotation on the compromised key, not the role trust policy.
 4. **Identity correlation > IP correlation.** The attacker's source IPs were diverse (multiple ASNs, likely VPN/proxy). Pivoting on `accessKeyId` was the only reliable way to link the activity.

## Artifacts & References

- **Sigma Rules:** `03-Sigma/aws_ec2_runinstances_multi_region_sweep.yml`, `03-Sigma/aws_iam_reconnaissance_burst.yml`
- **CloudTrail Query (Splunk SPL):** See SPL blocks in each Sigma rule file
- **BOTSv3 Reference:** `index="botsv3" sourcetype="aws:cloudtrail"` - used for rule development and testing
- **MITRE ATT&CK:** T1078.004, T1496, T1087.003, T1526, T1552.001, T1580
 - **Related Incidents:** None - this credential was not involved in prior IR-2026-0615 (S3 bucket exposure)

**Reviewed By:** _______________________
**Date:** _______________________