# Incident Report: S3 Misconfiguration & Drive-By Cryptominer Injection
**Report ID:** IR-2018-002  
**Severity:** HIGH  
**Status:** Partially Contained (Miner blocked; S3 remediated; root cause of forum compromise unknown)  
**Analyst:** Insiyah  
**Date of Analysis:** 2026-07-02  
**Incident Date:** 2018-08-20  
**Dataset:** BOTS v3 - Splunk Boss of the SOC (index=botsv3)

## Executive Summary

On August 20, 2018, Frothly employee `bstoll` accidentally misconfigured the AWS S3 bucket `frothlywebcode`, making it publicly writable for approximately 56 minutes (18:31-19:27 UTC). During this window, an attacker uploaded a malicious JavaScript Coinhive cryptominer payload to the bucket. The miner was subsequently delivered via `brewertalk.com` (Frothly's beer community forum, hosted at `54.67.127.227`) to visiting employees. At least three endpoints - `BSTOLL-L` (bstoll), `MKRAEUS-L` (mkraeus), and `BTUN-L` (BillyTun) - resolved Coinhive mining infrastructure domains. Symantec Endpoint Protection detected and blocked the miner on `BTUN-L`, identifying the threat as `JSCoinminer Download 6/8`. The bucket ACL was corrected by `bstoll` at 19:27 UTC, 56 minutes after the initial misconfiguration. S3 upload logs confirming the exact payload filename are unavailable due to a field parsing limitation in the dataset.

## Timeline of Events

| Time (UTC) | Event | Source | MITRE Technique |
|---|---|---|---|
| 18:31:46 | `bstoll` calls `PutBucketAcl` on `frothlywebcode` - bucket made publicly accessible | aws:cloudtrail | T1530 - Data from Cloud Storage |
| 18:31-19:27 | **56-minute exposure window** - bucket publicly writable | aws:cloudtrail | - |
| ~18:35-18:45 | Attacker uploads Coinhive JS payload to `frothlywebcode` S3 bucket | aws:s3:accesslogs (field gap) | T1608 - Stage Capabilities |
| 18:48:25 | `BSTOLL-L` (bstoll) browses `brewertalk.com` via Chrome - hits `/index.php`, `/forumdisplay.php`, `/showthread.php` from `54.67.127.227` | stream:http | T1189 - Drive-By Compromise |
| 18:57:47 | `MKRAEUS-L` resolves Coinhive mining domains via DNS | stream:dns | T1496 - Resource Hijacking |
| 19:08:19 | `BSTOLL-L` resolves `coinhive.com`, `ws001/005/011/014.coinhive.com` - miner active | stream:dns | T1496 - Resource Hijacking |
| 19:09:20 | `BSTOLL-L` continues resolving Coinhive WebSocket mining pool endpoints | stream:dns | T1496 |
| 19:12:22 | Symantec EP detects miner on `BTUN-L` - `JSCoinminer Download 6` blocked (SID 30356) | symantec:ep:security:file | T1496 |
| 19:13:24 | Symantec blocks `JSCoinminer Download 8` on `BTUN-L` (SID 30358) | symantec:ep:security:file | - |
| 19:13-19:14 | Additional Symantec blocks across detection window (46 total events) | symantec:ep:security:file | - |
| 19:27:54 | `bstoll` calls `PutBucketAcl` again - bucket ACL corrected, exposure ends | aws:cloudtrail | - (Remediation) |

**Exposure window: 56 minutes**  
**Endpoints with confirmed miner activity: 3** (BSTOLL-L, MKRAEUS-L, BTUN-L)  
 **Miner blocked by SEP on: BTUN-L confirmed; BSTOLL-L and MKRAEUS-L status unconfirmed**

## Attack Chain

```
[bstoll - accidental misconfiguration]
        |
        | 18:31:46 - PutBucketAcl on frothlywebcode
        | Bucket becomes publicly writable
        v
[Attacker - unknown origin]
        |
        | ~18:35 - uploads Coinhive JS payload
        | to frothlywebcode S3 bucket
        v
[brewertalk.com - 54.67.127.227]
        |
        | Forum page serving injected Coinhive script
        | from frothlywebcode S3 bucket
        v
[Employee Endpoints - drive-by via Chrome]
        |
        ├── BSTOLL-L (bstoll) - 18:48 browsing brewertalk
        |       > DNS: coinhive.com, ws001/005/011/014.coinhive.com @ 19:08
        |
        ├── MKRAEUS-L (mkraeus) - DNS: coinhive.com @ 18:57
        |
        └── BTUN-L (BillyTun) - 
                > Symantec BLOCKED JSCoinminer Download 6/8
                > Intrusion URL: brewertalk.com/forumdisplay.php?fid=8
                > Application: CHROME.EXE
                > Remote: 54.67.127.227

[bstoll - manual remediation]
        |
        | 19:27:54 - PutBucketAcl corrects bucket permissions
        | Exposure window closed
```

## Root Cause

**AWS S3 Bucket Misconfiguration by Privileged User**

IAM user `bstoll` (source IP `107.77.212.175`) called `PutBucketAcl` on S3 bucket `frothlywebcode` at 18:31:46 UTC, inadvertently granting public write access. The misconfiguration was self-remediated by the same user 56 minutes later at 19:27:54 UTC. No evidence of malicious intent by `bstoll` - this appears to be an accidental permission change, consistent with a misconfigured CLI command or console operation.

The attacker who exploited the open bucket and how they were monitoring for exposed S3 buckets (e.g., automated scanner, prior knowledge) is unknown from available telemetry.

**How the forum was connected:** `brewertalk.com` (54.67.127.227) appears to serve content sourced from the `frothlywebcode` S3 bucket. The injected miner script was delivered via forum pages, indicating the attacker embedded a script tag pointing to the malicious S3 object within the forum's HTML. Whether the attacker also had direct write access to the forum server is unconfirmed.

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| AWS User | `bstoll` | Misconfigured S3 bucket ACL (accidental) |
| S3 Bucket | `frothlywebcode` | Exposed bucket - public write for 56 min |
| Source IP | `107.77.212.175` | bstoll's IP for both PutBucketAcl calls |
| Web Server | `54.67.127.227` | brewertalk.com - forum delivering miner |
| Domain | `coinhive.com` | Monero browser mining service (now defunct) |
| Domains | `ws001/005/011/014.coinhive.com` | Coinhive WebSocket mining pool endpoints |
| Threat Name | `JSCoinminer Download 6` (SID 30356) | Symantec EP signature |
| Threat Name | `JSCoinminer Download 8` (SID 30358) | Symantec EP signature |
| Infected Hosts | `BSTOLL-L`, `MKRAEUS-L`, `BTUN-L` | Endpoints resolving Coinhive domains |
 | User | `BillyTun` | User on BTUN-L when miner was blocked |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Drive-By Compromise | T1189 | Coinhive JS delivered via brewertalk.com browsing session in Chrome |
| Resource Development | Stage Capabilities: Upload Tool | T1608 | Attacker uploaded miner payload to exposed S3 bucket |
| Collection | Data from Cloud Storage | T1530 | S3 bucket `frothlywebcode` publicly writable (misconfiguration) |
 | Impact | Resource Hijacking | T1496 | Coinhive Monero miner executing in employee browsers via WebSocket connections to ws001-014.coinhive.com |

## Controls Assessment

### Controls That Worked ✓
- **Symantec Endpoint Protection** - detected and blocked `JSCoinminer Download 6/8` on `BTUN-L` within minutes of infection; 46 total block events logged
- **Manual self-remediation** - `bstoll` identified and corrected the S3 ACL within 56 minutes
- **DNS telemetry** - Coinhive domain resolution captured across all three infected endpoints, enabling full scope assessment

### Controls That Failed or Were Missing ✗
- **No S3 bucket policy enforcing block-public-access** - AWS Block Public Access settings (available since 2018) would have prevented `PutBucketAcl` from granting public permissions regardless of user action
- **No S3 access logging with alerting** - public write attempts should trigger immediate alert; upload events during exposure window not queryable in available telemetry
- **No DNS sinkholes or category filtering** - `coinhive.com` and mining pool domains should be blocked at DNS resolver level; all three endpoints resolved freely
 - **SEP status on BSTOLL-L and MKRAEUS-L unclear** - DNS evidence confirms miner activity; no Symantec block events found for these two hosts, suggesting either SEP was not installed or signatures were not current

## Evidence Gaps

| Gap | Impact |
|---|---|
| S3 access logs `bucket_name` field not parseable in dataset | Cannot confirm exact payload filename, upload size, or attacker source IP for the upload |
| How attacker discovered the open bucket is unknown | Attribution and attack vector into the broader campaign unclear |
| BSTOLL-L and MKRAEUS-L miner containment status unconfirmed | Unknown whether CPU mining continued after the S3 bucket was closed |
 | brewertalk.com server-side logs not in dataset | Cannot confirm how miner script was injected into forum HTML |

## Recommendations

### Immediate (P0)
1. **Scan BSTOLL-L and MKRAEUS-L** for residual miner activity - Symantec blocked on BTUN-L but status on other two hosts is unconfirmed
2. **Verify brewertalk.com is clean** - if the miner script reference was injected into forum templates/database, correcting the S3 ACL alone does not remove the delivery mechanism

### Short-term (P1)
3. **Enable S3 Block Public Access at the account level** - prevents any bucket in the account from being made public, regardless of individual `PutBucketAcl` calls
4. **Enable S3 server access logging with alerting** - alert on any `PUT` or `DELETE` from unrecognized source IPs during business hours
5. **Deploy DNS category filtering** - block cryptomining domains at the resolver; Coinhive and similar mining pool domains are well-categorized in commercial threat intel feeds
6. **Audit SEP deployment** - confirm Symantec EP is installed and signature-current on all endpoints, particularly BSTOLL-L and MKRAEUS-L

### Long-term (P2)
7. **IAM policy: require MFA for S3 ACL changes** - `bstoll` changed a bucket ACL from what appears to be a standard session; require `aws:MultiFactorAuthPresent: true` for destructive S3 permission changes
 8. **Implement S3 bucket ownership controls** - enforce `BucketOwnerEnforced` ACL policy to disable ACL-based access entirely, using bucket policies only

## Relationship to IR-2018-001

These are **two separate, parallel incidents** on the same date with no confirmed overlap:

| | IR-2018-001 | IR-2018-002 |
|---|---|---|
| Primary actor | External attacker via EC2 IMDS | bstoll (accidental) + external attacker |
| AWS resource | IAM credentials / EC2 | S3 bucket `frothlywebcode` |
| Impact | Credential abuse, attempted EC2 hijacking | Drive-by cryptominer on 3 endpoints |
| Containment | Key revoked in 14 min (aws_ir) | Bucket closed in 56 min (manual) |

 The two incidents share no common IPs, users, or tooling. Coincidence of date is noted but no causal link found in available telemetry.

## Queries Used (SPL Reference)

```spl
-- PutBucketAcl events
index="botsv3" sourcetype="aws:cloudtrail" eventName=PutBucketAcl 
| table _time userIdentity.userName requestParameters.bucketName requestParameters.AccessControlPolicy sourceIPAddress

-- Cryptominer DNS queries
index="botsv3" (*coin* OR *monero*) sourcetype="stream:dns" | table _time host query

-- BSTOLL-L browsing session (forum visit)
index="botsv3" host="BSTOLL-L" sourcetype="stream:http" 
  earliest="08/20/2018:18:31:00" latest="08/20/2018:19:10:00" 
| table _time dest_ip uri_path status 
| search uri_path!="/pkiops*" uri_path!="/MF*"

-- Symantec EP detections (raw event expansion)
index="botsv3" sourcetype="symantec:ep:security:file" (*coin* OR *coinhive*) | head 5
```

*Report generated from hands-on investigation of BOTS v3 dataset. All claims verified against raw telemetry. Evidence gaps explicitly documented rather than inferred.*
