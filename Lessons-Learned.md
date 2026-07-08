# Lessons Learned - Frothly BOTSv3 Detection Engineering Exercise

**Author:** Insiyah Bhatia
**Date:** 2026-07-02
**Source Reports:** IR-2018-001, IR-2018-002 (BOTSv3 dataset, incident date 2018-08-20), IR-2026-0701-001 (follow-up detection-validation exercise, 2026-07-01)

## Summary

Two parallel incidents on Frothly's AWS infrastructure and employee endpoints - an IMDS credential-theft/multi-region hijack attempt (IR-2018-001) and an S3-misconfiguration-driven cryptominer delivery (IR-2018-002) - were investigated from the BOTSv3 dataset (2018-08-20). A third report, IR-2026-0701-001, documents a later exercise validating whether the Sigma rules built from IR-2018-001 would have caught a near-identical multi-region `RunInstances` sweep pattern. In all three cases, **no compute resources were successfully provisioned by the attacker** - but containment came from AWS service quotas and capacity limits, not from detection. That gap is the throughline of everything below, and it's what the dashboard and scheduled alerts built in this repo (`11-Dashboard/`, `12-Alerts/`) are designed to close.

> **Bottom line:** Defenders weren't beaten by a sophisticated attacker - they were saved by AWS quotas. The real findings are the control gaps (IMDSv1, overpermissive instance roles, no S3 Block Public Access, no egress filtering, no MFA) and the detection gaps (no SIEM alert fired in any of the three events) that this project's Sigma/YARA/Snort/Zeek content and live alerting are meant to close.

## 1. Cloud Infrastructure Security

**1.1 Retire IMDSv1.** The attacker queried `169.254.169.254/latest/meta-data/iam/security-credentials/EC2InstanceRole` with no session authentication. IMDSv2 requires a PUT-then-GET session handshake that would have blocked this outright.
> Enforce `MetadataOptions.HttpTokens=required` via SCP or account-level default.
```spl
index="botsv3" sourcetype="stream:http" dest_ip="169.254.169.254"
  uri_path="*iam/security-credentials*" http_method="GET"
| stats count by host
```

**1.2 Scope instance roles to least privilege.** `EC2InstanceRole` could call `sts:GetSessionToken` and `ec2:RunInstances` - neither needed by a typical application role. Once IMDS creds were stolen, the attacker inherited more power than the workload itself required.
> Audit all instance roles; strip `sts:GetSessionToken`, `sts:AssumeRole`, `ec2:RunInstances`, `iam:*` unless explicitly justified. Use dedicated CI/CD roles for provisioning.

**1.3 Enforce S3 Block Public Access at the account/org level.** `bstoll`'s `PutBucketAcl` call succeeded because nothing overrode it. Account-level Block Public Access (available since 2018) would have ignored the ACL change entirely.
```bash
aws s3control get-public-access-block --account-id 622676721278
```

**1.4 Quotas ≠ detection.** The 576-attempt, 15-region sweep - and its 2026 detection-validation replay - were both stopped by `Client.InstanceLimitExceeded` / `Server.InsufficientInstanceCapacity`, not by GuardDuty or a SIEM alert. Treat quotas as defense-in-depth, not a primary control. The Sigma rules in `03-Sigma/` and the scheduled alerts in `12-Alerts/` close this gap directly.

## 2. Detection Engineering

**2.1 Never conclude "IAM blocked everything" without checking error codes.** Some `RunInstances` calls returned `Server.InsufficientInstanceCapacity` - meaning authorization *succeeded* and only capacity blocked launch. The attacker was closer to success than the raw "denied" count suggested.
```spl
index=botsv3 eventName=RunInstances | stats count by errorCode
```
Any `Client.*`/`Server.*` code beyond `AccessDenied` means the call passed authorization.

**2.2 Pivot on identity, not IP.** The attacker rotated across `35.153.154.221` and `139.198.18.205` (likely VPN/proxy). `accessKeyId` was the only stable pivot across the full 15-region sweep - IPs are ephemeral, identities persist.

**2.3 GuardDuty has coverage gaps.** No finding fired for the RunInstances sweep in either 2018 or the 2026 replay, even though `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` should have caught the underlying IMDS theft. Layer custom CloudTrail-based Sigma detections and behavioral analytics on top - don't treat GuardDuty as complete coverage.

**2.4 DNS logging is the most reliable cross-host detective control.** Symantec EP blocked the miner on only one host (`BTUN-L`); `stream:dns` logging of Coinhive domain resolutions was the *only* evidence confirming infection on `BSTOLL-L` and `MKRAEUS-L`. DNS visibility doesn't depend on EDR agent health or signature currency.

**2.5 Raw query volume is not the same as a usable detection.** Building the dashboard's IMDS panel surfaced a real tuning lesson: every EC2 instance queries IMDS for credential refresh roughly every 15 minutes as normal SDK behavior. An untuned alert on every IMDS hit would fire hundreds of times a day and get ignored. The working detection (`12-Alerts/savedsearches.conf` > IMDS Credential Access Anomaly) alerts on the *first* query per host per hour instead - a concrete example of why a detection has to be validated against its own false-positive rate before it goes into a SOC's queue, not just against whether it can technically match the malicious event.

## 3. Incident Response

**3.1 Credential revocation is step one, not the finish line.** `aws_ir` disabled the compromised key in 14 minutes, but the C2 beacon on `mars` kept running for 4+ hours afterward (16:28, 16:33, 18:24) - the host itself was never isolated or reimaged.
> After revoking credentials: isolate the host (SG/NACL quarantine), capture forensics, reimage from known-good, and explicitly verify C2 termination before closing the ticket.

**3.2 Test IR playbooks, don't just script them.** `aws_ir` was re-run three times (15:00:53 / 15:03:59 / 15:05:01) - likely because there was no clear success signal after the first run.
> Define explicit success criteria (e.g., "key shows `Inactive` in IAM console") so responders aren't guessing.

**3.3 Self-remediation isn't the same as investigation.** `bstoll` quietly fixed the S3 ACL 56 minutes after causing the exposure - no security team involvement at any point.
> Alert on high-risk API calls (`PutBucketAcl`, `PutBucketPolicy`) regardless of who makes them, and require second-person review before treating them as resolved. This is now a standing alert in `12-Alerts/`.

## 4. AWS Architecture & Configuration

**4.1 CloudTrail regional gaps let part of the sweep go unlogged.** Not all 15 targeted regions had trails enabled.
> Enable CloudTrail (with log file validation) in every region, including opt-in regions, centralized to a cross-account S3 bucket.

**4.2 No egress filtering.** `mars` connected outbound to `34.215.24.225:9998` with nothing to stop it.
> Default-deny egress; allow-list only known endpoints (specific S3 buckets, API endpoints, package repos); alert on any traffic to unrecognized external IPs.

**4.3 No MFA on `web_admin`.** A stolen long-term key was immediately usable - and the 2026 replay confirms the same credential family remained vulnerable to the same pattern. `aws:MultiFactorAuthPresent: true` on sensitive actions would have neutralized both.
> Require MFA org-wide; pair with `aws:RequestedRegion` conditions to restrict where keys can be used.

## 5. From Investigation to Live Detection

Everything below started as a one-off SPL query during the hunt and now exists as durable detection content anyone can deploy against a live Splunk instance.

| Gap | Source Incident | Static Artifact | Live Deployment |
|---|---|---|---|
| Multi-region `RunInstances` sweep | IR-2018-001 / IR-2026-0701-001 | `03-Sigma/aws_ec2_runinstances_multi_region_sweep.yml` | Dashboard panel + scheduled alert (throttled 15m per accessKeyId) |
| IAM reconnaissance burst | IR-2018-001 / IR-2026-0701-001 | `03-Sigma/aws_iam_reconnaissance_burst.yml` | Dashboard panel + scheduled alert |
| S3 public ACL change | IR-2018-002 | - | Dashboard panel + scheduled alert (fires on every `PutBucketAcl`, regardless of actor) |
| Coinhive miner (file/HTML) | IR-2018-002 | `04-YARA/yara-coinhive-miner.yar` | Dashboard panel + scheduled alert (DNS-based) |
| C2 traffic, port 9998 | IR-2018-001 | `05-Snort/snort-c2-port9998.rules` | Dashboard panel + scheduled alert (throttled 15m per host/dest_ip) |
| C2 beacon behavior | IR-2018-001 | `06-Zeek/zeek-c2-beacon-detection.zeek` | Timeline panel |
| IMDS credential theft | IR-2018-001 | `06-Zeek/zeek-imds-credential-theft.zeek` | Dashboard panel (hourly first-seen) + scheduled alert - both tuned to exclude routine SDK refresh noise |
| Consolidated IOCs | All | `10-IOCs/consolidated-iocs.md` | - |
 | MITRE technique rollup | All | `08-MITRE/frothly-botsv3-campaign-attack-navigator-layer.json` | Dashboard summary table |

## 6. Key Metrics

| Metric | Value | Source |
|---|---|---|
| Total incidents investigated | 2 (BOTSv3) + 1 validation exercise | - |
| RunInstances attempts | 576 (IR-2018-001) | CloudTrail |
| AWS regions targeted | 15 (IR-2018-001) | CloudTrail |
| Endpoints affected (miner) | 3 - BSTOLL-L, MKRAEUS-L, BTUN-L | IR-2018-002 |
| Distinct attacker/source IPs across campaign | 4 | Consolidated IOCs |
| EC2 instances successfully launched | 0 | CloudTrail |
| Detection-to-credential-revocation | 14 min (IR-2018-001) | osquery |
| S3 exposure window | 56 min (IR-2018-002) | CloudTrail |
| C2 persistence post-revocation | 4+ hrs (IR-2018-001) | stream:tcp |
| Automated detections that fired (2018) | 1 - Symantec EP on BTUN-L only | Symantec EP |
| Automated detections that fired (2026 replay) | 0 | IR-2026-0701-001 |
 | Detection rules/queries produced | 9 static + 5 scheduled alerts + 1 dashboard | This exercise |

## 7. Snort 3 & YARA Implementation

**7.1 Snort 3 has to be built from source on modern distros.** Ubuntu 26.04 doesn't ship Snort packages anywhere. The chain goes: dependencies > LibDAQ (must match Snort's v3.0.27+ requirement) > Snort 3. LibDAQ v3.0.27 switched to CMake mid-cycle, so check the build system before running bootstrap.

**7.2 Snort 2 rules don't load in Snort 3 without changes.** The breaking differences we hit:
- `$HOME_NET` / `$EXTERNAL_NET` variables - Snort 3 defines them in `snort.lua` and references them without `$`. Rules need literal CIDR or config-scoped networks.
- Backslash line continuations - Snort 3 doesn't support them. All options must stay within the parentheses on natural lines.
- Pure IP/header-only rules - Snort 3 needs at least one detection option beyond the header. Adding `classtype` and `metadata` fixes it, but removing the IOC-IP rule entirely eliminated the complexity.
- The minimal rule set (4 rules, no `content`/`detection_filter`) passed clean on first load. The final file uses only `flags`, `dsize`, and `sid` / `rev` - the simplest valid Snort 3 syntax.

**7.3 Validate against a real PCAP, not just the config parser.** After `snort -c snort.lua --warn-all` passed, a Scapy PCAP with 3 packets confirmed rules 9000001 and 9000002 actually fired. Rules 9000003 and 9000005 didn't trigger - expected, since the synthetic payloads don't match their size (9000003 needs >1460 bytes) or destination port (9000005 covers 9990-9999, PCAP targets 9998). That's specificity, not a bug.

**7.4 YARA warnings matter, even if the syntax looks clean.** The `$sitekey` regex fires a performance warning. For production, swap it for a `for any` loop if scan speed matters. Also had to add `$wasm1` to the condition - YARA caught it as unreferenced at scan time.

**7.5 Test-driven development catches process gaps too.** Writing positive and negative samples before scanning revealed that YARA had been wiped during an earlier cleanup step. Easy fix: reinstall. The negative samples passed clean - no false positives.

## 8. Final Takeaway

The attacker never provisioned a single instance - but that was AWS's service quotas doing the work defenders should have been doing, in both 2018 and again in the 2026 replay. Across all three incidents, the pattern repeats: fast, effective *response* (14-minute key revocation) paired with incomplete *remediation* (host never isolated, C2 alive for hours) and near-total *detection* silence (one AV block, zero SIEM/GuardDuty alerts, zero alerts in the replay). The Sigma, YARA, Snort, Zeek, dashboard, and scheduled-alert content built from this investigation is designed to close exactly those detection gaps. The next step isn't more retrospective validation - it's deploying `12-Alerts/savedsearches.conf` against live traffic and tuning thresholds against real production volume.
