# Dataset Overview - BOTS v3

## Source
- Dataset: [Splunk BOTS v3](https://github.com/splunk/botsv3)
- Size: 320.1 MB (pre-indexed)
- MD5: `d7ccca99a01cff070dff3c139cdc10eb`
- Download: `wget https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz`

## Scenario
BOTS v3 simulates a security incident at "Frothly", a fictitious brewing company. The dataset captures two simultaneous attack chains on August 20, 2018:

1. **IR-2018-001 (CRITICAL):** An EC2 instance (`mars`) is compromised via malware delivered over non-standard port 9998. The attacker queries the EC2 IMDS for IAM credentials, abuses STS to mint tokens, performs IAM enumeration, and launches a multi-region `RunInstances` sweep across 15 regions (576 attempts) — likely for cryptomining. Stopped by IAM least-privilege + EC2 account quotas, with a 14-minute response time via `aws_ir`.

2. **IR-2018-002 (HIGH):** A developer (`bstoll`) accidentally makes an S3 bucket (`frothlywebcode`) publicly writable via `PutBucketAcl`. An attacker uploads a Coinhive JavaScript cryptominer. The payload is served to forum visitors via `brewertalk.com` (54.67.127.227), resulting in drive-by cryptomining on endpoints (BSTOLL-L, MKRAEUS-L, BTUN-L). Symantec EP blocks detection on one host. Bucket ACL is corrected after 56 minutes.

## Environment
| Item | Detail |
|---|---|
| Domain | frothly (internal AD), brewertalk.com (public web) |
| Key hosts | mars (EC2, compromised), BSTOLL-L (Win10, infected), MKRAEUS-L (Win10, infected), BTUN-L (Win10, infected + Symantec block) |
| Key users | bstoll (developer, misconfigured S3), ec2-instance-profile (EC2 role abused) |
| Cloud provider(s) | AWS (EC2, S3, IAM, STS, CloudTrail) |

## Log Sources Present
- [x] Windows Security Event Logs
- [x] Sysmon
- [x] DNS
- [ ] Proxy
- [ ] Firewall
- [x] Zeek
- [x] Suricata
- [x] AWS CloudTrail
- [x] Linux logs
- [ ] Email logs
- [x] Web logs
- [x] Endpoint logs (Symantec EP, osquery)

## Sourcetype Summary
The BOTS v3 dataset contains ~2M events across 107 sourcetypes. Key sourcetypes used in this investigation:

| Sourcetype | Source | Events Used |
|---|---|---|
| `aws:cloudtrail` | AWS CloudTrail API logs | IAM, EC2, S3 API calls |
| `WinEventLog:Security` | Windows Security Event Log | User logons, process creation |
| `WinEventLog:Symantec` | Symantec Endpoint Protection | JSCoinminer detections |
| `stream:dns` | Zeek DNS stream | Coinhive domain resolutions |
| `stream:tcp` | Zeek TCP stream | C2 beacon patterns on port 9998 |
| `stream:http` | Zeek HTTP stream | Web requests to brewertalk.com |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Sysmon | Process/network event correlation |
| `osquery:results` | osquery | IR tooling execution, process listing |

Verify with:
```spl
index=botsv3 earliest="08/20/2018:00:00:00" latest="08/20/2018:23:59:59"
| stats count by sourcetype
| sort -count
```

## Attack Timeline
See the full chronological timeline in [`Attack-Timeline.md`](Attack-Timeline.md), or the detailed incident reports in [`09-Incident-Reports/`](../09-Incident-Reports/).

| Time (UTC) | Event | Host/User | MITRE Technique | Report |
|---|---|---|---|---|
| 14:26 | Malware delivered to EC2 via C2 port 9998 | mars | T1105, T1571 | [IR-2018-001](../09-Incident-Reports/IR-2018-001-EC2-Credential-Abuse.md) |
| 14:40 | IMDS queried for IAM credentials | mars | T1552.005 | [IR-2018-001](../09-Incident-Reports/IR-2018-001-EC2-Credential-Abuse.md) |
| 14:40 | IAM enumeration burst (6 calls, <1s) | mars | T1580 | [IR-2018-001](../09-Incident-Reports/IR-2018-001-EC2-Credential-Abuse.md) |
| 14:40-14:45 | Multi-region RunInstances sweep (576 attempts) | ASIA... token | T1580, T1496 | [IR-2018-001](../09-Incident-Reports/IR-2018-001-EC2-Credential-Abuse.md) |
| 15:00 | aws_ir kills credential | SOC | — | [IR-2018-001](../09-Incident-Reports/IR-2018-001-EC2-Credential-Abuse.md) |
| 18:31 | bstoll makes S3 bucket publicly writable | bstoll | T1530 | [IR-2018-002](../09-Incident-Reports/IR-2018-002-S3-Cryptominer.md) |
| 18:48 | BSTOLL-L visits brewertalk.com — drive-by infection | BSTOLL-L | T1189 | [IR-2018-002](../09-Incident-Reports/IR-2018-002-S3-Cryptominer.md) |
| 19:12 | Symantec EP blocks miner on BTUN-L | BTUN-L | — | [IR-2018-002](../09-Incident-Reports/IR-2018-002-S3-Cryptominer.md) |
| 19:27 | bstoll corrects bucket ACL (56 min exposure) | bstoll | — | [IR-2018-002](../09-Incident-Reports/IR-2018-002-S3-Cryptominer.md) |
