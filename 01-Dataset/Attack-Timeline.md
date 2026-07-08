# Attack Timeline - BOTS v3

> Chronological attack chain across both incidents in the BOTS v3 dataset, August 20, 2018.

## IR-2018-001: EC2 Compromise & AWS Credential Abuse via IMDS

| Time (UTC) | Event | Host/User | MITRE Technique | Report Link |
|---|---|---|---|---|
| 14:26 | Malware delivered to EC2 instance `mars` via C2 on port 9998 | mars (EC2) | T1105, T1571 | [IR-2018-001](../09-Incident-Reports/IR-2018-001-EC2-Credential-Abuse.md) |
| 14:40 | IMDS queried for EC2InstanceRole credentials | mars (EC2) | T1552.005 | [IR-2018-001](../09-Incident-Reports/IR-2018-001-EC2-Credential-Abuse.md) |
| 14:40 | `GetSessionToken` mints STS token ASIA... | mars (EC2) | T1078.004 | [IR-2018-001](../09-Incident-Reports/IR-2018-001-EC2-Credential-Abuse.md) |
| 14:40 | IAM enumeration burst (6 calls, <1 second, Boto3) | mars (EC2) | T1580 | [IR-2018-001](../09-Incident-Reports/IR-2018-001-EC2-Credential-Abuse.md) |
| 14:40 | `CreateUser` / `CreateAccessKey` denied (least-privilege working) | mars (EC2) | T1136.003, T1098.001 | [IR-2018-001](../09-Incident-Reports/IR-2018-001-EC2-Credential-Abuse.md) |
| 14:40-14:45 | Multi-region `RunInstances` sweep: 576 attempts, 15 regions, 2 IPs | ASIA... token | T1580, T1496 | [IR-2018-001](../09-Incident-Reports/IR-2018-001-EC2-Credential-Abuse.md) |
| 15:00 | `aws_ir` kills compromised credential | SOC response | — | [IR-2018-001](../09-Incident-Reports/IR-2018-001-EC2-Credential-Abuse.md) |
| 16:28, 16:33, 18:24 | C2 beacons continue (host not cleaned) | mars (EC2) | T1571 | [IR-2018-001](../09-Incident-Reports/IR-2018-001-EC2-Credential-Abuse.md) |

## IR-2018-002: S3 Misconfiguration & Drive-By Cryptominer Injection

| Time (UTC) | Event | Host/User | MITRE Technique | Report Link |
|---|---|---|---|---|
| 18:31 | `bstoll` calls `PutBucketAcl` on `frothlywebcode` — bucket becomes publicly writable | bstoll | T1530 | [IR-2018-002](../09-Incident-Reports/IR-2018-002-S3-Cryptominer.md) |
| 18:31-19:27 | Exposure window (56 min): attacker uploads Coinhive JS miner payload | Unknown | T1496, T1608 | [IR-2018-002](../09-Incident-Reports/IR-2018-002-S3-Cryptominer.md) |
| 18:48 | BSTOLL-L visits `brewertalk.com` forum (54.67.127.227) — drive-by execution via Chrome | BSTOLL-L | T1189 | [IR-2018-002](../09-Incident-Reports/IR-2018-002-S3-Cryptominer.md) |
| 18:48+ | MKRAEUS-L and BTUN-L resolve `coinhive.com`, `ws001-014.coinhive.com` | MKRAEUS-L, BTUN-L | T1496 | [IR-2018-002](../09-Incident-Reports/IR-2018-002-S3-Cryptominer.md) |
| 19:12 | Symantec EP blocks JSCoinminer Download 6/8 on BTUN-L | BTUN-L | — | [IR-2018-002](../09-Incident-Reports/IR-2018-002-S3-Cryptominer.md) |
| 19:27 | `bstoll` corrects bucket ACL | bstoll | — | [IR-2018-002](../09-Incident-Reports/IR-2018-002-S3-Cryptominer.md) |

## Detection-Validation Exercise (2026-07-01)

| Time (UTC) | Event | MITRE Technique | Report Link |
|---|---|---|---|
| 2026-07-01 | Multi-region `RunInstances` sweep replayed against same detection logic | T1078.004, T1580, T1496 | [IR-2026-0701-001](../09-Incident-Reports/IR-2026-0701-001-Detection-Validation.md) |
| 2026-07-01 | Sweep blocked by AWS service quotas — no automated alert fired | — | [IR-2026-0701-001](../09-Incident-Reports/IR-2026-0701-001-Detection-Validation.md) |

## Key Observations

- **IR-2018-001:** Some `RunInstances` calls passed IAM checks and were blocked only by EC2 account quotas, not security policy — the attacker got closer to success than the raw "denied" count suggests.
- **IR-2018-002:** `bstoll` was both the person who misconfigured the bucket and the first person infected — they accessed the forum they had just inadvertently weaponized.
- **IR-2026-0701-001:** The detection-validation exercise confirmed that without the Sigma rules and saved searches in this repo, the same multi-region sweep pattern would still go undetected.
