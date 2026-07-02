# Dataset Overview - BOTS v3

## Source
- Dataset: [Splunk BOTS v3](https://github.com/splunk/botsv3)
- Size: 320.1 MB (pre-indexed)
- MD5: `d7ccca99a01cff070dff3c139cdc10eb`
- Download: `wget https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz`

## Scenario
BOTS v3 simulates a security incident at a fictitious brewing company ("Frothy"). Fill in once you've explored the data:
- What is the attack scenario / storyline?
- What environment is represented (on-prem, AWS, Azure, hybrid)?

## Environment
| Item | Detail |
|---|---|
| Domain | |
| Key hosts | |
| Key users | |
| Cloud provider(s) | |

## Log Sources Present
- [ ] Windows Security Event Logs
- [ ] Sysmon
- [ ] DNS
- [ ] Proxy
- [ ] Firewall
- [ ] Zeek
- [ ] Suricata
- [ ] AWS CloudTrail
- [ ] Linux logs
- [ ] Email logs
- [ ] Web logs
- [ ] Endpoint logs

Verify with:
```spl
index=botsv3 earliest=0 | stats count by sourcetype
```

## Attack Timeline
_High-level chronology - fill in as you investigate. Link each entry to its full write-up in 09-Incident-Reports/._

| Time (UTC) | Event | Host/User | MITRE Technique | Notes |
|---|---|---|---|---|
| | | | | |
