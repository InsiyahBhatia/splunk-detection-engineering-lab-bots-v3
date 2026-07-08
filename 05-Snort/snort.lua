-- Snort 3 configuration for C2 detection rules
-- Reference: IR-2018-001 - BOTS v3 EC2 Compromise & AWS Credential Abuse
-- Adjust HOME_NET to match your internal network before use

HOME_NET = '192.168.0.0/16'
EXTERNAL_NET = '!$HOME_NET'

ips =
{
    rules = [[
        include /path/to/05-Snort/snort-c2-port9998.rules
    ]]
}
