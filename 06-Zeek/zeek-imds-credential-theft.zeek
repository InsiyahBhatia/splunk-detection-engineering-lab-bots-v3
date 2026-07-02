##! Zeek Script: AWS Instance Metadata Service (IMDS) Credential Theft Detection
##! Author: Insiyah
##! Date: 2026-07-02
##! Reference: IR-2018-001 - BOTS v3 EC2 Compromise & AWS Credential Abuse
##!
##! Description:
##!   Detects processes querying the AWS Instance Metadata Service (IMDS) for
##!   IAM credentials via HTTP GET to 169.254.169.254. Any request to the
##!   /iam/security-credentials/ path represents credential harvesting - either
##!   by a legitimate application (expected, baselined) or by malware (alert).
##!
##!   In IR-2018-001, malware on mars.i-08e52f8b5a034012d queried IMDS at
##!   14:40:23 UTC, received EC2InstanceRole credentials, and used them 6 minutes
##!   later to begin IAM enumeration and multi-region EC2 hijacking.
##!
##! MITRE: T1552.005 - Unsecured Credentials: Cloud Instance Metadata API
##! Deploy on: EC2 instance running Zeek on the host network interface

@load base/frameworks/notice
@load base/protocols/http

module IMDS_CredentialTheft;

export {
    redef enum Notice::Type += {
        ## Fired when any process queries IMDS for IAM credentials
        IMDS_Credential_Access,
        ## Fired when IMDS returns a successful credential response
        IMDS_Credential_Returned,
        ## Fired when IMDS credential endpoint is accessed repeatedly
        IMDS_Repeated_Credential_Access
    };

    ## The IMDS link-local address - never changes in AWS
    const IMDS_IP = 169.254.169.254 &redef;

    ## URI paths that indicate credential harvesting (not just metadata browsing)
    const credential_paths: set[string] = {
        "/latest/meta-data/iam/security-credentials",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/meta-data/iam/info"
    } &redef;

    ## How many IMDS credential queries within this window triggers repeated-access alert
    const repeated_access_threshold = 3 &redef;
    const repeated_access_window    = 60secs &redef;
}

# Track per-source IMDS credential query counts
global imds_query_count: table[addr] of count &default=0 &create_expire=5mins;

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    # Only interested in requests to IMDS
    if ( c$id$resp_h != IMDS_IP )
        return;

    # Check if path is a credential-harvesting endpoint
    local is_credential_path = F;
    for ( path in credential_paths )
    {
        if ( path in unescaped_URI )
            is_credential_path = T;
    }

    # Alert on any direct credential path hit
    if ( is_credential_path )
    {
        NOTICE([$note=IMDS_Credential_Access,
                $conn=c,
                $msg=fmt("IMDS credential endpoint queried: %s -> %s%s",
                         c$id$orig_h, IMDS_IP, unescaped_URI),
                $sub=fmt("Method: %s | URI: %s", method, unescaped_URI),
                $identifier=cat(c$id$orig_h),
                $suppress_for=1min]);

        # Increment counter for repeated-access detection
        imds_query_count[c$id$orig_h] += 1;

        if ( imds_query_count[c$id$orig_h] >= repeated_access_threshold )
        {
            NOTICE([$note=IMDS_Repeated_Credential_Access,
                    $conn=c,
                    $msg=fmt("Repeated IMDS credential queries from %s (%d queries) - possible automated credential harvesting",
                             c$id$orig_h, imds_query_count[c$id$orig_h]),
                    $identifier=cat(c$id$orig_h),
                    $suppress_for=5mins]);
        }
    }

    # Also log any IMDS access to a dedicated log for baselining
    Log::write(HTTP::LOG, c$http);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    if ( c$id$resp_h != IMDS_IP )
        return;

    # HTTP 200 on credential path = credentials were actually returned
    if ( code == 200 && c?$http && c$http?$uri )
    {
        for ( path in credential_paths )
        {
            if ( path in c$http$uri )
            {
                NOTICE([$note=IMDS_Credential_Returned,
                        $conn=c,
                        $msg=fmt("IMDS returned credentials (HTTP 200) to %s for path: %s - verify this is an expected application",
                                 c$id$orig_h, c$http$uri),
                        $identifier=cat(c$id$orig_h, c$http$uri),
                        $suppress_for=5mins]);
            }
        }
    }
}
