##! Zeek Script: C2 Beacon Detection via Fixed-Size Packet Pattern
##! Author: Insiyah
##! Date: 2026-07-02
##! Reference: IR-2018-001 - BOTS v3 EC2 Compromise & AWS Credential Abuse
##!
##! Description:
##!   Detects C2 beaconing behavior characterized by repeated small fixed-size
##!   TCP connections to an external host on a non-standard port at regular
##!   intervals. Derived from observed traffic pattern on mars.i-08e52f8b5a034012d:
##!
##!     - Port: 9998/TCP (non-standard)
##!     - Outbound beacon size: ~74 bytes
##!     - Inbound response size: ~54 bytes  
##!     - Interval: approximately every 5 minutes
##!     - C2 IP: 34.215.24.225
##!
##!   Also detects the large inbound payload delivery pattern that preceded
##!   credential theft activity (11.7MB at 14:34, 6 min before IMDS query).
##!
##! MITRE: T1571 (Non-Standard Port), T1105 (Ingress Tool Transfer)

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/conn

module C2_BeaconDetection;

export {
    redef enum Notice::Type += {
        ## Fixed small-packet exchange on non-standard port - beacon pattern
        C2_Beacon_Suspected,
        ## Large inbound payload on non-standard port - tool delivery
        C2_Payload_Delivery,
        ## Confirmed IOC - known C2 IP contacted
        C2_Known_IP_Contacted,
        ## High-frequency connections to same external host/port
        C2_HighFrequency_Connections
    };

    ## Ports considered standard/expected outbound - tune per environment
    const standard_ports: set[port] = {
        80/tcp, 443/tcp, 22/tcp, 53/udp, 8080/tcp, 8443/tcp, 25/tcp,
        587/tcp, 993/tcp, 995/tcp, 3389/tcp, 9997/tcp
    } &redef;

    ## Beacon packet size thresholds (bytes) - tune based on your C2 baseline
    const beacon_min_bytes = 40  &redef;
    const beacon_max_bytes = 150 &redef;

    ## Large payload threshold - flag inbound transfers above this (bytes)
    const payload_threshold_bytes = 500000 &redef;  # 500KB

    ## How many small connections in this window = beacon alert
    const beacon_conn_threshold = 4   &redef;
    const beacon_window          = 20mins &redef;

    ## Known C2 IOC IPs - update as new IOCs are identified
    ## Note: IOC-based detection has a short shelf life; review quarterly
    const known_c2_ips: set[addr] = {
        34.215.24.225   ##  IR-2018-001 confirmed C2, observed 2018-08-20
    } &redef;
}

# Track connection counts per src->dst:port pair for beacon frequency detection
global conn_tracker: table[string] of count &default=0 &create_expire=20mins;

event connection_state_remove(c: connection)
{
    local src   = c$id$orig_h;
    local dst   = c$id$resp_h;
    local dport = c$id$resp_p;

    # Skip internal-to-internal traffic
    if ( Site::is_local_addr(dst) )
        return;

    # -----------------------------------------------------------------
    # CHECK 1: Known C2 IOC IP
    # -----------------------------------------------------------------
    if ( dst in known_c2_ips )
    {
        NOTICE([$note=C2_Known_IP_Contacted,
                $conn=c,
                $msg=fmt("Connection to known C2 IP %s:%s from internal host %s [IR-2018-001 IOC]",
                         dst, dport, src),
                $identifier=cat(src, dst),
                $suppress_for=30mins]);
    }

    # Skip further checks if port is standard
    if ( dport in standard_ports )
        return;

    # -----------------------------------------------------------------
    # CHECK 2: Fixed small-packet beacon pattern
    # Both sides small AND on non-standard port
    # -----------------------------------------------------------------
    if ( c?$conn )
    {
        local orig_bytes = c$conn$orig_ip_bytes;
        local resp_bytes = c$conn$resp_ip_bytes;

        if ( orig_bytes >= beacon_min_bytes && orig_bytes <= beacon_max_bytes &&
             resp_bytes >= beacon_min_bytes && resp_bytes <= beacon_max_bytes )
        {
            local tracker_key = fmt("%s->%s:%s", src, dst, dport);
            conn_tracker[tracker_key] += 1;

            if ( conn_tracker[tracker_key] >= beacon_conn_threshold )
            {
                NOTICE([$note=C2_Beacon_Suspected,
                        $conn=c,
                        $msg=fmt("C2 beacon pattern: %s -> %s:%s | %d small fixed-size connections (%d/%d bytes) on non-standard port",
                                 src, dst, dport,
                                 conn_tracker[tracker_key],
                                 orig_bytes, resp_bytes),
                        $identifier=cat(src, dst, dport),
                        $suppress_for=10mins]);
            }
        }

        # -----------------------------------------------------------------
        # CHECK 3: Large inbound payload on non-standard port
        # Inbound >> outbound = something large was delivered TO the host
        # -----------------------------------------------------------------
        if ( resp_bytes > payload_threshold_bytes && orig_bytes < 10000 )
        {
            NOTICE([$note=C2_Payload_Delivery,
                    $conn=c,
                    $msg=fmt("Large inbound payload on non-standard port %s: %s received %.1fMB from %s (sent only %dB) - possible tool/malware delivery",
                             dport, src,
                             resp_bytes / 1000000.0,
                             dst, orig_bytes),
                    $identifier=cat(src, dst, dport),
                    $suppress_for=5mins]);
        }
    }
}

# -----------------------------------------------------------------
# CHECK 4: High-frequency connections to same external host
# Catches automated tools even if packet sizes vary
# -----------------------------------------------------------------
event connection_established(c: connection)
{
    local dst   = c$id$resp_h;
    local dport = c$id$resp_p;
    local src   = c$id$orig_h;

    if ( Site::is_local_addr(dst) || dport in standard_ports )
        return;

    local freq_key = fmt("freq_%s->%s:%s", src, dst, dport);
    conn_tracker[freq_key] += 1;

    if ( conn_tracker[freq_key] == 10 )  # Alert once at threshold
    {
        NOTICE([$note=C2_HighFrequency_Connections,
                $conn=c,
                $msg=fmt("High-frequency outbound connections: %s -> %s:%s (%d connections) on non-standard port - possible C2 or scanning",
                         src, dst, dport, conn_tracker[freq_key]),
                $identifier=cat(src, dst, dport),
                $suppress_for=15mins]);
    }
}
