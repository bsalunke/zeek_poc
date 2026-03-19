##! Comprehensive weak TLS cipher and protocol detection script.
##!
##! Detects: NULL, EXPORT, DES, 3DES, RC4, RC2, IDEA, anonymous ciphers,
##!          MD5-based MACs, missing Perfect Forward Secrecy, and
##!          deprecated protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1).
##!
##! Generates notices in notice.log and writes a dedicated weak_ciphers.log.

@load base/protocols/ssl
@load base/frameworks/notice
@load base/utils/directions-and-hosts

module WeakCipherDetect;

export {
    ## Notice types
    redef enum Notice::Type += {
        ## A weak or insecure cipher suite was negotiated
        Weak_Cipher_Detected,
        ## A deprecated TLS/SSL protocol version was used
        Deprecated_Protocol_Detected,
        ## A cipher without Perfect Forward Secrecy was negotiated
        No_PFS_Detected,
    };

    ## Log stream for weak cipher detections
    redef enum Log::ID += { LOG };

    ## Record type for the weak_ciphers.log
    type Info: record {
        ts:           time   &log;
        uid:          string &log;
        orig_h:       addr   &log;
        orig_p:       port   &log;
        resp_h:       addr   &log;
        resp_p:       port   &log;
        server_name:  string &log &default="<unknown>";
        version:      string &log &default="<unknown>";
        cipher:       string &log &default="<unknown>";
        risk_level:   string &log;  # CRITICAL, HIGH, MEDIUM
        reason:       string &log;
    };

    ## Regex matching known-weak cipher patterns
    const weak_cipher_pattern =
        /NULL|_anon_|EXPORT|_DES_|_RC4_|_RC2_|_IDEA_|DES_CBC|3DES|DES.EDE|_MD5$/
        &redef;

    ## Regex matching ciphers without Perfect Forward Secrecy
    ## (static RSA key exchange — no DHE or ECDHE)
    const no_pfs_pattern =
        /^TLS_RSA_/
        &redef;

    ## Minimum acceptable TLS version (connections below this are flagged)
    ## SSLv20=0x0200, SSLv30=0x0300, TLSv10=0x0301, TLSv11=0x0302, TLSv12=0x0303
    const min_version: count = 0x0303 &redef;  # TLS 1.2

    ## Which hosts to monitor
    const monitor_hosts = ALL_HOSTS &redef;
}

event zeek_init() &priority=5
    {
    Log::create_stream(WeakCipherDetect::LOG,
        [$columns=Info, $path="weak_ciphers"]);
    }

## Classify risk level for a cipher
function classify_cipher_risk(cipher_name: string): string
    {
    if ( /NULL|_anon_|EXPORT/ in cipher_name )
        return "CRITICAL";
    if ( /RC4|_DES_|DES_CBC|3DES|DES.EDE/ in cipher_name )
        return "HIGH";
    if ( /RC2|IDEA|_MD5$/ in cipher_name )
        return "HIGH";
    if ( /^TLS_RSA_/ in cipher_name )
        return "MEDIUM";
    return "LOW";
    }

## Get the reason a cipher is weak
function get_weakness_reason(cipher_name: string): string
    {
    if ( /NULL/ in cipher_name )
        return "NULL cipher — no encryption";
    if ( /EXPORT/ in cipher_name )
        return "EXPORT cipher — deliberately weakened key length";
    if ( /_anon_/ in cipher_name )
        return "Anonymous cipher — no server authentication, MITM trivial";
    if ( /RC4/ in cipher_name )
        return "RC4 — broken stream cipher, banned by RFC 7465";
    if ( /3DES|DES.EDE/ in cipher_name )
        return "3DES — vulnerable to Sweet32 birthday attack (64-bit block)";
    if ( /_DES_|DES_CBC/ in cipher_name )
        return "Single DES — 56-bit key, brute-forceable";
    if ( /RC2/ in cipher_name )
        return "RC2 — deprecated, weak key schedule";
    if ( /IDEA/ in cipher_name )
        return "IDEA — deprecated, removed from TLS 1.3";
    if ( /_MD5$/ in cipher_name )
        return "MD5-based MAC — collision attacks";
    if ( /^TLS_RSA_/ in cipher_name )
        return "Static RSA — no Perfect Forward Secrecy";
    return "Unknown weakness";
    }

## Map version count to human-readable string
function version_to_string(v: count): string
    {
    if ( v == 0x0200 ) return "SSLv2";
    if ( v == 0x0300 ) return "SSLv3";
    if ( v == 0x0301 ) return "TLSv10";
    if ( v == 0x0302 ) return "TLSv11";
    if ( v == 0x0303 ) return "TLSv12";
    if ( v == 0x0304 ) return "TLSv13";
    return fmt("Unknown(0x%04x)", v);
    }

event ssl_server_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, server_random: string,
                       session_id: string, cipher: count,
                       comp_method: count) &priority=3
    {
    local cipher_name = "";
    if ( cipher in SSL::cipher_desc )
        cipher_name = SSL::cipher_desc[cipher];
    else
        cipher_name = fmt("UNKNOWN_CIPHER_0x%04x", cipher);

    local ver_str = version_to_string(version);
    local sni = c$ssl?$server_name ? c$ssl$server_name : "<no-sni>";

    # --- Check for weak cipher suites ---
    if ( weak_cipher_pattern in cipher_name )
        {
        local risk = classify_cipher_risk(cipher_name);
        local reason = get_weakness_reason(cipher_name);

        Log::write(WeakCipherDetect::LOG, [
            $ts=network_time(),
            $uid=c$uid,
            $orig_h=c$id$orig_h,
            $orig_p=c$id$orig_p,
            $resp_h=c$id$resp_h,
            $resp_p=c$id$resp_p,
            $server_name=sni,
            $version=ver_str,
            $cipher=cipher_name,
            $risk_level=risk,
            $reason=reason
        ]);

        NOTICE([
            $note=Weak_Cipher_Detected,
            $msg=fmt("[%s] Weak cipher: %s (%s) — %s", risk, cipher_name, ver_str, reason),
            $conn=c,
            $sub=cipher_name,
            $identifier=cat(c$id$resp_h, cipher_name),
            $suppress_for=1hr
        ]);
        }

    # --- Check for missing Perfect Forward Secrecy ---
    else if ( no_pfs_pattern in cipher_name )
        {
        Log::write(WeakCipherDetect::LOG, [
            $ts=network_time(),
            $uid=c$uid,
            $orig_h=c$id$orig_h,
            $orig_p=c$id$orig_p,
            $resp_h=c$id$resp_h,
            $resp_p=c$id$resp_p,
            $server_name=sni,
            $version=ver_str,
            $cipher=cipher_name,
            $risk_level="MEDIUM",
            $reason="Static RSA — no Perfect Forward Secrecy"
        ]);

        NOTICE([
            $note=No_PFS_Detected,
            $msg=fmt("[MEDIUM] No PFS: %s (%s) — static RSA key exchange", cipher_name, ver_str),
            $conn=c,
            $sub=cipher_name,
            $identifier=cat(c$id$resp_h, cipher_name),
            $suppress_for=1hr
        ]);
        }

    # --- Check for deprecated protocol versions ---
    if ( version < min_version )
        {
        local proto_risk = "HIGH";
        if ( version <= 0x0300 )
            proto_risk = "CRITICAL";

        local proto_reason = fmt("Deprecated protocol %s", ver_str);

        Log::write(WeakCipherDetect::LOG, [
            $ts=network_time(),
            $uid=c$uid,
            $orig_h=c$id$orig_h,
            $orig_p=c$id$orig_p,
            $resp_h=c$id$resp_h,
            $resp_p=c$id$resp_p,
            $server_name=sni,
            $version=ver_str,
            $cipher=cipher_name,
            $risk_level=proto_risk,
            $reason=proto_reason
        ]);

        NOTICE([
            $note=Deprecated_Protocol_Detected,
            $msg=fmt("[%s] Deprecated protocol: %s with cipher %s", proto_risk, ver_str, cipher_name),
            $conn=c,
            $sub=ver_str,
            $identifier=cat(c$id$resp_h, version),
            $suppress_for=1hr
        ]);
        }
    }
