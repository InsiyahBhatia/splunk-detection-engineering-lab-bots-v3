/*
    YARA Rule: Coinhive JavaScript Cryptominer Detection
    Author: Insiyah
    Date: 2026-07-02
    Reference: IR-2018-002 - BOTS v3 S3 Misconfiguration & Drive-By Cryptominer
    Description: Detects Coinhive browser-based Monero miner JS payloads and
                 variants delivered via compromised web assets. Based on observed
                 IOCs from brewertalk.com infection chain (54.67.127.227).
    Tested against: BOTS v3 dataset, Symantec SID 30356/30358 confirmed detections
*/

rule Coinhive_JS_Miner_Generic
{
    meta:
        description     = "Detects Coinhive JavaScript Monero miner - generic strings"
        author          = "Insiyah"
        report          = "IR-2018-002"
        date            = "2026-07-02"
        severity        = "HIGH"
        mitre_technique = "T1496"
        mitre_tactic    = "Impact"
        reference       = "https://attack.mitre.org/techniques/T1496/"

    strings:
        // Coinhive API and domain references
        $domain1 = "coinhive.com" ascii wide nocase
        $domain2 = "ws001.coinhive.com" ascii wide nocase
        $domain3 = "ws005.coinhive.com" ascii wide nocase
        $domain4 = "ws011.coinhive.com" ascii wide nocase
        $domain5 = "ws014.coinhive.com" ascii wide nocase

        // Coinhive JS API calls
        $api1 = "CoinHive.Miner" ascii wide nocase
        $api2 = "CoinHive.Anonymous" ascii wide nocase
        $api3 = "CoinHive.Token" ascii wide nocase
        $api4 = "coinhive.min.js" ascii wide nocase
        $api5 = "coin-hive.com" ascii wide nocase

        // Mining pool WebSocket patterns
        $ws1 = "wss://ws" ascii wide
        $ws2 = "mining.start()" ascii wide nocase
        $ws3 = "mining.stop()" ascii wide nocase
        $ws4 = "getHashesPerSecond" ascii wide nocase
        $ws5 = "getTotalHashes" ascii wide nocase

        // Site key pattern (base58, 32 chars - Coinhive API site key format)
        $sitekey = /[A-Za-z0-9]{32}/ ascii

        // Obfuscation patterns common in injected miners
        $obf1 = "atob(" ascii wide
        $obf2 = "eval(atob" ascii wide
        $obf3 = "fromCharCode" ascii wide

    condition:
        // Definite: any direct Coinhive API reference
        any of ($api*) or
        any of ($domain*)
        or
        // Probable: WebSocket mining behavior without explicit domain
        (2 of ($ws*) and $sitekey)
        or
        // Suspicious: obfuscated payload with mining indicators
        ($obf2 and any of ($ws*))
}


rule Coinhive_JS_Miner_Injected_In_HTML
{
    meta:
        description     = "Detects Coinhive miner script tags injected into HTML pages"
        author          = "Insiyah"
        report          = "IR-2018-002"
        date            = "2026-07-02"
        severity        = "HIGH"
        mitre_technique = "T1496"
        mitre_tactic    = "Impact"

    strings:
        // Script tag loading Coinhive from CDN or S3
        $inject1 = "<script src=\"https://coinhive.com" ascii nocase
        $inject2 = "<script src='https://coinhive.com" ascii nocase
        $inject3 = "<script src=\"https://coin-hive.com" ascii nocase
        $inject4 = "coinhive.com/lib/coinhive.min.js" ascii nocase
        $inject5 = "coinhive.com/lib/coinhive.anonymous.min.js" ascii nocase

        // Inline miner initialization
        $init1 = "new CoinHive.Miner(" ascii nocase
        $init2 = "new CoinHive.Anonymous(" ascii nocase
        $init3 = ".start({" ascii wide
        $init4 = "throttle:" ascii wide nocase

        // HTML context markers
        $html1 = "<html" ascii nocase
        $html2 = "<body" ascii nocase

    condition:
        ($html1 or $html2) and
        (any of ($inject*) or (any of ($init*) and $init4))
}


rule Generic_Browser_Cryptominer_Behavior
{
    meta:
        description     = "Detects generic browser cryptominer JS patterns - catches Coinhive variants and alternatives (Cryptoloot, Minero, etc.)"
        author          = "Insiyah"
        report          = "IR-2018-002"
        date            = "2026-07-02"
        severity        = "MEDIUM"
        mitre_technique = "T1496"
        mitre_tactic    = "Impact"
        note            = "Higher false positive rate than Coinhive-specific rules - tune before production use"

    strings:
        // Generic mining pool WebSocket endpoints
        $pool1 = "pool.minero.pw" ascii nocase
        $pool2 = "cryptoloot.com" ascii nocase
        $pool3 = "crypto-loot.com" ascii nocase
        $pool4 = "webmine.pro" ascii nocase
        $pool5 = "ppxxmr.com" ascii nocase
        $pool6 = "minerhills.com" ascii nocase

        // Generic miner JS API patterns
        $generic1 = "hashesPerSecond" ascii nocase
        $generic2 = "CryptoNoter" ascii nocase
        $generic3 = "JSEcoin" ascii nocase
        $generic4 = "stratum+tcp" ascii nocase
        $generic5 = "monero" ascii nocase

        // WebAssembly miner (WASM-based miners evade JS detection)
        $wasm1 = "WebAssembly.instantiate" ascii
        $wasm2 = ".wasm" ascii
        $wasm3 = "wasmMiner" ascii nocase

    condition:
        any of ($pool*) or
        (2 of ($generic*)) or
        ($wasm1 and $wasm3)
}
