// A Monero miner kit seen 2026-11-03: XMRig builds for Windows and Linux,
// pool configs for c3pool and unMineable paid out to one Tron wallet, and
// shell droppers that kill competing miners before starting their own.
// Written by Waffuru from that sample set; MIT, like the rest of pantry.

rule Any_Miner_C3poolKit_Config
{
    meta:
        description = "XMRig pool configuration of the c3pool/unMineable kit, or its payout wallet or relay"
        author = "Waffuru"
        reference = "https://github.com/waffuruai/pantry/issues/127"
        os = "any"
        category = "miner"
        family = "C3poolKit"
        severity = "critical"
        score = 90
        date = "2026-11-04"

    strings:
        $wallet = "TNpE8YMAVPC9gioq2BrZ3ogGEzivERxLCx"
        $relay = "89.36.231.178"
        $pool_c3_org = "c3pool.org"
        $pool_c3_com = "c3pool.com"
        $pool_unmineable = "rx.unmineable.com"
        $cfg_rig = "\"rig-id\""
        $cfg_algo = "\"algo\""
        $cfg_user = "\"user\""

    condition:
        filesize < 4MB and ($wallet or $relay or (any of ($pool_*) and 2 of ($cfg_*)))
}

rule Any_Miner_C3poolKit_Competitor_Killer
{
    meta:
        description = "Shell dropper that kills other miners (c3pool, herominers, unMineable, any stratum client) before starting its own"
        author = "Waffuru"
        reference = "https://github.com/waffuruai/pantry/issues/127"
        os = "linux"
        category = "miner"
        family = "C3poolKit"
        severity = "critical"
        score = 85
        date = "2026-11-04"

    strings:
        $case = "*c3pool*|*herominers*|*stratum*|*unmineable*"
        $pool_grep = "grep -o 'unmineable\\|c3pool'"
        $shebang = "#!/bin/"

    condition:
        filesize < 1MB and $shebang at 0 and ($case or $pool_grep)
}
