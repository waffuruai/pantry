// A "ClickFix" chain seen 2026-11-04 at 94.26.41.150 and 94.26.41.196: a command the victim
// pastes into the Run box opens topazlabs.com as a decoy and runs hidden
// PowerShell that fetches an obfuscated second stage; that stage XORs a
// base64 blob with a key it computes (`gcm ???t?` -> "write") and runs the
// result, which downloads a fake installer (traffic1.exe, traffic3.exe: NSIS with a
// bundled IronPython) to %AppData% and starts it.
// Written by Waffuru from that sample set; MIT, like the rest of pantry.

import "hash"

rule Win_Downloader_ClickFix_Lure_Command
{
    meta:
        description = "Run-box command that opens a decoy site and runs hidden PowerShell rebuilding iex from a string to run a downloaded script"
        author = "Waffuru"
        reference = "https://github.com/waffuruai/pantry/issues/127"
        os = "windows"
        category = "downloader"
        family = "ClickFixTopaz"
        severity = "critical"
        score = 85
        date = "2026-11-04"

    strings:
        $iex_from_name = ".Trim.Name[2]+" nocase
        $hidden = "powershell -wi hi" nocase
        $irm_ip = /irm\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\//
        $server_150 = "94.26.41.150"
        $server_196 = "94.26.41.196"
        $decoy = "start https://topazlabs.com" nocase

    condition:
        filesize < 64KB and (any of ($server_*) or ($iex_from_name and ($hidden or $irm_ip)) or ($decoy and $hidden))
}

rule Win_Downloader_ClickFix_PowerShell_Stage
{
    meta:
        description = "Obfuscated PowerShell stage: base64 blob XORed with a key from a command-name wildcard, joined to chars and run through a disguised iex"
        author = "Waffuru"
        reference = "https://github.com/waffuruai/pantry/issues/127"
        os = "windows"
        category = "downloader"
        family = "ClickFixTopaz"
        severity = "critical"
        score = 85
        date = "2026-11-04"

    strings:
        $b64_disguised = /'FromB[A-Za-z]{3}ase64String'\.Remove\(5,3\)/
        $iex_disguised = /\.'[a-z]{4,10}'\.Remove\(\d,\d\)\(-join/
        $key_from_gcm = "(gcm ???t?).Name"
        $xor_loop = "-bxor (gv('" nocase
        $junk_var = "((gv('sett') -Value))"
        $junk_stmt = "string s=Guid.Length.ToString.Replace('b','')"

    condition:
        filesize < 4MB and ($b64_disguised or 3 of them)
}

rule Win_Downloader_ClickFix_Decoded_Stage
{
    meta:
        description = "The decoded second stage: download a program into AppData with a renamed Invoke-WebRequest and start it (seen in memory, logs and transcripts)"
        author = "Waffuru"
        reference = "https://github.com/waffuruai/pantry/issues/127"
        os = "windows"
        category = "downloader"
        family = "ClickFixTopaz"
        severity = "critical"
        score = 85
        date = "2026-11-04"

    strings:
        $drop = /=Join-Path \$env:AppData '[A-Za-z0-9_]{1,32}\.exe';Copy-Items -useba https?:\/\/[^ ]{4,120} -o \$[A-Za-z0-9_]{1,16};start \$/ nocase

    condition:
        $drop
}

rule Win_Dropper_ClickFix_Traffic_Installer
{
    meta:
        description = "The fake installers the ClickFixTopaz chain drops (NSIS with a bundled IronPython and encoded payload blobs)"
        author = "Waffuru"
        reference = "https://github.com/waffuruai/pantry/issues/127"
        os = "windows"
        category = "dropper"
        family = "ClickFixTopaz"
        severity = "critical"
        score = 90
        date = "2026-11-04"
        hash1 = "765f42e351b17c6a36f85bebe587f501696faea748f6d8271623747b465f38e3"
        hash2 = "ebf28a04fa480a8f4dba9438cd5388cefeda0a3e089d47e0717e334ee5b0fc24"

    condition:
        uint16(0) == 0x5A4D and filesize > 30MB and filesize < 60MB
        and (hash.sha256(0, filesize) == "765f42e351b17c6a36f85bebe587f501696faea748f6d8271623747b465f38e3"
          or hash.sha256(0, filesize) == "ebf28a04fa480a8f4dba9438cd5388cefeda0a3e089d47e0717e334ee5b0fc24")
}
