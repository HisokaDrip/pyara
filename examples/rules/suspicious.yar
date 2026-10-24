rule EICAR_Test_File : testfile
{
    meta:
        description = "EICAR antivirus test file (harmless, used to test scanners)"
    strings:
        $head = { 58 35 4F 21 50 25 40 41 50 5B 34 }
        $tag = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        all of them and filesize < 128
}

rule PowerShell_Download_Cradle : script suspicious
{
    meta:
        description = "PowerShell one-liner that downloads and executes code"
    strings:
        $ps = "powershell" nocase
        $dl1 = /New-Object\s+(System\.)?Net\.WebClient/i
        $dl2 = "Invoke-WebRequest" nocase
        $dl3 = "DownloadString" nocase
        $exec1 = "IEX" nocase
        $exec2 = "Invoke-Expression" nocase
        $enc = /\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{40,}/i
    condition:
        $ps and ((1 of ($dl*) and 1 of ($exec*)) or $enc)
}
