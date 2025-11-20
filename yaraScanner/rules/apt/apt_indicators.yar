rule APT_Generic_Webshell
{
    meta:
        description = "Detects generic webshell indicators"
        author = "SecOps Helper"
        severity = "critical"
        date = "2025-11-20"
        tags = "webshell apt"

    strings:
        $php1 = "<?php" nocase
        $asp1 = "<%@" nocase
        $asp2 = "<%=" nocase
        $jsp1 = "<%@page" nocase

        $exec1 = "exec(" nocase
        $exec2 = "shell_exec" nocase
        $exec3 = "system(" nocase
        $exec4 = "passthru" nocase
        $exec5 = "eval(" nocase
        $exec6 = "assert(" nocase
        $exec7 = "WScript.Shell" nocase
        $exec8 = "cmd.exe" nocase

        $upload1 = "move_uploaded_file" nocase
        $upload2 = "FileUpload" nocase

    condition:
        (any of ($php*, $asp*, $jsp*)) and 2 of ($exec*) and filesize < 100KB
}

rule APT_Suspicious_Credential_Access
{
    meta:
        description = "Detects credential dumping tools"
        author = "SecOps Helper"
        severity = "critical"
        date = "2025-11-20"
        tags = "apt credential-access"

    strings:
        $cred1 = "lsass.exe" nocase
        $cred2 = "sekurlsa" nocase
        $cred3 = "mimikatz" nocase
        $cred4 = "procdump" nocase
        $cred5 = "SAM" nocase
        $cred6 = "SYSTEM" nocase
        $cred7 = "SeDebugPrivilege" nocase

        $method1 = "MiniDumpWriteDump"
        $method2 = "LsaEnumerateLogonSessions"

    condition:
        2 of ($cred*) or any of ($method*)
}

rule APT_Lateral_Movement
{
    meta:
        description = "Detects lateral movement techniques"
        author = "SecOps Helper"
        severity = "high"
        date = "2025-11-20"
        tags = "apt lateral-movement"

    strings:
        $psexec1 = "psexec" nocase
        $psexec2 = "paexec" nocase
        $wmi1 = "Win32_Process" nocase
        $wmi2 = "Create" nocase
        $smb1 = "\\\\\\ADMIN$" nocase
        $smb2 = "\\\\\\C$" nocase
        $smb3 = "\\\\\\IPC$" nocase
        $rdp1 = "mstsc.exe" nocase
        $rdp2 = "Terminal Services" nocase

    condition:
        (any of ($psexec*)) or ($wmi1 and $wmi2) or (2 of ($smb*)) or (any of ($rdp*))
}

rule APT_C2_Communication
{
    meta:
        description = "Detects potential C2 communication patterns"
        author = "SecOps Helper"
        severity = "critical"
        date = "2025-11-20"
        tags = "apt c2 command-and-control"

    strings:
        $http1 = "User-Agent:" nocase
        $http2 = "POST" nocase
        $http3 = "GET" nocase

        $encode1 = "base64_encode" nocase
        $encode2 = "base64_decode" nocase
        $encode3 = "Convert.ToBase64String"
        $encode4 = "FromBase64String"

        $beacon1 = /sleep\(\d{4,}\)/ nocase
        $beacon2 = /Start-Sleep\s+-Seconds\s+\d{2,}/ nocase

        $dns1 = "nslookup" nocase
        $dns2 = "Resolve-DnsName" nocase

    condition:
        (any of ($http*) and any of ($encode*)) or any of ($beacon*) or any of ($dns*)
}
