param (
    [Parameter(Mandatory)]
    [string]$p
)

$allEvents = @()

function Extract-FromXml {
    param ($event, $userField, $ipField)

    try {
        $xml = [xml]$event.ToXml()
        $edata = $xml.Event.EventData.Data
        $user = $edata | Where-Object { $_.Name -eq $userField } | Select-Object -ExpandProperty "#text"
        $ip = $edata | Where-Object { $_.Name -eq $ipField } | Select-Object -ExpandProperty "#text"
        return @($user, $ip)
    } catch {
        return @("", "")
    }
}

#function Parse-4624 {
#    param ($event)
#    $user, $ip = Extract-FromXml $event "TargetUserName" "IpAddress"
#    $logonType = ([xml]$event.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq "LogonType" } | Select-Object -ExpandProperty "#text"
#    if ($ip) {
#        return [PSCustomObject]@{
#            "Status/Tag"           = ""
#            "System Name"          = ($event.MachineName -split '\.')[0]
#            "Date/Time (UTC)"      = $event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
#            "Evidence Source"      = "Security - EID 4624"
#            "Activity Description" = "Logon type $logonType with $user from $ip"
#            "Details/Comments"     = ""
#            "User"                 = $user
#        }
#    }
#}

function Parse-RDP {
    param ($event, $source)

    $msg  = $event.Message
    $user = ""
    $ip   = ""
    $sessionId = ""

    if ($msg -match "User:\s+(\S+)") { $user = $matches[1] }
    if ($msg -match "Source Network Address:\s+(\S+)") { $ip = $matches[1] }
    if (-not $user -and $msg -match "with\s+(\S+)") { $user = $matches[1] }
    if (-not $ip   -and $msg -match "from\s+([\d\.:a-fA-F]+)") { $ip = $matches[1] }

    if ($event.Id -in 21, 23, 24 -and $msg -match "Session ID:\s+(\d+)") {
    $sessionId = $matches[1]
    }

    $usernameOnly = if ($user -match '\\') { ($user -split '\\')[-1] } else { $user }

    $desc = switch ($event.Id) {
        21     { "RDP connection with $usernameOnly from $ip" }
        23     { "RDP session reconnected with $usernameOnly from $ip" }
        24     { "RDP disconnection with $usernameOnly from $ip" }
        1149   { "RDP connection initiated with $usernameOnly from $ip" }
        default { "Unknown RDP event $($event.Id)" }
    }

    return [PSCustomObject]@{
        "Status/Tag"           = ""
        "System Name"          = ($event.MachineName -split '\.')[0]
        "Date/Time (UTC)"      = $event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        "Evidence Source"      = "$source - EID $($event.Id)"
        "Activity Description" = $desc
        "Details/Comments"     = if ($sessionId) { "Session ID: $sessionId" } else { "" }
        "User"                 = $usernameOnly
    }
}

function Parse-131 {
    param ($event)

    $msg = $event.Message
    $ip = ""

    if ($msg -match "client\s+\[?([0-9a-fA-F\.:]+)\]?:\d+") {
        $ip = $matches[1]
    }

    return [PSCustomObject]@{
        "Status/Tag"           = ""
        "System Name"          = ($event.MachineName -split '\.')[0]
        "Date/Time (UTC)"      = $event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        "Evidence Source"      = "RdpCoreTS - EID 131"
        "Activity Description" = "The server accepted a new connection from client $ip"
        "Details/Comments"     = ""
        "User"                 = ""
    }
}

$allowedLogFiles = @(
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx"
#    "Security.evtx"
)

$relevantLogs = Get-ChildItem -Path $p -Filter *.evtx | Where-Object {
    $allowedLogFiles -contains $_.Name
}
foreach ($log in $relevantLogs) {
    $path = $log.FullName
    $name = $log.BaseName -split "%4" | Select-Object -First 1
    Write-Host "Processing: $($log.Name)"
    try {
        $events = Get-WinEvent -Path $path -ErrorAction Stop

        foreach ($event in $events) {
            $parsed = $null

#            if ($name -eq "Security" -and $event.Id -eq 4624) {
#                $parsed = Parse-4624 $event
#            }
#if ($name -eq "Security") {
#    try {
 #       $events = Get-WinEvent -FilterHashtable @{Path=$path; Id=4624} -ErrorAction Stop
  #  } catch {
   #     Write-Warning "Failed to read Security log: $($_.Exception.Message)"
    #    continue
    #}

    #foreach ($event in $events) {
     #   $parsed = Parse-4624 $event
      #  if ($parsed) { $allEvents += $parsed }
    #}

    #continue  
#}
            if ($name -eq "Microsoft-Windows-TerminalServices-LocalSessionManager" -and $event.Id -in 21, 23, 24) {
                $parsed = Parse-RDP $event "LocalSessionManager"
            }
            elseif ($name -eq "Microsoft-Windows-TerminalServices-RemoteConnectionManager" -and $event.Id -eq 1149) {
                $parsed = Parse-RDP $event "RemoteConnectionManager"
            }
            elseif ($name -eq "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS" -and $event.Id -eq 131) {
                $parsed = Parse-131 $event
            }

            if ($parsed) {
                $allEvents += $parsed
            }
        }
    } catch {
        Write-Warning "Failed to process $($log.Name): $_"
    }
}

$machineForFilename = "UnknownMachine"
if ($allEvents.Count -gt 0 -and $allEvents[0]."System Name") {
    $machineForFilename = $allEvents[0]."System Name"
}

$outputPath = Join-Path $PSScriptRoot ("{0}_Parsed_Connection_Events.csv" -f $machineForFilename)
$allEvents | Sort-Object "Date/Time (UTC)" | Export-Csv -Path $outputPath -NoTypeInformation
Write-Host "`nExported to $outputPath"