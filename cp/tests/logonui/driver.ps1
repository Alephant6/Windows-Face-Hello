# Tests the Credential Provider against the real LogonUI of a hosted Windows runner.
# The runner job runs in an interactive console session, so it can lock the workstation; a LocalSystem
# helper (secure.ps1, started on the Winlogon desktop with PsExec) takes screenshots and sends input.
# The face service is replaced by cp/tests/mock_service.py, which always "recognizes" mock-user.txt.
param([string]$Dll, [string]$RoundsFile)
$ErrorActionPreference = 'Stop'
$work = 'C:\fh-ui'; $out = "$work\out"
New-Item -ItemType Directory -Force $out | Out-Null
Copy-Item $Dll "$work\FaceHelloCP.dll" -Force
Copy-Item "$PSScriptRoot\secure.ps1", "$PSScriptRoot\..\mock_service.py" $work -Force
$user = $env:USERNAME
$sessionId = (Get-Process -Id $PID).SessionId
$py = (Get-Command python).Source
function Say([string]$m) { $l = "{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $m; Write-Host $l; Add-Content "$out\driver.log" $l }

# --- environment ---
New-Item -ItemType Directory -Force 'C:\ProgramData\FaceHello' | Out-Null
Set-Content 'C:\ProgramData\FaceHello\lang.txt' 'en' -Encoding ascii -NoNewline
# Known throwaway password for the ephemeral runner account, also stored as the provider's LSA secret,
# so a "recognized" face really unlocks the session.
$pw = 'Fh-' + [guid]::NewGuid().ToString('N').Substring(0, 16) + 'aA1'
net user $user $pw | Out-Null
$code = "import sys, win32security; pol = win32security.LsaOpenPolicy(None, win32security.POLICY_CREATE_SECRET); win32security.LsaStorePrivateData(pol, 'L`$FaceHello_' + sys.argv[1], sys.argv[2]); win32security.LsaClose(pol)"
& $py -c $code $user $pw
if ($LASTEXITCODE -ne 0) { throw 'could not store the LSA secret' }
# Lock screen without Ctrl+Alt+Del, like a client edition.
reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v DisableCAD /t REG_DWORD /d 1 /f | Out-Null
Set-Content "$work\mock.cmd" "@echo off`r`n`"$py`" $work\mock_service.py" -Encoding ascii
Set-Content 'C:\Users\Public\mock-user.txt' $user -Encoding ascii -NoNewline
schtasks /create /tn fh-mock /ru SYSTEM /sc once /st 00:00 /rl highest /f /tr "$work\mock.cmd" | Out-Null
schtasks /run /tn fh-mock | Out-Null
Invoke-WebRequest 'https://download.sysinternals.com/files/PSTools.zip' -OutFile "$work\PSTools.zip" -UseBasicParsing
Expand-Archive "$work\PSTools.zip" "$work\pstools" -Force
$psexec = "$work\pstools\PsExec64.exe"

function LogonUiRunning { [bool](Get-Process LogonUI -ErrorAction SilentlyContinue) }
function Invoke-AsSystem([string]$command) {
    & $psexec -accepteula -nobanner -s powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $command 2>&1 | Out-Null
}
function Invoke-Secure([string]$round, [string[]]$actions) {
    $af = "$work\actions-$round.txt"
    Set-Content $af $actions -Encoding ascii
    & $psexec -accepteula -nobanner -s -i $sessionId -x powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "$work\secure.ps1" -Round $round -ActionsFile $af -OutDir $out 2>&1 | Out-Null
}

$registered = $false
$results = @()
foreach ($r in (Get-Content $RoundsFile -Raw | ConvertFrom-Json)) {
    Say "=== round $($r.name): register=$($r.register) autostart=$($r.autostart) mockUser=$($r.mockUser)"
    if ($r.register -and -not $registered) {
        regsvr32.exe /s "$work\FaceHelloCP.dll"; Start-Sleep -Seconds 2
        $registered = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{E071A7CE-5D7F-4063-9A10-AE39AEC64EE8}'
        Say "provider registered: $registered"
    }
    $mockUser = if ($r.mockUser) { $r.mockUser } else { $user }
    Set-Content 'C:\Users\Public\mock-user.txt' $mockUser -Encoding ascii -NoNewline
    if ($r.autostart) { Set-Content 'C:\ProgramData\FaceHello\autostart.txt' '1' -Encoding ascii -NoNewline }
    else { Remove-Item 'C:\ProgramData\FaceHello\autostart.txt' -Force -ErrorAction SilentlyContinue }

    if (LogonUiRunning) {
        # Still locked from the previous round: restart LogonUI so it enumerates providers afresh.
        Invoke-AsSystem 'Stop-Process -Name LogonUI -Force'
        Start-Sleep -Seconds 6
    } else {
        rundll32.exe user32.dll,LockWorkStation
        Start-Sleep -Seconds 6
    }
    $lockedBefore = LogonUiRunning
    $actions = @($r.actions | ForEach-Object { $_ -replace '\{PASSWORD\}', $pw })
    Invoke-Secure $r.name $actions
    Start-Sleep -Seconds 2
    $unlocked = -not (LogonUiRunning)
    Say "round $($r.name): locked before=$lockedBefore, unlocked after=$unlocked (expected unlocked=$($r.expectUnlocked))"
    $results += [pscustomobject]@{ round = $r.name; locked_before = $lockedBefore; unlocked_after = $unlocked; expected_unlocked = $r.expectUnlocked }
}

$crashes = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000, 1002 } -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'LogonUI|FaceHello' } | ForEach-Object { '{0:u} {1}' -f $_.TimeCreated, (($_.Message -split "`n")[0..2] -join ' | ') })
Say "LogonUI / FaceHello crash events: $($crashes.Count)"
$crashes | ForEach-Object { Say "  $_" }
Say '--- mock service log'
Get-Content 'C:\Users\Public\mock-service.log' -Tail 60 -ErrorAction SilentlyContinue | ForEach-Object { Say "  $_" }
Say '--- secure helper log'
Get-Content "$out\secure.log" -ErrorAction SilentlyContinue | ForEach-Object { Say "  $_" }
$results | Format-Table -AutoSize | Out-String | Write-Host
$results | ConvertTo-Json | Set-Content "$out\results.json"

$bad = @($results | Where-Object { $null -ne $_.expected_unlocked -and $_.unlocked_after -ne $_.expected_unlocked })
if ($crashes.Count -gt 0) { throw "LogonUI crash events were recorded" }
if ($bad.Count -gt 0) { throw "rounds with an unexpected lock state: $(($bad | ForEach-Object round) -join ', ')" }
