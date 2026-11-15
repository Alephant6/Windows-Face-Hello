# Runs cp/tests/harness.exe as LocalSystem next to the mock pipe service (also LocalSystem) on a CI
# runner, and fails if any check fails. The provider only talks to a LocalSystem pipe server and only
# LocalSystem can read its LSA secret, hence the scheduled task.
param([string]$Dll, [string]$Harness)
$ErrorActionPreference = 'Stop'
$work = 'C:\fh-test'
New-Item -ItemType Directory -Force $work | Out-Null
Copy-Item $Dll "$work\FaceHelloCP.dll" -Force
Copy-Item $Harness "$work\harness.exe" -Force
Copy-Item "$PSScriptRoot\mock_service.py" $work -Force
New-Item -ItemType Directory -Force 'C:\ProgramData\FaceHello' | Out-Null
Set-Content 'C:\ProgramData\FaceHello\lang.txt' 'en' -Encoding ascii -NoNewline
$py = (Get-Command python).Source
$user = $env:USERNAME
$sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
Write-Host "runner account: $user"

# Test-only LSA secret for the runner account. The harness only checks that a credential blob is
# produced; nothing is ever submitted to a real logon.
$code = "import sys, win32security; pol = win32security.LsaOpenPolicy(None, win32security.POLICY_CREATE_SECRET); win32security.LsaStorePrivateData(pol, 'L`$FaceHello_' + sys.argv[1], 'harness-only-not-a-real-password'); win32security.LsaClose(pol); print('lsa secret stored')"
& $py -c $code $user
if ($LASTEXITCODE -ne 0) { throw 'could not store the test LSA secret' }

Set-Content "$work\run.cmd" @(
    '@echo off',
    "start `"`" /b `"$py`" $work\mock_service.py",
    'ping -n 4 127.0.0.1 >nul',
    "$work\harness.exe $work\FaceHelloCP.dll $sid $user $work\harness.log > $work\harness.out 2>&1",
    "echo %ERRORLEVEL% > $work\exitcode.txt",
    'taskkill /f /im python.exe >nul 2>&1',
    "echo done > $work\done.txt"
) -Encoding ascii

schtasks /create /tn fh-harness /ru SYSTEM /sc once /st 00:00 /rl highest /f /tr "$work\run.cmd" | Out-Host
schtasks /run /tn fh-harness | Out-Host
$deadline = (Get-Date).AddMinutes(4)
while (-not (Test-Path "$work\done.txt") -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 3 }

Write-Host '===== harness log ====='
if (Test-Path "$work\harness.log") { Get-Content "$work\harness.log" } else { Write-Host '(no harness.log)' }
Write-Host '===== mock service log ====='
if (Test-Path 'C:\Users\Public\mock-service.log') { Get-Content 'C:\Users\Public\mock-service.log' -Tail 40 }
if (-not (Test-Path "$work\done.txt")) { throw 'harness did not finish within 4 minutes' }
$exit = (Get-Content "$work\exitcode.txt" -Raw).Trim()
if ($exit -ne '0') { throw "harness failed (exit $exit)" }
