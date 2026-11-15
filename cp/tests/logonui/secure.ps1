# Runs as LocalSystem on the Winlogon (secure) desktop of the runner's console session, started by
# PsExec -s -i <session> -x. Executes a small action list against the real LogonUI:
#   shot <name>        save a screenshot
#   space              press the space bar
#   keys <sendkeys>    send keystrokes ({TAB}, {ENTER} ...)
#   type <text>        send literal text
#   click <x> <y>      left-click at screen coordinates
#   sleep <seconds>
#   waitunlock <sec>   wait until LogonUI is gone (session unlocked) or the timeout passes
param([string]$Round, [string]$ActionsFile, [string]$OutDir)
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class FhNative {
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extra);
}
"@
$log = Join-Path $OutDir 'secure.log'
function Log([string]$m) { Add-Content $log ("[{0}] {1} {2}" -f $Round, (Get-Date -Format 'HH:mm:ss'), $m) }
function Shot([string]$name) {
    try {
        $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
        $bmp.Save((Join-Path $OutDir "$Round-$name.png")); $g.Dispose(); $bmp.Dispose()
        Log "shot $name"
    } catch { Log "shot $name FAILED: $($_.Exception.Message)" }
}
function LogonUiRunning { [bool](Get-Process LogonUI -ErrorAction SilentlyContinue) }

Log "helper start as $([Security.Principal.WindowsIdentity]::GetCurrent().Name), LogonUI running=$(LogonUiRunning)"
foreach ($line in (Get-Content $ActionsFile)) {
    $line = $line.Trim()
    if (-not $line) { continue }
    $verb, $rest = $line -split ' ', 2
    switch ($verb) {
        'shot'  { Shot $rest }
        'sleep' { Start-Sleep -Seconds ([double]$rest) }
        'space' { try { [System.Windows.Forms.SendKeys]::SendWait(' '); Log 'space' } catch { Log "space FAILED: $($_.Exception.Message)" } }
        'keys'  { try { [System.Windows.Forms.SendKeys]::SendWait($rest); Log "keys $rest" } catch { Log "keys FAILED: $($_.Exception.Message)" } }
        'type'  { try { [System.Windows.Forms.SendKeys]::SendWait($rest); Log 'type <text>' } catch { Log "type FAILED: $($_.Exception.Message)" } }
        'click' {
            $x, $y = $rest -split ' '
            [void][FhNative]::SetCursorPos([int]$x, [int]$y); Start-Sleep -Milliseconds 150
            [FhNative]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 60
            [FhNative]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
            Log "click $x $y"
        }
        'waitunlock' {
            $deadline = (Get-Date).AddSeconds([double]$rest)
            while ((LogonUiRunning) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
            Log "waitunlock: unlocked=$(-not (LogonUiRunning))"
        }
        default { Log "unknown action: $line" }
    }
}
Log "helper done, LogonUI running=$(LogonUiRunning)"
