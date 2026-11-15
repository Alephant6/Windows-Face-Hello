# Runs as LocalSystem on the Winlogon (secure) desktop of the runner's console session, started by
# PsExec -s -i <session> -x. Executes a small action list against the real LogonUI:
#   shot <name>        save a screenshot
#   key <NAME>         press one key: SPACE TAB ENTER ESC UP DOWN LEFT RIGHT (prefix SHIFT+ for shift)
#   type <text>        type literal text
#   click <x> <y>      left-click at screen coordinates
#   sleep <seconds>
#   waitunlock <sec>   wait until LogonUI is gone (session unlocked) or the timeout passes
# Input is injected with keybd_event / mouse_event; SendKeys does not reach LogonUI from here.
param([string]$Round, [string]$ActionsFile, [string]$OutDir)
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class FhNative {
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extra);
    [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern short VkKeyScanW(char ch);
    public static void Press(byte vk, bool shift) {
        if (shift) keybd_event(0x10, 0, 0, UIntPtr.Zero);
        keybd_event(vk, 0, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(40);
        keybd_event(vk, 0, 2, UIntPtr.Zero);
        if (shift) keybd_event(0x10, 0, 2, UIntPtr.Zero);
        System.Threading.Thread.Sleep(40);
    }
}
"@
$vk = @{ SPACE = 0x20; TAB = 0x09; ENTER = 0x0D; ESC = 0x1B; UP = 0x26; DOWN = 0x28; LEFT = 0x25; RIGHT = 0x27 }
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
        'key'   {
            $shift = $rest -like 'SHIFT+*'
            $name = $rest -replace '^SHIFT\+', ''
            if ($vk.ContainsKey($name)) { [FhNative]::Press([byte]$vk[$name], $shift); Log "key $rest" } else { Log "unknown key $rest" }
        }
        'type'  {
            foreach ($ch in $rest.ToCharArray()) {
                $r = [FhNative]::VkKeyScanW($ch)
                [FhNative]::Press([byte]($r -band 0xFF), [bool](($r -shr 8) -band 1))
            }
            Log "type <$($rest.Length) chars>"
        }
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
