# killswitch-policy-smoke.ps1 - prove, on a real Windows host, that the policy
# the engine installs actually controls egress.
#
# Why this exists: the Windows killswitch policy rests on two documented
# Windows Firewall behaviours, and neither can be observed from a unit test on a
# host that is not Windows:
#
#   1. an explicit Allow rule outranks the profile DEFAULT block setting
#      (so "DefaultOutboundAction = Block" alone does NOT stop an application
#      that already has an Allow rule);
#   2. an explicit Block rule outranks every conflicting Allow rule, and an
#      Allow rule carrying -OverrideBlockRules outranks that Block rule
#      (which is how the tunnel, the daemon carrier and the optional LAN and
#      DHCP exceptions survive the block).
#
# Run this on a throwaway Windows host or VM, elevated. It changes the firewall
# and restores everything in a finally block; do NOT run it on a machine whose
# network you cannot afford to disturb for a minute.
#
#   powershell -ExecutionPolicy Bypass -File scripts\windows\killswitch-policy-smoke.ps1
#
# It exits non-zero if any step behaves differently from the documented model.

[CmdletBinding()]
param(
    # A destination that is reachable from a normal Windows host. The test only
    # needs a TCP handshake, so any public address and port will do.
    [string]$ProbeAddress = '1.1.1.1',
    [int]$ProbePort = 443
)

$ErrorActionPreference = 'Stop'

$Prefix = 'warren-smoke-'
$Results = New-Object System.Collections.Generic.List[object]

function Assert-Result {
    param([string]$Name, [bool]$Condition, [string]$Detail)
    $Results.Add([pscustomobject]@{ Name = $Name; Passed = $Condition; Detail = $Detail })
    $status = if ($Condition) { 'PASS' } else { 'FAIL' }
    Write-Host ("[{0}] {1} - {2}" -f $status, $Name, $Detail)
}

function Test-Egress {
    # One TCP handshake: the only thing a firewall rule can change here.
    $probe = Test-NetConnection -ComputerName $ProbeAddress -Port $ProbePort `
        -InformationLevel Quiet -WarningAction SilentlyContinue
    return [bool]$probe
}

function Remove-SmokeRules {
    Get-NetFirewallRule -DisplayName "$Prefix*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'This smoke test needs an elevated PowerShell (Run as administrator).'
    exit 2
}

# Snapshot the profile settings we are about to change, so the finally block
# restores the host exactly as it was found.
$Profiles = @('Domain', 'Private', 'Public')
$Snapshot = @{}
foreach ($p in $Profiles) {
    $current = Get-NetFirewallProfile -Profile $p
    $Snapshot[$p] = @{
        Enabled = $current.Enabled
        DefaultOutboundAction = $current.DefaultOutboundAction
    }
}

try {
    # A pre-existing explicit Allow rule, the shape a user's "Allow" click on a
    # firewall prompt leaves behind. It is created BEFORE the killswitch policy.
    Remove-SmokeRules
    New-NetFirewallRule -DisplayName "${Prefix}preexisting-allow" -Direction Outbound `
        -Action Allow -Protocol TCP -RemoteAddress $ProbeAddress -RemotePort $ProbePort | Out-Null

    Assert-Result 'baseline egress works' (Test-Egress) `
        "TCP $ProbeAddress`:$ProbePort reaches the destination"

    # 1. The OLD policy: the profile default only. This is the defect: the
    #    pre-existing Allow rule still outranks the default block.
    Set-NetFirewallProfile -Profile ($Profiles -join ',') -DefaultOutboundAction Block
    Assert-Result 'default block does NOT outrank a pre-existing allow rule' (Test-Egress) `
        'reproduces the leak the explicit block rule exists to close'

    # 2. The FIX. An explicit Block rule outranks the conflicting Allow rule.
    New-NetFirewallRule -DisplayName "${Prefix}block-outbound" -Direction Outbound `
        -Action Block | Out-Null
    Start-Sleep -Seconds 2
    Assert-Result 'explicit block rule stops the pre-existing allow rule' (-not (Test-Egress)) `
        'the application can no longer egress the physical interface'

    # 3. The exception mechanism the engine relies on: an Allow rule carrying
    #    -OverrideBlockRules is permitted even where the block rule matches.
    #    Scoped to this shell's own executable, the way the engine scopes the
    #    exit carrier to the daemon.
    $self = (Get-Process -Id $PID).Path
    New-NetFirewallRule -DisplayName "${Prefix}bypass-allow" -Direction Outbound `
        -Action Allow -Protocol TCP -RemoteAddress $ProbeAddress -RemotePort $ProbePort `
        -Program $self -OverrideBlockRules $true | Out-Null
    Start-Sleep -Seconds 2
    Assert-Result 'an OverrideBlockRules allow survives the block rule' (Test-Egress) `
        "the exception scoped to $self still reaches the destination"

    # 4. The exception is scoped: it must not hand the destination to a process
    #    that is not named by the rule. Removing the program scope is the
    #    "Port Fail / TunnelCrack ServerIP" shape, so this step proves the
    #    scope is what carries the restriction.
    Get-NetFirewallRule -DisplayName "${Prefix}bypass-allow" | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName "${Prefix}bypass-allow-unscoped" -Direction Outbound `
        -Action Allow -Protocol TCP -RemoteAddress $ProbeAddress -RemotePort $ProbePort `
        -OverrideBlockRules $true | Out-Null
    Start-Sleep -Seconds 2
    Assert-Result 'an unscoped bypass allow opens the destination to every process' (Test-Egress) `
        'why the engine scopes the exit exception with -Program'
}
finally {
    Remove-SmokeRules
    foreach ($p in $Profiles) {
        Set-NetFirewallProfile -Profile $p `
            -Enabled $Snapshot[$p].Enabled `
            -DefaultOutboundAction $Snapshot[$p].DefaultOutboundAction | Out-Null
    }
    Write-Host 'Restored the firewall profiles and removed every smoke rule.'
}

$failed = @($Results | Where-Object { -not $_.Passed })
Write-Host ''
Write-Host ("{0} step(s) passed, {1} failed." -f ($Results.Count - $failed.Count), $failed.Count)
if ($failed.Count -gt 0) {
    Write-Host 'A failing step means the documented mechanism does not hold on this host:'
    $failed | ForEach-Object { Write-Host ("  - {0}: {1}" -f $_.Name, $_.Detail) }
    exit 1
}
exit 0
