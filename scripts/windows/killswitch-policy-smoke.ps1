# killswitch-policy-smoke.ps1 - prove, on a real Windows host, that the policy
# the engine installs actually controls egress, and that it keeps controlling it.
#
# Why this exists: the Windows killswitch rests on documented Windows Firewall
# behaviours, and none of them can be observed from a unit test on a host that is
# not Windows:
#
#   1. an explicitly defined Allow rule outranks the profile DEFAULT block
#      setting, so "DefaultOutboundAction = Block" alone does NOT stop an
#      application that already has an Allow rule;
#   2. an explicit Block rule outranks every conflicting Allow rule, INCLUDING one
#      created later, which is what keeps the policy binding for the whole
#      session;
#   3. an Allow rule carrying -OverrideBlockRules is permitted even where that
#      Block rule matches, which is how the tunnel, the daemon carrier and the
#      optional LAN and DHCP flows survive it.
#
# Step 3 is the one this repository cannot settle by itself. Microsoft documents
# -OverrideBlockRules as an outbound "allow bypass rule" from Windows 7 on, and
# the Windows Filtering Platform mechanism behind it is the hard permit, but the
# same page states earlier that such traffic "must be authenticated by using a
# separate IPsec rule". This script decides the question with real traffic, so run
# it BEFORE shipping the Windows killswitch to a fleet, and re-run it after any
# change to the rule set.
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
    # A destination reachable from a normal Windows host. The test only needs a
    # TCP handshake, so any public address and port will do.
    [string]$ProbeAddress = '1.1.1.1',
    [int]$ProbePort = 443
)

$ErrorActionPreference = 'Stop'

$Prefix = 'warren-smoke-'
$Results = New-Object System.Collections.Generic.List[object]

function Assert-Result {
    param([string]$Name, [bool]$Condition, [string]$Detail, [switch]$Skipped)
    $state = if ($Skipped) { 'SKIP' } elseif ($Condition) { 'PASS' } else { 'FAIL' }
    $Results.Add([pscustomobject]@{
        Name    = $Name
        Passed  = ($Condition -or $Skipped)
        Skipped = [bool]$Skipped
        Detail  = $Detail
    })
    Write-Host ("[{0}] {1} - {2}" -f $state, $Name, $Detail)
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

function Remove-SmokeRule {
    param([string]$Name)
    Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

function New-ProbeAllowRule {
    param([string]$Name, [string]$Program, [switch]$Override)
    $arguments = @{
        DisplayName   = $Name
        Direction     = 'Outbound'
        Action        = 'Allow'
        Protocol      = 'TCP'
        RemoteAddress = $ProbeAddress
        RemotePort    = $ProbePort
    }
    if ($Program) { $arguments['Program'] = $Program }
    if ($Override) { $arguments['OverrideBlockRules'] = $true }
    New-NetFirewallRule @arguments | Out-Null
}

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'This smoke test needs an elevated PowerShell (Run as administrator).'
    exit 2
}

$self = (Get-Process -Id $PID).Path
$preexisting = "${Prefix}preexisting-allow"
$block = "${Prefix}block-outbound"
$exception = "${Prefix}override-allow"
$later = "${Prefix}later-allow"
$readback = "${Prefix}readback-allow"

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
    Remove-SmokeRules

    # A pre-existing explicit Allow rule, the shape a user's "Allow" answer to a
    # firewall prompt leaves behind. It exists BEFORE the killswitch policy.
    New-ProbeAllowRule -Name $preexisting
    Assert-Result 'baseline egress works' (Test-Egress) `
        "TCP $ProbeAddress`:$ProbePort reaches the destination with an allow rule"

    # Step 1: the profile default only. The defect: an explicit allow rule
    # outranks the default block, so the application keeps its egress.
    Set-NetFirewallProfile -Profile ($Profiles -join ',') -DefaultOutboundAction Block
    Start-Sleep -Seconds 2
    Assert-Result 'the default block does not outrank a pre-existing allow rule' (Test-Egress) `
        'reproduces the leak the explicit block rule closes'

    # Step 2: the persistent mechanism. An explicit Block rule outranks the
    # conflicting allow rule.
    New-NetFirewallRule -DisplayName $block -Direction Outbound -Action Block | Out-Null
    Start-Sleep -Seconds 2
    Assert-Result 'the explicit block rule stops the pre-existing allow rule' `
        (-not (Test-Egress)) 'the application can no longer egress the physical interface'

    # Step 3: the exception mechanism. An Allow rule carrying OverrideBlockRules is
    # permitted even where the block rule matches; this is the step that decides
    # whether the tunnel and the carrier can survive the block on this build.
    New-ProbeAllowRule -Name $exception -Program $self -Override
    Start-Sleep -Seconds 2
    Assert-Result 'an OverrideBlockRules allow survives the block rule' (Test-Egress) `
        "the exception scoped to $self reaches the destination"

    # Step 4: persistence. With the exception removed, a rule created AFTER the
    # install (no override) must NOT reopen the egress: this is the property the
    # disable-at-install step alone cannot give.
    Remove-SmokeRule -Name $exception
    New-ProbeAllowRule -Name $later
    Start-Sleep -Seconds 2
    Assert-Result 'a rule created after the install cannot reopen the egress' `
        (-not (Test-Egress)) 'the block rule outranks an allow rule added later'
    Remove-SmokeRule -Name $later

    # Step 5: the read-back surface the engine's verification depends on. A
    # property name or a filter cmdlet that behaves differently on this host makes
    # the engine refuse an install it cannot confirm, so it is worth confirming
    # here rather than discovering it in production.
    $adapter = (Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1).Name
    $arguments = @{
        DisplayName   = $readback
        Direction     = 'Outbound'
        Action        = 'Allow'
        Protocol      = 'TCP'
        RemoteAddress = $ProbeAddress
        RemotePort    = $ProbePort
        Program       = $self
    }
    if ($adapter) { $arguments['InterfaceAlias'] = $adapter }
    New-NetFirewallRule @arguments -OverrideBlockRules $true | Out-Null
    Start-Sleep -Seconds 2

    $rule = Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName $readback
    $security = $rule | Get-NetFirewallSecurityFilter
    $app = $rule | Get-NetFirewallApplicationFilter
    $port = $rule | Get-NetFirewallPortFilter
    $addr = $rule | Get-NetFirewallAddressFilter
    Assert-Result '-OverrideBlockRules reads back from the active policy' `
        ($security.OverrideBlockRules -eq $true) "reported: $($security.OverrideBlockRules)"
    Assert-Result '-Program reads back from the active policy' ($app.Program -eq $self) `
        "reported: $($app.Program)"
    Assert-Result '-Protocol and -RemotePort read back' `
        (($port.Protocol -eq 'TCP') -and ("$($port.RemotePort)" -eq "$ProbePort")) `
        "reported: $($port.Protocol) / $($port.RemotePort)"
    Assert-Result '-RemoteAddress reads back' ("$($addr.RemoteAddress)" -eq $ProbeAddress) `
        "reported: $($addr.RemoteAddress)"
    if ($adapter) {
        $iface = $rule | Get-NetFirewallInterfaceFilter
        Assert-Result '-InterfaceAlias reads back' ("$($iface.InterfaceAlias)" -eq $adapter) `
            "reported: $($iface.InterfaceAlias)"
    }
    else {
        Assert-Result '-InterfaceAlias reads back' $true 'no active adapter to scope a rule to' -Skipped
    }

    $effective = Get-NetFirewallProfile -PolicyStore ActiveStore -Profile Domain,Private,Public |
        Format-List Name, Enabled, DefaultOutboundAction, AllowLocalFirewallRules | Out-String
    Assert-Result 'the effective profile read exposes the fields the engine parses' `
        (($effective -match 'AllowLocalFirewallRules') -and ($effective -match 'DefaultOutboundAction')) `
        'the engine refuses an install whose effective policy it cannot read'

    # Step 6: the categorical query. The engine also disables the operator's own
    # allow rules, and refuses the install while one of them remains enabled.
    $foreign = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound `
        -Action Allow -Enabled True |
        Where-Object { $_.DisplayName -notlike 'warren-killswitch-*' })
    Assert-Result 'the foreign-allow query sees an enabled allow rule' `
        ([bool]($foreign | Where-Object { $_.DisplayName -eq $readback })) `
        "$($foreign.Count) enabled outbound allow rule(s) visible to the engine's check"

    $readbackName = (Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName $readback).Name
    Disable-NetFirewallRule -Name $readbackName
    Start-Sleep -Seconds 2
    $foreign = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound `
        -Action Allow -Enabled True |
        Where-Object { $_.DisplayName -notlike 'warren-killswitch-*' })
    Assert-Result 'a disabled allow rule drops out of the query' `
        (-not [bool]($foreign | Where-Object { $_.DisplayName -eq $readback })) `
        'the engine establishes its policy only when no such rule remains'
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
Write-Host ("{0} step(s) passed, {1} skipped, {2} failed." -f `
    (@($Results | Where-Object { -not $_.Skipped -and $_.Passed }).Count), `
    (@($Results | Where-Object { $_.Skipped }).Count), `
    $failed.Count)
if ($failed.Count -gt 0) {
    Write-Host 'A failing step means the documented mechanism does not hold on this host:'
    $failed | ForEach-Object { Write-Host ("  - {0}: {1}" -f $_.Name, $_.Detail) }
    exit 1
}
exit 0
