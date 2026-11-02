param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("enable", "disable")]
    [string]$Action,
    [int]$TransparentPort = 0,
    [string]$HotspotClientNetwork = ""
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$bridgeRuleName = "eMudhra MITM transparent bridge"
$quicRuleName = "eMudhra MITM QUIC block"

function Write-Result {
    param([hashtable]$Result)

    [Console]::WriteLine(($Result | ConvertTo-Json -Compress))
}

try {
    Remove-NetFirewallRule `
        -DisplayName $bridgeRuleName `
        -ErrorAction SilentlyContinue
    Remove-NetFirewallRule `
        -DisplayName $quicRuleName `
        -ErrorAction SilentlyContinue

    if ($Action -eq "enable") {
        if ($TransparentPort -lt 1 -or $TransparentPort -gt 65535) {
            throw "Transparent port is invalid."
        }
        if (-not [System.Net.IPAddress]::TryParse(
            ($HotspotClientNetwork -split '/')[0],
            [ref] $null
        )) {
            throw "Hotspot client network is invalid."
        }
        New-NetFirewallRule `
            -DisplayName $bridgeRuleName `
            -Direction Inbound `
            -Action Allow `
            -Protocol TCP `
            -LocalPort $TransparentPort `
            -Profile Any `
            | Out-Null
        New-NetFirewallRule `
            -DisplayName $quicRuleName `
            -Direction Outbound `
            -Action Block `
            -Protocol UDP `
            -RemotePort 443 `
            -RemoteAddress $HotspotClientNetwork `
            -Profile Any `
            | Out-Null
    }

    Write-Result @{
        ok = $true
        action = $Action
    }
}
catch {
    Write-Result @{
        ok = $false
        message = $_.Exception.Message
    }
}
