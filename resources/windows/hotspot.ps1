param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("start", "stop", "status")]
    [string]$Action,
    [string]$Ssid = "",
    [string]$Password = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Write-Result {
    param([hashtable]$Result)

    Write-Output ($Result | ConvertTo-Json -Depth 5 -Compress)
}

function Await-Operation {
    param(
        [Parameter(Mandatory = $true)]
        $Operation,
        [Parameter(Mandatory = $true)]
        [Type]$ResultType
    )

    $asTaskMethod = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq "AsTask" `
            -and $_.IsGenericMethod `
            -and $_.GetGenericArguments().Count -eq 1 `
            -and $_.GetParameters().Count -eq 1
    } | Select-Object -First 1

    $task = $asTaskMethod.MakeGenericMethod($ResultType).Invoke(
        $null,
        @($Operation)
    )
    if (-not $task.Wait(25000)) {
        $Operation.Cancel()
        throw "Windows hotspot operation timed out."
    }
    return $task.Result
}

function Await-Action {
    param(
        [Parameter(Mandatory = $true)]
        $Operation
    )

    $asTaskMethod = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq "AsTask" `
            -and -not $_.IsGenericMethod `
            -and $_.GetParameters().Count -eq 1
    } | Select-Object -First 1

    $task = $asTaskMethod.Invoke($null, @($Operation))
    if (-not $task.Wait(15000)) {
        $Operation.Cancel()
        throw "Windows hotspot configuration timed out."
    }
    $task.GetAwaiter().GetResult()
}

try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime] | Out-Null
    [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime] | Out-Null
    [Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime] | Out-Null

    $connectionProfile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
    if ($null -eq $connectionProfile) {
        throw "No internet connection is available to share."
    }

    $capability = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::GetTetheringCapabilityFromConnectionProfile($connectionProfile)
    if ("$capability" -ne "Enabled") {
        throw "Windows mobile hotspot is not available: $capability"
    }

    $manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($connectionProfile)

    if ($Action -eq "start") {
        if ($Ssid -or $Password) {
            try {
                $accessPoint = $manager.GetCurrentAccessPointConfiguration()
            }
            catch {
                $accessPoint = New-Object `
                    -TypeName Windows.Networking.NetworkOperators.NetworkOperatorTetheringAccessPointConfiguration
            }
            if ($Ssid) {
                $accessPoint.Ssid = $Ssid
            }
            if ($Password) {
                $accessPoint.Passphrase = $Password
            }
            Await-Action ($manager.ConfigureAccessPointAsync($accessPoint))
        }

        if ("$($manager.TetheringOperationalState)" -ne "On") {
            $operationResult = Await-Operation `
                ($manager.StartTetheringAsync()) `
                ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
            if ("$($operationResult.Status)" -ne "Success") {
                throw "$($operationResult.Status) $($operationResult.AdditionalErrorMessage)"
            }
        }
    }
    elseif ($Action -eq "stop") {
        if ("$($manager.TetheringOperationalState)" -ne "Off") {
            $operationResult = Await-Operation `
                ($manager.StopTetheringAsync()) `
                ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
            if ("$($operationResult.Status)" -ne "Success") {
                throw "$($operationResult.Status) $($operationResult.AdditionalErrorMessage)"
            }
        }
    }

    $accessPoint = $null
    try {
        $accessPoint = $manager.GetCurrentAccessPointConfiguration()
    }
    catch {
        # Some adapters do not expose an access point profile until the radio is ready.
    }
    $gateway = $null
    $gatewayAttempts = if ("$($manager.TetheringOperationalState)" -eq "On") {
        40
    } else {
        1
    }
    for ($attempt = 0; $attempt -lt $gatewayAttempts; $attempt++) {
        $gateway = Get-NetIPAddress `
            -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue `
            | Where-Object { $_.IPAddress -eq "192.168.137.1" } `
            | Select-Object -First 1
        if ($null -ne $gateway) {
            break
        }
        Start-Sleep -Milliseconds 250
    }
    $gatewayAdapter = if ($null -ne $gateway) {
        Get-NetAdapter `
            -InterfaceIndex $gateway.InterfaceIndex `
            -ErrorAction SilentlyContinue
    }
    $clientDevices = @()
    if ($null -ne $gateway) {
        $clientDevices = @(
            Get-NetNeighbor `
                -InterfaceIndex $gateway.InterfaceIndex `
                -AddressFamily IPv4 `
                -ErrorAction SilentlyContinue `
                | Where-Object {
                    $_.IPAddress -like "192.168.137.*" `
                        -and $_.IPAddress -ne $gateway.IPAddress `
                        -and $_.IPAddress -notlike "*.255" `
                        -and $_.LinkLayerAddress `
                        -and $_.LinkLayerAddress -notmatch "^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF)$" `
                        -and $_.State -in @(
                            "Reachable",
                            "Stale",
                            "Delay",
                            "Probe",
                            "Permanent"
                        )
                } `
                | Sort-Object IPAddress `
                | ForEach-Object {
                    @{
                        ip_address = [string]$_.IPAddress
                        mac_address = [string]$_.LinkLayerAddress
                        state = [string]$_.State
                    }
                }
        )
    }

    Write-Result @{
        ok = $true
        state = "$($manager.TetheringOperationalState)"
        ssid = if ($null -ne $accessPoint) { [string]$accessPoint.Ssid } else { "" }
        clients = [int]$manager.ClientCount
        max_clients = [int]$manager.MaxClientCount
        gateway = if ($null -ne $gateway) { [string]$gateway.IPAddress } else { "" }
        prefix_length = if ($null -ne $gateway) { [int]$gateway.PrefixLength } else { 0 }
        interface_name = if ($null -ne $gateway) { [string]$gateway.InterfaceAlias } else { "" }
        interface_guid = if ($null -ne $gatewayAdapter) {
            [string]$gatewayAdapter.InterfaceGuid
        } else {
            ""
        }
        interface_ifindex = if ($null -ne $gateway) { [int]$gateway.InterfaceIndex } else { 0 }
        devices = @($clientDevices)
    }
}
catch {
    Write-Result @{
        ok = $false
        state = "Unknown"
        message = $_.Exception.Message
    }
}
