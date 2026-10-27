$ErrorActionPreference = "Stop"

Set-Location -LiteralPath $PSScriptRoot

$venvDirectory = Join-Path $PSScriptRoot ".venv"
$venvPython = Join-Path $venvDirectory "Scripts\python.exe"
$dependencyStateFile = Join-Path $venvDirectory ".emudhra-dependencies.sha256"

function Test-PythonVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [string[]]$PrefixArguments = @()
    )

    & $Executable @PrefixArguments -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)"
    return $LASTEXITCODE -eq 0
}

if (Test-Path -LiteralPath $venvPython -PathType Leaf) {
    if (-not (Test-PythonVersion -Executable $venvPython)) {
        throw "The existing .venv does not use Python 3.12 or newer."
    }
}
elseif (Test-Path -LiteralPath $venvDirectory) {
    throw ".venv exists but is not a usable Windows virtual environment."
}
else {
    $pythonExecutable = $null
    $pythonPrefixArguments = @()

    if (Get-Command py -ErrorAction SilentlyContinue) {
        if (Test-PythonVersion -Executable "py" -PrefixArguments @("-3")) {
            $pythonExecutable = "py"
            $pythonPrefixArguments = @("-3")
        }
    }

    $fallbackPythonAvailable = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonExecutable -and $fallbackPythonAvailable -and (Test-PythonVersion -Executable "python")) {
        $pythonExecutable = "python"
    }

    if (-not $pythonExecutable) {
        throw "Python 3.12 or newer was not found."
    }

    Write-Host "[1/3] Creating the virtual environment..."
    & $pythonExecutable @pythonPrefixArguments -m venv $venvDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create the virtual environment."
    }
}

$pythonRuntimeId = (
    & $venvPython -c "import sys; print(f'{sys.implementation.name}:{sys.version_info.major}.{sys.version_info.minor}')"
).Trim()
$pyprojectHash = (
    Get-FileHash -LiteralPath (Join-Path $PSScriptRoot "pyproject.toml") -Algorithm SHA256
).Hash
$dependencyState = "$pyprojectHash`n$pythonRuntimeId"

$dependenciesAreCurrent = $false
if (Test-Path -LiteralPath $dependencyStateFile -PathType Leaf) {
    $cachedDependencyState = (
        Get-Content -LiteralPath $dependencyStateFile -Raw
    ).Trim()
    $dependenciesAreCurrent = $cachedDependencyState -eq $dependencyState
}

if ($dependenciesAreCurrent) {
    Write-Host "[2/3] Dependencies are up to date."
}
else {
    Write-Host "[2/3] Installing dependencies..."
    & $venvPython -m pip install -e ".[android]"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install dependencies."
    }
    Set-Content -LiteralPath $dependencyStateFile -Value $dependencyState -Encoding ASCII
}

Write-Host "[3/3] Starting eMudhra MITM..."
& $venvPython main.py
exit $LASTEXITCODE
