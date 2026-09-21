param(
    [Parameter(Position = 0)]
    [ValidateSet('start', 'stop', 'status')]
    [string]$Action = 'status'
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$workerPath = Join-Path $projectRoot 'python\wazuh_live.py'
$dataPath = Join-Path $projectRoot 'data'
$pidPath = Join-Path $dataPath 'wazuh-live.pid'

function Get-WatchuProcess {
    if (-not (Test-Path -LiteralPath $pidPath)) { return $null }
    $saved = Get-Content -LiteralPath $pidPath -Raw | ConvertFrom-Json
    $processId = [int]$saved.pid
    if (-not $saved.startTicks) { return $null }
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if (-not $process) { return $null }
    if ($process.StartTime.ToUniversalTime().Ticks -ne [long]$saved.startTicks -or $process.ProcessName -notlike 'python*') { return $null }
    return $process
}

if ($Action -eq 'status') {
    $running = Get-WatchuProcess
    if ($running) { Write-Output "Wazuh live berjalan (PID $($running.ProcessId))." }
    else { Write-Output 'Wazuh live tidak berjalan.' }
    exit 0
}

if ($Action -eq 'stop') {
    $running = Get-WatchuProcess
    if (-not $running) {
        Write-Output 'Wazuh live sudah berhenti.'
    } else {
        Stop-Process -Id $running.ProcessId -ErrorAction Stop
        Write-Output 'Wazuh live dihentikan.'
    }
    if (Test-Path -LiteralPath $pidPath) { Remove-Item -LiteralPath $pidPath -Force }
    exit 0
}

if (Get-WatchuProcess) {
    Write-Output 'Wazuh live sudah berjalan.'
    exit 0
}

$envPath = Join-Path $projectRoot '.env'
$pythonBinary = 'python'
if (Test-Path -LiteralPath $envPath) {
    $line = Get-Content -LiteralPath $envPath | Where-Object { $_ -match '^PYTHON_BINARY=' } | Select-Object -Last 1
    if ($line) {
        $candidate = ($line -split '=', 2)[1].Trim().Trim('"', "'")
        if ($candidate) { $pythonBinary = $candidate }
    }
}
$pythonCommand = Get-Command -Name $pythonBinary -ErrorAction SilentlyContinue
if (-not $pythonCommand) {
    throw 'Python tidak dijumpai. Pasang Python atau isi PYTHON_BINARY dengan path penuh python.exe dalam .env.'
}
if (-not (Test-Path -LiteralPath $dataPath)) { New-Item -ItemType Directory -Path $dataPath | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outputPath = Join-Path $dataPath "wazuh-live-$stamp.log"
$errorPath = Join-Path $dataPath "wazuh-live-$stamp.err.log"
$worker = Start-Process -FilePath $pythonCommand.Source -ArgumentList @('-u', "`"$workerPath`"") -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput $outputPath -RedirectStandardError $errorPath -PassThru
@{ pid = $worker.Id; startTicks = $worker.StartTime.ToUniversalTime().Ticks } | ConvertTo-Json | Set-Content -LiteralPath $pidPath -Encoding UTF8
Start-Sleep -Milliseconds 700
if (-not (Get-WatchuProcess)) {
    Remove-Item -LiteralPath $pidPath -Force
    throw "Proses terhenti selepas mula. Semak log ralat: $errorPath"
}
Write-Output "Wazuh live dimulakan (PID $($worker.Id)). Log: $outputPath"
