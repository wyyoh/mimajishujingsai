param([Parameter(ValueFromRemainingArguments=$true)][string[]]$ProjectArgs)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$wslPath = Join-Path $env:SystemRoot 'System32/wsl.exe'
if ($ProjectArgs.Count -gt 0 -and $ProjectArgs[0] -eq 'start') {
  $serverArgs = @($ProjectArgs | Select-Object -Skip 1)
  if ($serverArgs.Count -gt 1 -or ($serverArgs.Count -eq 1 -and $serverArgs[0] -ne '--lab')) {
    Write-Error 'Usage: scripts/project.ps1 start [--lab]'
    exit 2
  }
  $wantLab = $serverArgs -contains '--lab'
  $current = (& $wslPath -d Ubuntu --cd $projectRoot --exec bash scripts/project status) | ConvertFrom-Json
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  if ($current.state -in @('RUNNING', 'STARTING')) {
    if ($current.lab -ne $wantLab) {
      Write-Error 'Server is already running in a different mode. Use stop before changing --lab.'
      exit 1
    }
    if ($current.state -eq 'RUNNING') {
      $current | ConvertTo-Json -Compress
      exit 0
    }
  } elseif ($current.state -ne 'STOPPED') {
    $current | ConvertTo-Json -Compress
    exit 1
  } else {
    # A foreground WSL command keeps the distribution alive after this launcher exits.
    # A Linux systemd service alone does not keep WSL alive.
    $hostArgs = @('-d', 'Ubuntu', '--cd', ('"' + $projectRoot + '"'), '--exec', 'bash', 'scripts/project', 'server-host') + $serverArgs
    $serverHost = Start-Process -FilePath $wslPath -ArgumentList $hostArgs -WindowStyle Hidden -PassThru
  }
  $deadline = (Get-Date).AddSeconds(30)
  do {
    Start-Sleep -Milliseconds 300
    $current = (& $wslPath -d Ubuntu --cd $projectRoot --exec bash scripts/project status) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if ($current.state -eq 'RUNNING') {
      if ($current.lab -ne $wantLab) {
        Write-Error 'Server started in a different mode; no mode was changed automatically.'
        exit 1
      }
      $current | ConvertTo-Json -Compress
      exit 0
    }
    if ($serverHost -and $serverHost.HasExited) { break }
  } while ((Get-Date) -lt $deadline)
  $current | ConvertTo-Json -Compress
  Write-Error ('Server did not become ready. Inspect the local log: ' + $current.log)
  exit 1
}
# Pass the Windows path directly; decoding wslpath output can corrupt Unicode in PS 5.1.
& $wslPath -d Ubuntu --cd $projectRoot --exec bash scripts/project @ProjectArgs
if ($LASTEXITCODE -eq 0 -and $ProjectArgs[0] -eq 'build') {
  Push-Location (Join-Path $projectRoot 'apps/web')
  try {
    & npm.cmd ci
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & npm.cmd run build
  } finally {
    Pop-Location
  }
}
exit $LASTEXITCODE
