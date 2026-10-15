<#
.SYNOPSIS
  Full TOCTOU sweep of all three configurations, then figures.

.DESCRIPTION
  The orchestration lives in sweep_all.py so there is one copy of it; this
  wrapper only locates an interpreter and decides foreground vs detached.

  Results land in results\<UTC timestamp>_<config>\ with figures alongside, and
  results\combined\ overlays every config swept in the run.

.PARAMETER Configs
  Which configurations to sweep. Defaults to all three.

.PARAMETER Detached
  Run in the background, surviving the console closing.

.PARAMETER SkipPreflight
  Skip the dependency and port checks.

.PARAMETER Trials
  Override the trials-per-delay count declared in attacker.py.

.PARAMETER Delays
  Override the delay list declared in attacker.py, in milliseconds.

.PARAMETER DryRun
  Run preflight, print the plan, and exit. Starts nothing, touches no
  containers, writes no results.

.EXAMPLE
  .\run_sweep.ps1 -DryRun
  Check the machine is ready and show what a real run would do.

.EXAMPLE
  .\run_sweep.ps1
  All three, in the foreground (~6 h).

.EXAMPLE
  .\run_sweep.ps1 -Detached
  Same, in the background.

.EXAMPLE
  .\run_sweep.ps1 -Configs Tight
  One config only.
#>
[CmdletBinding()]
param(
  [ValidateSet('BaseLine', 'Tight', 'Secure')]
  [string[]]$Configs,
  [switch]$Detached,
  [switch]$SkipPreflight,
  [ValidateRange(1, 100000)]
  [int]$Trials,
  [int[]]$Delays,
  [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$py = $null
foreach ($c in 'python', 'python3', 'py') {
  $cmd = Get-Command $c -ErrorAction SilentlyContinue
  if ($cmd) { $py = $cmd.Source; break }
}
if (-not $py) {
  [Console]::Error.WriteLine('no python interpreter on PATH')
  exit 2
}

$sweepArgs = @((Join-Path $root 'sweep_all.py'))
if ($Configs)       { $sweepArgs += '--configs'; $sweepArgs += $Configs }
if ($SkipPreflight) { $sweepArgs += '--skip-preflight' }
if ($Trials)        { $sweepArgs += '--trials'; $sweepArgs += "$Trials" }
if ($Delays)        { $sweepArgs += '--delays'; $sweepArgs += ($Delays -join ',') }
if ($DryRun)        { $sweepArgs += '--dry-run' }

if ($DryRun -and $Detached) {
  [Console]::Error.WriteLine('-DryRun and -Detached are mutually exclusive')
  exit 2
}

$results = Join-Path $root 'results'
if (-not (Test-Path $results)) { New-Item -ItemType Directory $results | Out-Null }

if ($Detached) {
  $p = Start-Process -FilePath $py -ArgumentList $sweepArgs `
    -WorkingDirectory $root `
    -RedirectStandardOutput (Join-Path $results 'sweep_stdout.log') `
    -RedirectStandardError  (Join-Path $results 'sweep_stderr.log') `
    -PassThru -WindowStyle Hidden
  "sweep detached as PID $($p.Id)"
  "  progress : Get-Content results\sweep_run.log -Wait"
  "  stop     : Stop-Process -Id $($p.Id)"
}
else {
  & $py @sweepArgs
  exit $LASTEXITCODE
}
