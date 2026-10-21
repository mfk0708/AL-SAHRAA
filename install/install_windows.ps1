<#
=====================================================================
 Contract Assessment Tools – Windows Server installer
 Windows Server 2016 / 2019 / 2022 / 2025 or Windows 10/11, 64-bit.
 Needs Python 3.11, 3.12 or 3.13 (64-bit) from python.org, installed
 "for all users". No internet needed when the offline bundle (wheels\windows-x64) is present.

 Run in PowerShell **as Administrator** from the package folder:
   powershell -ExecutionPolicy Bypass -File .\install\install_windows.ps1
 Options:
   -InstallDir  C:\ContractAssessmentTools   program folder
   -DataDir     C:\ContractAssessmentTools\data
   -Port        8000
   -DatabaseUrl "postgresql+psycopg://cat:PASSWORD@dbserver:5432/cat"   (default: SQLite)
   -NoSample    start with an empty database (production)
   -NoService   install only; do not register the startup task
 Re-running the installer upgrades the program and keeps settings and data.
=====================================================================
#>
param(
  [string]$InstallDir = 'C:\ContractAssessmentTools',
  [string]$DataDir = '',
  [int]$Port = 8000,
  [string]$DatabaseUrl = '',
  [switch]$NoSample,
  [switch]$NoService,
  [string]$Python = ''
)
$ErrorActionPreference = 'Stop'
$TaskName = 'Contract Assessment Tools'
function Say($m) { Write-Host "`n$m" -ForegroundColor Cyan }
$Src = Split-Path -Parent $PSScriptRoot
if (-not $DataDir) { $DataDir = Join-Path $InstallDir 'data' }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run this script in PowerShell opened with "Run as administrator".' }

Say '1/7  Checking Python'
$candidates = @()
if ($Python) { $candidates += ,@($Python) }
$candidates += ,@('py', '-3.13'); $candidates += ,@('py', '-3.12'); $candidates += ,@('py', '-3.11'); $candidates += ,@('python')
$py = $null
foreach ($c in $candidates) {
  try {
    $exe = & $c[0] @($c[1..($c.Length)] | Where-Object { $_ }) -c "import sys,struct;ok=(3,11)<=sys.version_info[:2]<=(3,13) and struct.calcsize('P')==8;print(sys.executable if ok else '')" 2>$null
    if ($LASTEXITCODE -eq 0 -and $exe) { $py = $exe.Trim(); break }
  } catch { }
}
if (-not $py) { throw 'Python 3.11, 3.12 or 3.13 (64-bit) is required. Install it from https://www.python.org/downloads/windows/ ("Install for all users"), then run this script again.' }
Write-Host "Using $py"

Say "2/7  Copying program files to $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir, (Join-Path $DataDir 'logs') | Out-Null
$running = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($running) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue; Start-Sleep 2 }
foreach ($d in 'cat_server', 'web') { if (Test-Path (Join-Path $InstallDir $d)) { Remove-Item -Recurse -Force (Join-Path $InstallDir $d) } }
foreach ($i in 'cat_server', 'web', 'sample', 'install', 'requirements.txt', 'README.md', 'cat.env.example') { Copy-Item -Recurse -Force (Join-Path $Src $i) $InstallDir }

Say '3/7  Installing Python packages'
$venvPy = Join-Path $InstallDir '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPy)) { & $py -m venv (Join-Path $InstallDir '.venv'); if ($LASTEXITCODE) { throw 'Could not create the virtual environment.' } }
$wheels = Join-Path $Src 'wheels\windows-x64'
if (Test-Path $wheels) {
  Write-Host "Offline install from $wheels"
  & $venvPy -m pip install -q --no-index --find-links $wheels -r (Join-Path $InstallDir 'requirements.txt')
} else {
  Write-Host 'Installing from the Python Package Index'
  & $venvPy -m pip install -q -r (Join-Path $InstallDir 'requirements.txt')
}
if ($LASTEXITCODE) { throw 'Package installation failed (see messages above).' }

Say '4/7  Settings'
$envFile = Join-Path $InstallDir 'cat.env'
if (-not (Test-Path $envFile)) {
  $t = Get-Content (Join-Path $InstallDir 'cat.env.example') -Raw
  $t = $t -replace '(?m)^CAT_PORT=.*$', "CAT_PORT=$Port"
  $t = $t -replace '(?m)^CAT_DATA_DIR=.*$', "CAT_DATA_DIR=$DataDir"
  $t = $t -replace '(?m)^SEED_SAMPLE=.*$', ('SEED_SAMPLE=' + $(if ($NoSample) { '0' } else { '1' }))
  $t = $t -replace '(?m)^DATABASE_URL=.*$', "DATABASE_URL=$DatabaseUrl"
  $t = $t -replace '(?m)^# CAT_LOG_FILE=.*$', ('CAT_LOG_FILE=' + (Join-Path $DataDir 'logs\server.log'))
  [IO.File]::WriteAllText($envFile, $t, (New-Object Text.UTF8Encoding $false))
  Write-Host "Created $envFile"
} else { Write-Host "Keeping existing $envFile" }
# settings and data readable only by Administrators and SYSTEM
foreach ($p in $envFile, $DataDir) {
  & icacls $p /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' | Out-Null
}

Say '5/7  Preparing the database'
Push-Location $InstallDir
$env:CAT_ENV_FILE = $envFile
& $venvPy -c "from cat_server.run import load_env; import os; load_env(os.environ['CAT_ENV_FILE']); from cat_server import store; store.init_db(); print('Database ready:', store.engine.url.render_as_string(hide_password=True))"
Pop-Location
if ($LASTEXITCODE) { throw 'Database preparation failed.' }

Say '6/7  Firewall'
if (-not (Get-NetFirewallRule -DisplayName $TaskName -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName $TaskName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
  Write-Host "Inbound TCP $Port allowed"
} else { Write-Host 'Firewall rule already present' }

if (-not $NoService) {
  Say '7/7  Registering the startup task (runs as SYSTEM, restarts on failure)'
  $action = New-ScheduledTaskAction -Execute $venvPy -Argument "-m cat_server.run --env `"$envFile`"" -WorkingDirectory $InstallDir
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
  Start-ScheduledTask -TaskName $TaskName
  $ok = $false
  for ($i = 0; $i -lt 40; $i++) { Start-Sleep 1; try { Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$Port/api/health" -TimeoutSec 2 | Out-Null; $ok = $true; break } catch { } }
  if ($ok) { Write-Host 'Server is running.' -ForegroundColor Green } else { Write-Host "Server did not answer yet - see $(Join-Path $DataDir 'logs\server.log')" -ForegroundColor Yellow }
} else {
  Say '7/7  Startup task not created (-NoService). Start manually with:'
  Write-Host "  cd $InstallDir; `$env:CAT_ENV_FILE='$envFile'; .\.venv\Scripts\python.exe -m cat_server.run --env `"$envFile`""
}

Say 'Done.'
Write-Host "Open:      http://$($env:COMPUTERNAME):$Port"
Write-Host "Settings:  $envFile   (after changes: Stop-ScheduledTask / Start-ScheduledTask '$TaskName')"
Write-Host "Data:      $DataDir    Log: $(Join-Path $DataDir 'logs\server.log')"
if (-not $NoSample) { Write-Host 'Sample sign-in: example.admin@sample.cat.test / Sample-2026-demo   (see README for all accounts)' }
else { Write-Host "Create the first administrator:  cd $InstallDir; .\.venv\Scripts\python.exe -m cat_server.cli create-admin --email you@company.ae --name `"Your Name`" --password `"Temporary-Pass-2026`"" }
