<#
  Machine-wide state store lifecycle smoke (`%ProgramData%\sandbox-runtime`).

  Asserts the elevated install provisions the shared store (dir
  owned by Administrators, sandbox-group DENY, Users modify; the
  credential in its own Users-read-only `cred.dat`), that a
  sandboxed child can read neither the DB nor the credential file,
  that an install running as SYSTEM (the SCCM/Intune fleet shape)
  leaves a credential the INTERACTIVE user's broker can read and
  spawn with — the per-user-store bug this store exists to fix —
  that a re-install rotates the shared credential in place, and
  that a full uninstall removes the credential with the account.

  Self-contained: installs under a fixed test-only sublayer GUID
  (distinct from the other smoke scripts); uninstalls in `finally`.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; referenced by cleanup.ps1.
$Sublayer  = '4c7d9b21-3e58-4a06-9d17-8f2a6c40be93'
$PortRange = '60080-60089'

function Run { param([string[]] $argv)
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}
function J { param([string[]] $argv) Run $argv | ConvertFrom-Json }
function RunCapture { param([string[]] $argv)
  $raw = & $Exe @argv 2>&1 | Out-String
  return [pscustomobject]@{ exit = $LASTEXITCODE; raw = $raw }
}

$cmd      = Join-Path $env:SystemRoot 'System32\cmd.exe'
$stateDir = Join-Path $env:ProgramData 'sandbox-runtime'
$credFile = Join-Path $stateDir 'cred.dat'
$env:SANDBOX_RUNTIME_WIN_DEBUG = '1'
Write-Host "smoke-machine-store: sublayer=$Sublayer  exe=$Exe"

try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke-machine-store: WARNING: Start-Service seclogon: $_"
}

try {
  # ── MS1: elevated install provisions the machine store ───────────
  Run @('install', '--sublayer-guid', $Sublayer, '--proxy-port-range', $PortRange, '--force')
  $us = J @('user', 'status')
  if ($us.store -ne 'machine')   { throw "MS1: store expected 'machine', got '$($us.store)'" }
  if (-not $us.cred_present)     { throw 'MS1: cred_present false after machine-store install' }
  if (-not (Test-Path $credFile)) { throw "MS1: $credFile missing" }

  $acl = Get-Acl $stateDir
  if ($acl.Owner -notmatch 'Administrators$') {
    throw "MS1: state dir owner expected Administrators, got '$($acl.Owner)'"
  }
  $deny = $acl.Access | Where-Object {
    $_.AccessControlType -eq 'Deny' -and
    $_.IdentityReference.Value -match 'sandbox-runtime-users$'
  }
  if (-not $deny) {
    throw "MS1: state-dir DACL has no DENY for sandbox-runtime-users; got:`n$($acl.Access | Out-String)"
  }
  $usersModify = $acl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.IdentityReference.Value -match '\\Users$' -and
    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::WriteData)
  }
  if (-not $usersModify) {
    throw "MS1: state-dir DACL grants BUILTIN\Users no write; got:`n$($acl.Access | Out-String)"
  }

  $cacl = Get-Acl $credFile
  $credDeny = $cacl.Access | Where-Object {
    $_.AccessControlType -eq 'Deny' -and
    $_.IdentityReference.Value -match 'sandbox-runtime-users$'
  }
  if (-not $credDeny) {
    throw "MS1: cred.dat DACL has no DENY for sandbox-runtime-users; got:`n$($cacl.Access | Out-String)"
  }
  $credUsersWrite = $cacl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.IdentityReference.Value -match '\\Users$' -and
    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::WriteData)
  }
  if ($credUsersWrite) {
    throw "MS1: cred.dat is writable by BUILTIN\Users; got:`n$($cacl.Access | Out-String)"
  }
  Write-Host 'MS1 ok: machine store provisioned (owner, deny, Users modify, cred.dat read-only)'

  # ── MS2: sandboxed child can read neither cred.dat nor state.db ──
  foreach ($p in @($credFile, (Join-Path $stateDir 'state.db'))) {
    $r = RunCapture @('exec', '--quiet', '--', $cmd, '/c', "type `"$p`"")
    if ($r.exit -eq 0) { throw "MS2: child READ $p. raw: $($r.raw)" }
  }
  $r = RunCapture @('exec', '--quiet', '--', $cmd, '/c', "echo x > `"$credFile`"")
  if ($r.exit -eq 0) { throw 'MS2: child OVERWROTE cred.dat' }
  if (-not (Test-Path $credFile)) { throw 'MS2: cred.dat vanished during deny probe' }
  Write-Host 'MS2 ok: sandbox child denied on cred.dat and state.db'

  # ── MS3: SYSTEM install is readable by the interactive user ──────
  # The fleet shape (SCCM/Intune run installs as SYSTEM). Under the
  # per-user store this left the interactive user's dependency check
  # at cred_present:false — the bug the machine store fixes.
  Run @('uninstall', '--sublayer-guid', $Sublayer)
  if (Test-Path $credFile) { throw 'MS3: cred.dat survived full uninstall' }
  $task = 'srt-win-ms3-system-install'
  # A scheduled task starts in System32, so the exe path must be
  # absolute; run through a wrapper .cmd that captures output, since
  # a SYSTEM task's console is otherwise invisible.
  $exeFull = (Resolve-Path $Exe).Path
  $ms3Log  = 'C:\Windows\Temp\srt-ms3-system-install.log'
  $runner  = 'C:\Windows\Temp\srt-ms3-system-install.cmd'
  Remove-Item $ms3Log -ea SilentlyContinue
  @(
    '@echo off'
    "`"$exeFull`" install --sublayer-guid $Sublayer --proxy-port-range $PortRange --force > `"$ms3Log`" 2>&1"
  ) | Set-Content $runner -Encoding ascii
  schtasks /Create /F /RU SYSTEM /SC ONCE /ST 00:00 /TN $task /TR "`"$runner`"" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "MS3: schtasks /Create exited $LASTEXITCODE" }
  try {
    schtasks /Run /TN $task | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "MS3: schtasks /Run exited $LASTEXITCODE" }
    $deadline = (Get-Date).AddSeconds(120)
    while (-not (Test-Path $credFile)) {
      if ((Get-Date) -gt $deadline) {
        $installOut = if (Test-Path $ms3Log) { Get-Content $ms3Log | Out-String } else { '<no log>' }
        throw "MS3: SYSTEM install did not produce cred.dat in 120s. install output:`n$installOut"
      }
      Start-Sleep -Seconds 2
    }
    # Give the SYSTEM install a moment to finish its WFP step too.
    Start-Sleep -Seconds 5
  } finally {
    schtasks /Delete /F /TN $task | Out-Null
    Remove-Item $runner, $ms3Log -ea SilentlyContinue
  }
  $us = J @('user', 'status')   # interactive user's view
  if (-not $us.cred_present) { throw 'MS3: interactive user sees cred_present:false after SYSTEM install' }
  if ($us.store -ne 'machine') { throw "MS3: store expected 'machine', got '$($us.store)'" }
  $pw = & $Exe user read-cred
  if ($LASTEXITCODE -ne 0) { throw "MS3: interactive read-cred exited $LASTEXITCODE" }
  if ($pw.Length -ne 32)   { throw "MS3: read-cred expected 32 chars, got $($pw.Length)" }
  $r = RunCapture @('exec', '--quiet', '--', $cmd, '/c', 'whoami')
  if ($r.exit -ne 0) { throw "MS3: interactive exec after SYSTEM install failed: $($r.raw)" }
  Write-Host 'MS3 ok: SYSTEM install; interactive user reads cred and spawns'

  # ── MS4: re-install rotates the shared credential in place ───────
  $before = [System.IO.File]::ReadAllBytes($credFile)
  Run @('install', '--sublayer-guid', $Sublayer, '--proxy-port-range', $PortRange, '--force')
  $after = [System.IO.File]::ReadAllBytes($credFile)
  if ([System.Convert]::ToBase64String($before) -eq [System.Convert]::ToBase64String($after)) {
    throw 'MS4: cred.dat unchanged across rotating re-install'
  }
  $pw = & $Exe user read-cred
  if ($LASTEXITCODE -ne 0 -or $pw.Length -ne 32) {
    throw "MS4: read-cred after rotation failed (exit $LASTEXITCODE, len $($pw.Length))"
  }
  Write-Host 'MS4 ok: rotation refreshed the shared credential'

  # ── MS5: full uninstall removes the credential with the account ──
  Run @('uninstall', '--sublayer-guid', $Sublayer)
  if (Test-Path $credFile) { throw 'MS5: cred.dat survived uninstall' }
  $us = J @('user', 'status')
  if ($us.cred_present) { throw 'MS5: cred_present still true after uninstall' }
  Write-Host 'MS5 ok: uninstall removed the shared credential'

  Write-Host 'smoke-machine-store: all checks passed'
} finally {
  & $Exe uninstall --sublayer-guid $Sublayer 2>&1 | Out-Null
}
