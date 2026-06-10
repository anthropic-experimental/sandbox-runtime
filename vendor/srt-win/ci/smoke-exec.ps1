<#
  Smoke test for `srt-win exec`.

  Self-contained: provisions WFP filters under a fixed test-only
  sublayer GUID and uses `BUILTIN\Administrators` (S-1-5-32-544) as
  the discriminator group SID. We do NOT create a custom group.

  Why Administrators as the group:
    - The custom-group approach can't exercise the WFP fence on
      hosted CI: the runner can't logout/login mid-job, so a freshly
      created group is *absent* from the token (not deny-only). With
      the machine-wide filter shape, an absent-group child is
      PERMITted by the non-member filter — the fence test would lie.
    - `BUILTIN\Administrators` IS in the runner token (the GHA
      Windows runner runs as admin). `srt-win exec` flips it
      deny-only along with the discriminator. The child therefore
      genuinely matches the BLOCK filter and is fenced.
    - It also means the broker pre-flight passes without
      `--skip-group-check` (Admins is enabled in the broker token),
      so we exercise the normal pre-flight path.

  This is a CI-only configuration. Production callers use a
  dedicated group. The `srt-win exec` code path is identical.

  The fixed sublayer GUID lets the workflow's `if: always()`
  cleanup step uninstall any leaked filters even if this script
  throws mid-run.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; distinct from srt-win's compile-time
# default and from anything smoke.ps1 uses. Referenced verbatim by
# the workflow's always()-cleanup step.
$Sublayer  = '5b0e64f4-09f1-4c2e-8c97-4d2c0f4e9b7d'
$GroupSid  = 'S-1-5-32-544'   # BUILTIN\Administrators
# Loopback PERMIT is scoped to this port range (filter 2). Anything
# on 127.0.0.1 outside it is BLOCKed (filter 3). Match srt-win's
# default but pass it explicitly so this script doesn't drift if
# the default ever changes.
$PortRange = '60080-60089'
$PortLo    = 60080
$PortHi    = 60089

# Bind a TcpListener on the first free port from $candidates.
# Throws if none bind.
function Bind-Listener {
  param([int[]] $Candidates)
  foreach ($p in $Candidates) {
    try {
      $l = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback, $p)
      $l.Start()
      return $l
    } catch {
      # port in use — try next
    }
  }
  throw "no free port among: $($Candidates -join ',')"
}

function Run {
  param([string[]] $argv)
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}
function J { param([string[]] $argv) Run $argv | ConvertFrom-Json }

# Capture exit code + output without throwing on non-zero.
# `srt-win exec` writes its own diagnostics (self-protect SDDL,
# pre-flight warnings, errors) to stderr with a `srt-win:`
# prefix; the CHILD's output is everything else. We merge
# 2>&1 so nothing is lost, then split:
#   .exit — exit code
#   .raw  — full merged output (use for E-rows that assert on
#           srt-win's own messages: E6 diag, E9, E10, E10b)
#   .out  — child output only (lines NOT starting `srt-win:`),
#           rejoined; use for E-rows that parse what the
#           sandboxed child wrote: E2/E4/E5/E7
function Exec {
  param([string[]] $tail)
  $argv = @('exec', '--group-sid', $GroupSid) + $tail
  $raw = & $Exe @argv 2>&1 | Out-String
  $exit = $LASTEXITCODE
  $lines = $raw -split "`r?`n"
  $child = ($lines | Where-Object { $_ -notmatch '^srt-win:' }) -join "`n"
  return [pscustomobject]@{
    exit = $exit; raw = $raw; out = $child
  }
}

$cmd  = Join-Path $env:SystemRoot 'System32\cmd.exe'
$pwsh = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
# Enable srt-win's per-exec stderr diagnostics (notably the
# self-protect SDDL dump that E6 records). Production callers
# leave this unset; the Exec helper's .out filter tolerates it
# either way.
$env:SANDBOX_RUNTIME_WIN_DEBUG = '1'
Write-Host "smoke-exec: group_sid=$GroupSid  sublayer=$Sublayer  exe=$Exe"

# ── precondition: Administrators is enabled in this token ───────
# If the runner ever stops running as admin, the BLOCK filter
# wouldn't apply and E3 would false-pass; fail loudly here instead.
$gs = J @('group','status','--group-sid',$GroupSid)
if ($gs.state -ne 'ready') {
  throw "smoke-exec requires BUILTIN\Administrators enabled in the " +
        "broker token (got state=$($gs.state)). This script depends " +
        "on the GHA Windows runner running elevated."
}

# ── setup: WFP filters under the test sublayer ──────────────────
Run @('wfp','install',
      '--group-sid',$GroupSid,
      '--sublayer-guid',$Sublayer,
      '--proxy-port-range',$PortRange)
$ws = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($ws.state -ne 'installed') {
  throw "wfp not installed under test sublayer: $($ws.state)"
}

# ── E1: exit code propagates verbatim ────────────────────────────
$r = Exec @('--', $cmd, '/c', 'exit 42')
if ($r.exit -ne 42) {
  throw "E1: expected exit 42, got $($r.exit). out: $($r.out)"
}
Write-Host 'E1 ok: exit code propagates'

# ── E2: group SID is deny-only in the child's token ──────────────
# `/FO CSV /NH` — machine-parseable, no header. The default table
# format pads columns to the widest value, which the SID column
# won't survive when the runner has long group names.
$r = Exec @('--', $cmd, '/c', 'whoami /groups /FO CSV /NH')
if ($r.exit -ne 0) { throw "E2: whoami exited $($r.exit): $($r.out)" }
$rows = $r.out | ConvertFrom-Csv -Header Name,Type,SID,Attributes
$g = $rows | Where-Object { $_.SID -eq $GroupSid }
if (-not $g) {
  throw "E2: SID $GroupSid not in whoami /groups:`n$($r.out)"
}
if ($g.Attributes -notmatch '(?i)deny') {
  throw "E2: $GroupSid attrs '$($g.Attributes)' — expected " +
        "'Group used for deny only'"
}
Write-Host 'E2 ok: discriminator SID is deny-only in child token'

# ── E3: outbound network blocked when no proxy is configured ─────
$r = Exec @('--', $cmd, '/c', 'curl -sS -m 5 https://example.com')
if ($r.exit -eq 0) {
  throw "E3: outbound curl succeeded under sandbox " +
        "(fence not in effect?). out: $($r.out)"
}
Write-Host "E3 ok: outbound blocked (curl exit=$($r.exit))"

# ── E4: loopback in proxy-port-range permitted ───────────────────
# Bind a real listener on the broker side at an in-range port and
# connect from inside the sandbox — proves filter 2 (PERMIT 127/8
# ∩ port-range) fires. A closed port wouldn't distinguish
# WFP-block from RST, hence the live listener. Try the high half
# of the range to avoid clashing with anything smoke.ps1 binds.
$inRange = Bind-Listener ($PortHi..($PortLo+5))
$portIn  = $inRange.LocalEndpoint.Port
try {
  $r = Exec @('--', $pwsh, '-NoProfile', '-Command',
    "(Test-NetConnection 127.0.0.1 -Port $portIn " +
    "-WarningAction SilentlyContinue).TcpTestSucceeded")
  if ($r.exit -ne 0) {
    throw "E4: Test-NetConnection exited $($r.exit): $($r.out)"
  }
  if ($r.out -notmatch '(?i)\bTrue\b') {
    throw "E4: loopback connect to in-range port $portIn did " +
          "not succeed. out: $($r.out)"
  }
  Write-Host "E4 ok: loopback to in-range port $portIn permitted"
} finally {
  $inRange.Stop()
}

# ── E4b: loopback outside proxy-port-range blocked ───────────────
# Same setup but on a port well outside the range. The listener
# is reachable from the broker (we bind it), but the sandboxed
# child must NOT reach it — filter 3 BLOCKs.
$outRange = Bind-Listener (50000, 50001, 50002, 49999)
$portOut  = $outRange.LocalEndpoint.Port
try {
  $r = Exec @('--', $pwsh, '-NoProfile', '-Command',
    "(Test-NetConnection 127.0.0.1 -Port $portOut " +
    "-WarningAction SilentlyContinue).TcpTestSucceeded")
  if ($r.out -match '(?i)\bTrue\b') {
    throw "E4b: loopback to out-of-range port $portOut " +
          "succeeded (range tightening not in effect?). out: $($r.out)"
  }
  # Sanity: prove the listener was actually live (reachable from
  # the unsandboxed broker), so a False isn't just "port closed".
  $bs = (Test-NetConnection 127.0.0.1 -Port $portOut `
         -WarningAction SilentlyContinue).TcpTestSucceeded
  if (-not $bs) {
    throw "E4b: broker-side connect to its own listener on " +
          "$portOut failed — test invalid"
  }
  Write-Host "E4b ok: loopback to out-of-range port $portOut blocked"
} finally {
  $outRange.Stop()
}

# ── E5: exec forwards the broker's env to the child verbatim ─────
# Proxy config is single-sourced by the TS caller now: `srt-win exec`
# has no --http-proxy/--socks-proxy flags and synthesizes nothing — it
# forwards its OWN environment to the child. Prove that by setting the
# proxy vars in THIS (broker) process and asserting the sandboxed child
# sees the same values. `cmd /c set VAR` prints `VAR=value` if set,
# exits 1 if unset. One Exec per var — no `&` chaining, so this row is
# independent of the cmd-quoting behaviour exercised by E7.

# Set $Var to $Value for the duration of $Body, then restore exactly
# what was there before (including absence).
function Invoke-WithEnv {
  param([string]$Var, [string]$Value, [scriptblock]$Body)
  $had = Test-Path "Env:$Var"
  $old = if ($had) { (Get-Item "Env:$Var").Value } else { $null }
  Set-Item -Path "Env:$Var" -Value $Value
  try { & $Body }
  finally {
    if ($had) { Set-Item -Path "Env:$Var" -Value $old }
    else { Remove-Item -Path "Env:$Var" -ErrorAction SilentlyContinue }
  }
}

function Assert-EnvPassthrough {
  param([string]$Var, [string]$Want)
  Invoke-WithEnv $Var $Want {
    $r = Exec @('--', $cmd, '/c', "set $Var")
    if ($r.exit -ne 0) {
      throw "E5: 'set $Var' exited $($r.exit) (var unset in child?). out: $($r.out)"
    }
    $line = ($r.out -split "`r?`n" |
             Where-Object { $_ -like "$Var=*" } |
             Select-Object -First 1)
    if ($line -ne "$Var=$Want") {
      throw "E5: $Var expected '$Want', got '$line'. full: $($r.out)"
    }
  }
}
# Values are arbitrary — this proves verbatim passthrough; the real
# values come from the TS generateProxyEnvVars. NO_PROXY doubles as the
# regression guard for the old exec blanking it.
Assert-EnvPassthrough 'HTTPS_PROXY' "http://127.0.0.1:$PortLo"
Assert-EnvPassthrough 'NO_PROXY'    'localhost,127.0.0.1'
Write-Host 'E5 ok: exec forwards broker env (incl. proxy set) to child verbatim'

# ── E5b: broker restores the twin casing of *_PROXY vars ────────
# The host spawn layer (Node/bun child_process on win32) keeps only ONE
# casing of an env key, but Cygwin/MSYS2 children have case-sensitive
# environments whose tools read the lowercase names — so exec appends
# the missing twin (identical value, never invented). The broker process
# itself can only hold one casing (Win32 env is case-insensitive), so
# setting HTTP_PROXY here and finding BOTH casings in the child proves
# the repair. `set http` lists matching vars with their STORED casing;
# -clike is the case-SENSITIVE match.
Invoke-WithEnv 'HTTP_PROXY' "http://127.0.0.1:$PortLo" {
  $r = Exec @('--', $cmd, '/c', 'set http')
  if ($r.exit -ne 0) {
    throw "E5b: 'set http' exited $($r.exit). out: $($r.out)"
  }
  $lines = $r.out -split "`r?`n"
  if (-not ($lines | Where-Object { $_ -clike 'http_proxy=*' })) {
    throw "E5b: lowercase http_proxy twin missing in child. out: $($r.out)"
  }
  if (-not ($lines | Where-Object { $_ -clike 'HTTP_PROXY=*' })) {
    throw "E5b: uppercase HTTP_PROXY missing in child. out: $($r.out)"
  }
}
Write-Host 'E5b ok: broker restores the lowercase twin of proxy vars for the child'

# ── E6: self-protect — child cannot OpenProcess the broker ──────
# The child discovers the broker by walking its parent-process chain
# by NAME (the depth differs between cmd / powershell / git-bash
# children, so no fixed hop count). Win32_Process.ParentProcessId is
# readable without any handle on the broker itself, so discovery does
# not depend on the access self-protect denies. The probe then
# P/Invokes OpenProcess directly with PROCESS_VM_READ — an unambiguous
# mask that the broker-only DACL must deny. (`.NET Process.Handle`
# is NOT sufficient: it lazily falls back to
# PROCESS_QUERY_LIMITED_INFORMATION, which can succeed via paths
# the DACL doesn't fully gate; that produced a false "OPENED"
# on the previous CI run.)
$probe = @'
$bp = 0
$why = ''
$cur = $PID
for ($i = 0; $i -lt 6; $i++) {
  $p = Get-CimInstance Win32_Process -Filter "ProcessId=$cur" -ErrorAction SilentlyContinue
  if (-not $p) { $why = "WMI query failed at pid $cur (hop $i)"; break }
  if ($p.Name -eq 'srt-win.exe') { $bp = [int]$p.ProcessId; break }
  if (-not $p.ParentProcessId) { $why = "no parent beyond pid $cur (hop $i)"; break }
  $cur = $p.ParentProcessId
}
if ($bp -eq 0) {
  if (-not $why) { $why = 'hop cap reached without finding srt-win.exe' }
  Write-Output "NOBROKER: $why"
  exit 0
}
$sig = '[DllImport("kernel32.dll",SetLastError=true)]public static extern System.IntPtr OpenProcess(uint a,bool b,uint p);'
$k32 = Add-Type -MemberDefinition $sig -Name K32 -Namespace W -PassThru
# 0x0010 = PROCESS_VM_READ
$h = $k32::OpenProcess(0x0010, $false, $bp)
$le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
if ($h -ne [System.IntPtr]::Zero) {
  Write-Output "OPENED:vm_read handle=$h"
} elseif ($le -eq 5) {
  Write-Output "DENIED:vm_read le=5"
} else {
  Write-Output "OTHER:vm_read le=$le"
}
# Also try PROCESS_QUERY_LIMITED_INFORMATION (0x1000) so the CI
# log records whether THAT is granted — not asserted on, but
# useful diagnostic for the threat model.
$h2 = $k32::OpenProcess(0x1000, $false, $bp)
$le2 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Output "INFO:limited_query handle=$h2 le=$le2"
'@
$r = Exec @('--', $pwsh, '-NoProfile', '-Command', $probe)
# self_protect.rs eprintln!s the applied SDDL to stderr; that
# line is in .raw (filtered out of .out by the `srt-win:`
# prefix). Surface it here so the DACL is visible next to the
# probe result.
$sddl = ($r.raw -split "`r?`n" |
         Where-Object { $_ -match 'self-protect applied' }) -join ' '
Write-Host "E6 broker DACL: $sddl"
Write-Host "E6 probe output: $($r.out.Trim())"
if ($r.out -match 'NOBROKER') {
  $reason = ($r.out -split "`r?`n" |
             Where-Object { $_ -match '^NOBROKER' }) -join ' '
  throw "E6: broker discovery failed — $reason. raw: $($r.raw)"
}
if ($r.out -match 'OPENED:vm_read') {
  throw "E6: child got PROCESS_VM_READ on broker " +
        "(self-protect ineffective). raw: $($r.raw)"
}
if ($r.out -notmatch 'DENIED:vm_read') {
  throw "E6: expected ACCESS_DENIED (5) for PROCESS_VM_READ. " +
        "raw: $($r.raw)"
}
Write-Host 'E6 ok: child denied PROCESS_VM_READ on broker'

# ── E7: cmd.exe /c passthrough — user-quoted payload survives ───
# build_cmdline wraps the post-/c content in ONE outer "…" pair
# for /s to strip; inner content is verbatim. The `&` is inside
# the user's own "…" so cmd treats it literally.
$r = Exec @('--', $cmd, '/d', '/s', '/c', 'echo "x & y"')
if ($r.exit -ne 0) { throw "E7 exited $($r.exit): $($r.out)" }
$got = $r.out.Trim()
if ($got -ne '"x & y"') {
  throw "E7: expected literal '`"x & y`"', got '$got'"
}
Write-Host 'E7 ok: user-quoted payload passes through verbatim'

# ── E7b: cmd metachar passthrough — `&` works as separator ──────
# By design: the post-/c string is the user's cmd command, NOT
# escaped. `&` chains commands inside the *sandboxed* cmd.exe.
# This is not the Phase-6 N1 host-shell injection — that
# concerned the OUTER spawn (solved by argv-mode in batch 03);
# the child here IS the sandbox.
$r = Exec @('--', $cmd, '/d', '/s', '/c', 'echo MARKER & exit 5')
if ($r.exit -ne 5) {
  throw "E7b: expected exit 5 from chained command, got $($r.exit). " +
        "out: $($r.out)"
}
if ($r.out.Trim() -notlike 'MARKER*') {
  throw "E7b: expected MARKER in output. out: $($r.out)"
}
Write-Host 'E7b ok: & chains commands inside sandboxed cmd (passthrough)'

# ── E8: --name resolution path through exec ─────────────────────
# Every row above used --group-sid. Run one row via --name to cover
# `resolve_group_sid`'s LookupAccountNameW branch in the exec path.
# `BUILTIN\Administrators` resolves on every Windows install.
$r = & $Exe exec --name 'BUILTIN\Administrators' -- $cmd /c 'exit 7' 2>&1
if ($LASTEXITCODE -ne 7) {
  throw "E8: --name exec expected exit 7, got $LASTEXITCODE. out: $r"
}
Write-Host 'E8 ok: --name resolution path through exec works'

# ── E9: refuse to nest — exec from inside exec fails fast ───────
# Inside the sandbox child, the discriminator SID is deny-only;
# the inner `srt-win exec` pre-flight (no --skip-group-check) must
# refuse with the deny-only message.
$inner = "`"$Exe`" exec --group-sid $GroupSid -- $cmd /c exit 0"
$r = Exec @('--', $cmd, '/c', $inner)
if ($r.exit -eq 0) {
  throw "E9: nested exec succeeded; expected refusal. raw: $($r.raw)"
}
# The deny-only refusal comes from the INNER srt-win's stderr,
# which is `srt-win:`-prefixed and therefore in .raw (filtered
# out of .out — the filter can't distinguish inner-vs-outer
# srt-win lines).
if ($r.raw -notmatch '(?i)deny-only') {
  throw "E9: nested exec failed but not with the deny-only " +
        "message. raw: $($r.raw)"
}
Write-Host 'E9 ok: nested exec refused (deny-only guard)'

# ── E10: --skip-group-check is silent when group is ready ───────
# The flag must not break the run and must NOT warn when the
# group is in fact enabled (warning fires only on Absent).
$r = & $Exe exec --group-sid $GroupSid --skip-group-check `
        -- $cmd /c 'exit 0' 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
  throw "E10: --skip-group-check run exited ${LASTEXITCODE}: $r"
}
if ($r -match '(?i)WARNING:.*skip-group-check') {
  throw "E10: warning fired despite group being ready. out: $r"
}
Write-Host 'E10 ok: --skip-group-check silent when group is ready'

# ── E10b: --skip-group-check warns when group is ABSENT ─────────
# A well-formed but unmapped SID (alias RID 9999 doesn't exist)
# is Absent in the broker token. With the flag, exec must warn
# and proceed (exit = child's). Without the flag it would refuse
# — that path is covered by E9's deny-only refusal; the Absent
# refusal differs only in the message.
$r = & $Exe exec --group-sid S-1-5-32-9999 --skip-group-check `
        -- $cmd /c 'exit 0' 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
  throw "E10b: --skip-group-check + absent group exited ${LASTEXITCODE}: $r"
}
if ($r -notmatch '(?i)WARNING:.*skip-group-check') {
  throw "E10b: expected absent-group warning. out: $r"
}
Write-Host 'E10b ok: --skip-group-check warns when group is absent'

# TODO E11: verify mitigation policies actually applied (child-side
#   GetProcessMitigationPolicy probe). Deferred — would need a
#   helper binary or P/Invoke from inside the sandboxed PowerShell.

# ── teardown ─────────────────────────────────────────────────────
Run @('wfp','uninstall','--sublayer-guid',$Sublayer)
$post = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($post.state -ne 'absent') {
  throw "post-uninstall expected absent, got $($post.state)"
}
Write-Host 'smoke-exec: PASS (E1-E10b incl. E4b/E7b)'
