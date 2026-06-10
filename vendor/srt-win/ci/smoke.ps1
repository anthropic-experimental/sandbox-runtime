<#
  srt-win end-to-end smoke test.

  Exercises the full group + WFP lifecycle against a built srt-win.exe.
  Throws on any assertion failure. Requires elevation (NetLocalGroup*
  and Fwpm* both need admin).

  Usage (local dev machine):
    pwsh vendor/srt-win/ci/smoke.ps1 .\target\release\srt-win.exe

  Usage (CI — workflow passes the path):
    pwsh vendor/srt-win/ci/smoke.ps1 vendor\srt-win\target\release\srt-win.exe

  All WFP operations target $TestSublayer (a fixed test GUID), NOT
  the production default sublayer — safe to run on a dev machine
  that has real sandbox-runtime filters installed; the idempotent
  install's purge-then-re-add only touches the test sublayer.

  When running under GitHub Actions, the random alt-sublayer GUID is
  also written to $env:GITHUB_ENV so the always()-gated cleanup step
  can remove those filters even if this script throws midway.
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$Exe,
  [string]$GroupName = 'srt-ci-test',
  # Distinct from wfp::DEFAULT_SUBLAYER_GUID so local runs never
  # touch a production install.
  [string]$TestSublayer = 'a91b6f12-4c0e-4e30-b1f7-3d52890ce117',
  # Second sublayer for the single-install convenience-subcommand
  # row, so it doesn't perturb the lifecycle section's $TestSublayer.
  [string]$InstallSublayer = 'b2e8a6c4-1f73-4d09-9e25-c7b0d3a48f61'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Exe)) {
  throw "srt-win.exe not found at '$Exe'"
}

# user_sid logged for debug context only (whose TokenGroups the
# group-status / fence assertions are evaluating against).
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Write-Host "srt-win smoke: exe=$Exe group=$GroupName sublayer=$TestSublayer user_sid=$me"
$sl = @('--sublayer-guid', $TestSublayer)
# Explicit so the assertions below are deterministic even if the
# compiled-in default changes.
$pr = @('--proxy-port-range', '60080-60089')

function Run([string[]]$argv) {
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}
function J([string[]]$argv) { Run $argv | ConvertFrom-Json }
function MustFail([string[]]$argv, [string]$why) {
  & $Exe @argv 2>$null
  if ($LASTEXITCODE -eq 0) {
    throw "expected non-zero ($why): srt-win $($argv -join ' ')"
  }
}

# The admin mutators below (group create|delete, wfp install|uninstall)
# self-elevate via maybe_self_elevate (batch 02b). The CI runner is
# already elevated, so the helper returns None and they run in-process,
# same as before; the UAC self-elevate relaunch path is interactive-only
# (see 02b) and is not exercised here.
# ── group create (idempotent) ────────────────────────────────────────
Run @('group', 'create', '--name', $GroupName)
Run @('group', 'create', '--name', $GroupName)   # second call must succeed

$gs = J @('group', 'status', '--name', $GroupName)
Write-Host "group status (--name): $($gs | ConvertTo-Json -Compress)"
# In CI there's no logout, so the new group SID is not yet on the
# runner's token: `created-not-on-token` is expected. On a dev box
# that already has the group from a prior run, `ready` is fine too.
if ($gs.state -notin 'created-not-on-token', 'ready') {
  throw "unexpected group state: $($gs.state)"
}
if (-not $gs.sid -or -not $gs.sid.StartsWith('S-1-')) {
  throw "group status did not return a SID"
}

# --group-sid path returns the same SID.
$gs2 = J @('group', 'status', '--group-sid', $gs.sid)
if ($gs2.sid -ne $gs.sid) {
  throw "--group-sid status sid mismatch: $($gs2.sid) vs $($gs.sid)"
}
# Unmapped SID via --group-sid reports absent (not created-not-on-token).
$gsBad = J @('group', 'status', '--group-sid', 'S-1-5-21-1-2-3-9999999')
if ($gsBad.state -ne 'absent') {
  throw "unmapped --group-sid expected absent, got $($gsBad.state)"
}

# ── negative input ──────────────────────────────────────────────────
MustFail @('wfp', 'install', '--group-sid', 'not-a-sid') 'invalid --group-sid'
MustFail (@('wfp', 'install', '--name', $GroupName, '--proxy-port-range', '100-50') + $sl) 'low>high'
MustFail (@('wfp', 'install', '--name', $GroupName, '--proxy-port-range', '1-1000') + $sl) 'range too wide'
MustFail (@('wfp', 'install', '--name', $GroupName, '--proxy-port-range', '60080') + $sl) 'missing dash'

# ═════════════════════════════════════════════════════════════════════
# WFP lifecycle test — uses $GroupName.
#
# The WFP filters are machine-wide and keyed on the group SID. We
# can install/enumerate/uninstall them regardless of whether the
# group is on the current token, so $GroupName works fine for the
# *lifecycle* assertions below. It does NOT work for asserting
# "the broker gets through" — that needs a group already enabled
# on this token, which $GroupName isn't (no logout in CI). The
# fence-behaviour section further down uses BUILTIN\Administrators
# instead.
# ═════════════════════════════════════════════════════════════════════

# ── pre-install absent ───────────────────────────────────────────────
$pre = J (@('wfp', 'status') + $sl)
if ($pre.state -ne 'absent') {
  throw "pre-install wfp status expected absent, got $($pre.state)"
}

# First install via --name.
Run (@('wfp', 'install', '--name', $GroupName) + $sl + $pr)
$ws = J (@('wfp', 'status') + $sl)
Write-Host "wfp status: $($ws | ConvertTo-Json -Compress)"
if ($ws.state -ne 'installed') { throw "expected installed, got $($ws.state)" }
if ($ws.filters -lt 8)         { throw "expected >=8 filters, got $($ws.filters)" }
if ($ws.port_range[0] -ne 60080 -or $ws.port_range[1] -ne 60089) {
  throw "expected port_range [60080,60089], got [$($ws.port_range -join ',')]"
}

# Idempotency: second install via --group-sid path leaves the same
# filter count.
Run (@('wfp', 'install', '--group-sid', $gs.sid) + $sl + $pr)
$ws2 = J (@('wfp', 'status') + $sl)
if ($ws2.filters -ne $ws.filters) {
  throw "idempotency: filter count changed $($ws.filters) -> $($ws2.filters)"
}

# ── --proxy-port-range override round-trips through status ─────────
Run (@('wfp', 'install', '--name', $GroupName, '--proxy-port-range', '50000-50001') + $sl)
$wsR = J (@('wfp', 'status') + $sl)
if ($wsR.port_range[0] -ne 50000 -or $wsR.port_range[1] -ne 50001) {
  throw "expected port_range [50000,50001], got [$($wsR.port_range -join ',')]"
}
# No-flag install: assert the compiled-in DEFAULT_PROXY_PORT_RANGE.
Run (@('wfp', 'install', '--name', $GroupName) + $sl)
$wsD = J (@('wfp', 'status') + $sl)
if ($wsD.port_range[0] -ne 60080 -or $wsD.port_range[1] -ne 60089) {
  throw "no-flag default expected [60080,60089], got [$($wsD.port_range -join ',')]"
}

# ── --sublayer-guid isolation ────────────────────────────────────────
# Persist the alt GUID so an always()-gated cleanup step can remove
# its filters even if this script throws midway.
$altGuid = [guid]::NewGuid().ToString()
if ($env:GITHUB_ENV) {
  Add-Content $env:GITHUB_ENV "SRT_ALT_GUID=$altGuid"
}
Run (@('wfp', 'install', '--name', $GroupName, '--sublayer-guid', $altGuid) + $pr)
$alt = J @('wfp', 'status', '--sublayer-guid', $altGuid)
if ($alt.state -ne 'installed') {
  throw "alt sublayer expected installed, got $($alt.state)"
}
# Test sublayer is still its own thing.
$stillTest = J (@('wfp', 'status') + $sl)
if ($stillTest.filters -ne $ws.filters) {
  throw "test sublayer perturbed by alt install"
}
Run @('wfp', 'uninstall', '--sublayer-guid', $altGuid)
$altGone = J @('wfp', 'status', '--sublayer-guid', $altGuid)
if ($altGone.state -ne 'absent') {
  throw "alt sublayer expected absent after uninstall, got $($altGone.state)"
}

# ── teardown: uninstall on test sublayer ────────────────────────────
Run (@('wfp', 'uninstall') + $sl)
$post = J (@('wfp', 'status') + $sl)
if ($post.state -ne 'absent') {
  throw "post-uninstall expected absent, got $($post.state)"
}
# Idempotent no-op: second uninstall must also exit 0.
Run (@('wfp', 'uninstall') + $sl)

# ═════════════════════════════════════════════════════════════════════
# WFP fence-behaviour test — uses BUILTIN\Administrators (S-1-5-32-544).
#
# Why a different group: the fence relies on AccessCheck against the
# connecting token, so to assert "broker passes filter 1" we need a
# group that's *already enabled* on this token. $GroupName was just
# created and won't be in TokenGroups until a fresh logon. Admins is
# reliably enabled on the GHA runner.
# ═════════════════════════════════════════════════════════════════════

$adminsSid = 'S-1-5-32-544'
Run (@('wfp', 'install', '--group-sid', $adminsSid) + $sl + $pr)
try {
  # Broker-side: this process has Admins enabled, so filter 1
  # (PERMIT group-enabled) should let the connect through.
  $r = curl.exe -s -m 10 -o NUL -w "%{http_code}" https://example.com
  if ($LASTEXITCODE -ne 0 -or $r -ne '200') {
    throw "broker egress through filter 1 expected 200, got exit=$LASTEXITCODE code='$r'"
  }
  Write-Host "fence: broker egress OK ($r)"

  # Child-side (group deny-only) assertion lands in batch 02 once
  # `srt-win exec` exists; that batch's smoke-exec.ps1 will run
  #   srt-win exec --group-sid S-1-5-32-544 -- curl https://example.com
  # and assert it is BLOCKED.
}
finally {
  Run (@('wfp', 'uninstall') + $sl)
}

# ── group teardown ───────────────────────────────────────────────────
Run @('group', 'delete', '--name', $GroupName)
$gd = J @('group', 'status', '--name', $GroupName)
if ($gd.state -ne 'absent') {
  throw "post-delete group expected absent, got $($gd.state)"
}
# Idempotent no-op: second delete must also exit 0.
Run @('group', 'delete', '--name', $GroupName)

# ═════════════════════════════════════════════════════════════════════
# Single-step `install` / `uninstall` convenience subcommands.
#
# Distinct group name + sublayer so this section is isolated from the
# lifecycle assertions above. Verifies that one `install` call leaves
# both the group present AND the WFP filters installed, and that one
# `uninstall` call removes both.
# ═════════════════════════════════════════════════════════════════════

$instGrp = "$GroupName-inst"
$isl = @('--sublayer-guid', $InstallSublayer)

Run (@('install', '--name', $instGrp) + $isl + $pr)
$ig = J @('group', 'status', '--name', $instGrp)
if ($ig.state -notin 'created-not-on-token', 'ready') {
  throw "install: group expected created-not-on-token/ready, got $($ig.state)"
}
$iw = J (@('wfp', 'status') + $isl)
if ($iw.state -ne 'installed' -or $iw.filters -lt 8) {
  throw "install: wfp expected installed/>=8, got $($iw.state)/$($iw.filters)"
}

# Idempotency, same range: second install with identical flags is
# a no-op (exit 0, "already installed").
$out = & $Exe @(@('install', '--name', $instGrp) + $isl + $pr) 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
  throw "install idempotency: same-range expected exit 0, got $LASTEXITCODE"
}
if ($out -notmatch 'already installed') {
  throw "install idempotency: expected 'already installed' in output, got '$out'"
}
$iw2 = J (@('wfp', 'status') + $isl)
if ($iw2.filters -ne $iw.filters) {
  throw "install idempotency: filters $($iw.filters) -> $($iw2.filters)"
}

# Conflict, different range without --force: exits 13.
& $Exe @(@('install', '--name', $instGrp, '--proxy-port-range', '50000-50001') + $isl) 2>$null
if ($LASTEXITCODE -ne 13) {
  throw "install conflict: different-range without --force expected exit 13, got $LASTEXITCODE"
}
# Original range still in place.
$iw3 = J (@('wfp', 'status') + $isl)
if ($iw3.port_range[0] -ne 60080) {
  throw "install conflict: range was overwritten without --force"
}

# --force replaces.
Run (@('install', '--name', $instGrp, '--proxy-port-range', '50000-50001', '--force') + $isl)
$iwF = J (@('wfp', 'status') + $isl)
if ($iwF.port_range[0] -ne 50000 -or $iwF.port_range[1] -ne 50001) {
  throw "install --force: expected port_range [50000,50001], got [$($iwF.port_range -join ',')]"
}

# --group-sid path (group externally managed; here it already
# exists from the --name install above). With matching range
# this is the same-range no-op.
Run (@('install', '--group-sid', $ig.sid, '--proxy-port-range', '50000-50001') + $isl)

# Distinct exit code 11: group step fails on a malformed
# --group-sid (canonicalize_sid rejects). --force so the
# pre-check (which would otherwise fire on the existing
# install above) is skipped and we reach the group step.
& $Exe @(@('install', '--group-sid', 'not-a-sid', '--force') + $isl) 2>$null
if ($LASTEXITCODE -ne 11) {
  throw "install: invalid --group-sid expected exit 11, got $LASTEXITCODE"
}

# Uninstall removes filters only — group remains.
Run (@('uninstall') + $isl)
$uw = J (@('wfp', 'status') + $isl)
if ($uw.state -ne 'absent') {
  throw "uninstall: wfp expected absent, got $($uw.state)"
}
$ug = J @('group', 'status', '--name', $instGrp)
if ($ug.state -notin 'created-not-on-token', 'ready') {
  throw "uninstall: group should be left intact, got $($ug.state)"
}
# Idempotent no-op: second uninstall must also exit 0.
Run (@('uninstall') + $isl)

# Explicit group teardown.
Run @('group', 'delete', '--name', $instGrp)

Write-Host 'srt-win smoke: OK'
