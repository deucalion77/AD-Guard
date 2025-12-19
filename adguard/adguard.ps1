param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("bootstrap","collect","analyze","scan","report")]
  [string]$Command,

  [string]$OutDir = "C:\adguard\out",
  [string]$AuditUserSam = "svc_ad_audit",
  [string]$AuditGroupName = "AD-Audit-Readers",
  [string]$UserOU = "",
  [string]$WorkstationsOU = "",
  [string]$ServersOU = "",

  [switch]$EnableEventLogReadersGPO,
  [switch]$UseAuditCredential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Run-Script($path, $argsArray) {
  Write-Host "==> Running: $path $($argsArray -join ' ')"
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $path @argsArray
}

function Ensure-OutDirs($base) {
  New-Item -ItemType Directory -Force -Path $base | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $base "raw") | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $base "reports") | Out-Null
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$scripts = Join-Path $root "scripts"
$engine  = Join-Path $root "engine"

Ensure-OutDirs $OutDir

switch ($Command) {

  "bootstrap" {
    $args = @(
      "-AuditUserSam", $AuditUserSam,
      "-AuditGroupName", $AuditGroupName
    )

    if ($UserOU -and $UserOU.Trim()) {
      $args += @("-TargetOUForUser", $UserOU)
    }

    if ($EnableEventLogReadersGPO) { $args += "-EnableEventLogReadersGPO" }
    if ($WorkstationsOU -and $WorkstationsOU.Trim()) { $args += @("-WorkstationsOU", $WorkstationsOU) }
    if ($ServersOU -and $ServersOU.Trim()) { $args += @("-ServersOU", $ServersOU) }

    Run-Script (Join-Path $scripts "bootstrap.ps1") $args
  }

  "collect" {
    $args = @(
      "-OutDir", $OutDir,
      "-AuditGroupName", $AuditGroupName
    )

    if ($UseAuditCredential) {
      Import-Module ActiveDirectory -ErrorAction Stop
      $domain = (Get-ADDomain).DNSRoot
      $cred = Get-Credential -Message "Enter credentials for scanning (e.g., $domain\$AuditUserSam)"
      $args += @("-Credential", $cred)
    }

    Run-Script (Join-Path $scripts "collect.ps1") $args
  }

  "analyze" {
    $rawDir  = Join-Path $OutDir "raw"
    $scanJson = Join-Path $OutDir "scan.json"
    $htmlOut  = Join-Path $OutDir "reports\report.html"

    Write-Host "==> Running Python analyzer"
    python (Join-Path $engine "analyze.py") --raw $rawDir --out $scanJson --html $htmlOut
  }

  "report" {
    $scanJson = Join-Path $OutDir "scan.json"
    $htmlOut  = Join-Path $OutDir "reports\report.html"
    python (Join-Path $engine "report.py") --infile $scanJson --html $htmlOut
  }

  "scan" {
    # Run collect
    if ($UseAuditCredential) {
      & $PSCommandPath -Command collect -OutDir $OutDir -AuditGroupName $AuditGroupName -AuditUserSam $AuditUserSam -UseAuditCredential
    } else {
      & $PSCommandPath -Command collect -OutDir $OutDir -AuditGroupName $AuditGroupName -AuditUserSam $AuditUserSam
    }

    # Run analyze
    & $PSCommandPath -Command analyze -OutDir $OutDir

    Write-Host "Report: $(Join-Path $OutDir 'reports\report.html')"
  }
}