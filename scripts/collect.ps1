param(
  [Parameter(Mandatory=$true)]
  [string]$OutDir,

  [string]$AuditGroupName = "AD-Audit-Readers",

  [pscredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$raw = Join-Path $OutDir "raw"
New-Item -ItemType Directory -Force -Path $raw | Out-Null

# Domain (supports -Credential)
$domain = if ($Credential) { Get-ADDomain -Credential $Credential } else { Get-ADDomain }
$domainDn = $domain.DistinguishedName

Write-Host "Collecting AD domain basics..."
$domainInfo = [pscustomobject]@{
  DNSRoot            = $domain.DNSRoot
  DistinguishedName  = $domainDn
  DomainSID          = $domain.DomainSID.Value
  PDCEmulator        = $domain.PDCEmulator
}
$domainInfo | ConvertTo-Json -Depth 6 | Out-File (Join-Path $raw "domain.json") -Encoding utf8

Write-Host "Collecting users (minimal fields)..."

$userProps = @(
  "servicePrincipalName",
  "pwdLastSet",
  "userAccountControl",
  "memberOf",
  "PasswordNeverExpires",
  "LastLogonDate",
  "adminCount"
)

$userSelect = @(
  "SamAccountName",
  "UserPrincipalName",
  "Enabled",
  "servicePrincipalName",
  "pwdLastSet",
  "userAccountControl",
  "PasswordNeverExpires",
  "LastLogonDate",
  "memberOf",
  "adminCount"
)

if ($Credential) {
  Get-ADUser -Filter * -Credential $Credential -Properties $userProps |
    Select-Object $userSelect |
    ConvertTo-Json -Depth 6 |
    Out-File (Join-Path $raw "users.json") -Encoding utf8
} else {
  Get-ADUser -Filter * -Properties $userProps |
    Select-Object $userSelect |
    ConvertTo-Json -Depth 6 |
    Out-File (Join-Path $raw "users.json") -Encoding utf8
}


Write-Host "Collecting groups..."
# IMPORTANT: include adminCount in BOTH branches
$groupProps = @(
  "Members",
  "adminCount"
)
$groupSelect = @("Name","SamAccountName","DistinguishedName","GroupScope","GroupCategory","adminCount")

if ($Credential) {
  Get-ADGroup -Filter * -Credential $Credential -Properties $groupProps |
    Select-Object $groupSelect |
    ConvertTo-Json -Depth 6 |
    Out-File (Join-Path $raw "groups.json") -Encoding utf8
} else {
  Get-ADGroup -Filter * -Properties $groupProps |
    Select-Object $groupSelect |
    ConvertTo-Json -Depth 6 |
    Out-File (Join-Path $raw "groups.json") -Encoding utf8
}

Write-Host "Collecting MachineAccountQuota..."
$maq = if ($Credential) {
  (Get-ADObject -Identity $domainDn -Credential $Credential -Properties ms-DS-MachineAccountQuota)."ms-DS-MachineAccountQuota"
} else {
  (Get-ADObject -Identity $domainDn -Properties ms-DS-MachineAccountQuota)."ms-DS-MachineAccountQuota"
}
([pscustomobject]@{ msDSMachineAccountQuota = $maq }) |
  ConvertTo-Json |
  Out-File (Join-Path $raw "domain_policies.json") -Encoding utf8

Write-Host "Collecting GPO list + reports..."
# Note: GPO cmdlets generally run in current user context (no -Credential parameter).
$gpos = Get-GPO -All
$gpos | Select-Object DisplayName,Id,CreationTime,ModificationTime |
  ConvertTo-Json -Depth 5 |
  Out-File (Join-Path $raw "gpos.json") -Encoding utf8

$gpoReportDir = Join-Path $raw "gpo_reports"
New-Item -ItemType Directory -Force -Path $gpoReportDir | Out-Null

foreach ($gpo in $gpos) {
  $safeName = ($gpo.DisplayName -replace '[\\/:*?"<>|]','_')
  $path = Join-Path $gpoReportDir "$safeName-$($gpo.Id).xml"
  Get-GPOReport -Guid $gpo.Id -ReportType Xml -Path $path
}

Write-Host "Collecting ACLs for high-value AD containers..."
$aclDir = Join-Path $raw "acl_targets"
New-Item -ItemType Directory -Force -Path $aclDir | Out-Null

$targets = @(
  @{ Name = "domain_root"; DN = $domainDn },
  @{ Name = "users_container"; DN = "CN=Users,$domainDn" },
  @{ Name = "computers_container"; DN = "CN=Computers,$domainDn" },
  @{ Name = "domain_controllers_ou"; DN = "OU=Domain Controllers,$domainDn" }
)

foreach ($t in $targets) {
  $name = $t.Name
  $dn   = $t.DN
  try {
    Write-Host "  - ACL: $name  ($dn)"
    # NOTE: AD:\ provider ACL reads use the current Windows security context, not -Credential.
    $acl = Get-Acl -Path ("AD:\$dn")

    $acl.Access |
      Select-Object IdentityReference,ActiveDirectoryRights,AccessControlType,IsInherited,InheritanceType,ObjectType,InheritedObjectType |
      ConvertTo-Json -Depth 6 |
      Out-File (Join-Path $aclDir "$name.json") -Encoding utf8
  } catch {
    Write-Host "  ! Failed to read ACL for $dn : $($_.Exception.Message)"
  }
}

Write-Host "Collecting domain root ACL (legacy export: domain_acl.json)..."
try {
  $domainAcl = Get-Acl -Path ("AD:\$domainDn")
  $domainAcl.Access |
    Select-Object IdentityReference,ActiveDirectoryRights,AccessControlType,IsInherited,InheritanceType,ObjectType,InheritedObjectType |
    ConvertTo-Json -Depth 6 |
    Out-File (Join-Path $raw "domain_acl.json") -Encoding utf8
} catch {
  Write-Host "  ! Failed to read domain root ACL : $($_.Exception.Message)"
}

Write-Host "Collection complete: $raw"
