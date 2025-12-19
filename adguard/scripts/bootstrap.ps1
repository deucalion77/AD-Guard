
param(
  [string]$AuditUserSam = "svc_ad_audit",
  [string]$AuditGroupName = "AD-Audit-Readers",
  [string]$TargetOUForUser = "",

  # Optional account behavior
  [switch]$PasswordNeverExpires,
  [switch]$ForceResetPasswordAtLogon,

  # Optional: restrict audit user to specific workstations (comma-separated NETBIOS names)
  # Example: "AD-AUDIT-VM01,AD-AUDIT-VM02"
  [string]$LogonWorkstations = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Module($name) {
  if (-not (Get-Module -ListAvailable -Name $name)) {
    throw "Required module '$name' not found. Install RSAT: 'RSAT: Active Directory Domain Services and Lightweight Directory Services Tools'."
  }
  Import-Module $name -ErrorAction Stop
}

function New-StrongPassword {
  Add-Type -AssemblyName System.Web
  # length=28, non-alphanumeric=6
  return [System.Web.Security.Membership]::GeneratePassword(28, 6)
}

function Write-Section($title) {
  Write-Host ""
  Write-Host "=== $title ==="
}

Assert-Module ActiveDirectory

# Domain info
$domain = Get-ADDomain
$domainDn = $domain.DistinguishedName
Write-Host "Domain DNS : $($domain.DNSRoot)"
Write-Host "Domain DN  : $domainDn"

# 1) Ensure group exists
Write-Section "Group"
$group = Get-ADGroup -Filter "Name -eq '$AuditGroupName'" -ErrorAction SilentlyContinue
if (-not $group) {
  Write-Host "Creating group: $AuditGroupName"
  $group = New-ADGroup -Name $AuditGroupName `
    -SamAccountName $AuditGroupName `
    -GroupScope Global `
    -GroupCategory Security `
    -Path $domainDn `
    -Description "ADGuard audit readers group (least privilege)."
} else {
  Write-Host "Group exists: $AuditGroupName"
}

# 2) Ensure user exists
Write-Section "User"
$user = Get-ADUser -Filter "SamAccountName -eq '$AuditUserSam'" -ErrorAction SilentlyContinue
$plainPw = $null

if (-not $user) {
  $plainPw = New-StrongPassword
  $secPw = ConvertTo-SecureString $plainPw -AsPlainText -Force

  $userPath = if ($TargetOUForUser -and $TargetOUForUser.Trim()) { $TargetOUForUser } else { $domainDn }

  Write-Host "Creating user: $AuditUserSam"
  Write-Host "Path        : $userPath"

  New-ADUser -Name $AuditUserSam `
    -SamAccountName $AuditUserSam `
    -UserPrincipalName "$AuditUserSam@$($domain.DNSRoot)" `
    -Path $userPath `
    -AccountPassword $secPw `
    -Enabled $true `
    -Description "Least-privilege AD audit account used by ADGuard tool."

  if ($PasswordNeverExpires) {
    Set-ADUser -Identity $AuditUserSam -PasswordNeverExpires $true
  }

  if ($ForceResetPasswordAtLogon) {
    Set-ADUser -Identity $AuditUserSam -ChangePasswordAtLogon $true
  }

  if ($LogonWorkstations -and $LogonWorkstations.Trim()) {
    # AD stores this as a comma-separated list
    Set-ADUser -Identity $AuditUserSam -LogonWorkstations $LogonWorkstations
  }

  Write-Host ""
  Write-Host "INITIAL PASSWORD for ${AuditUserSam}:"
  Write-Host "  $plainPw"
  Write-Host "Store it securely (vault). Rotate after first use."
} else {
  Write-Host "User exists: $AuditUserSam"

  # Optionally enforce settings if requested
  if ($PasswordNeverExpires) {
    Set-ADUser -Identity $AuditUserSam -PasswordNeverExpires $true
  }
  if ($ForceResetPasswordAtLogon) {
    Set-ADUser -Identity $AuditUserSam -ChangePasswordAtLogon $true
  }
  if ($LogonWorkstations -and $LogonWorkstations.Trim()) {
    Set-ADUser -Identity $AuditUserSam -LogonWorkstations $LogonWorkstations
  }
}

# 3) Ensure membership
Write-Section "Membership"
Write-Host "Ensuring ${AuditUserSam} is a member of ${AuditGroupName}..."
try {
  Add-ADGroupMember -Identity $AuditGroupName -Members $AuditUserSam -ErrorAction Stop
  Write-Host "Added (or updated) membership."
} catch {
  # If already a member, ignore; otherwise throw
  if ($_.Exception.Message -match "already a member") {
    Write-Host "Already a member."
  } else {
    throw
  }
}

# 4) Delegate read-only directory access + ACL visibility on domain root
Write-Section "Delegation (Read-only + ACL visibility)"
Write-Host "Applying read-only delegations on domain root (inherited to all objects)..."
Write-Host "This enables reliable ACL enumeration (for dangerous ACE and DCSync-risk checks)."

# Resolve group SID
$groupSid = (Get-ADGroup -Identity $AuditGroupName).SID

# Use AD provider for ACL operations
$rootPath = "AD:\$domainDn"
$acl = Get-Acl -Path $rootPath

# GenericRead: read properties/list objects
$ruleGenericRead = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
  $groupSid,
  [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
  [System.Security.AccessControl.AccessControlType]::Allow,
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
)

# ReadControl: "Read permissions" (ability to read security descriptors/ACLs)
$ruleReadControl = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
  $groupSid,
  [System.DirectoryServices.ActiveDirectoryRights]::ReadControl,
  [System.Security.AccessControl.AccessControlType]::Allow,
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
)

# Add rules (idempotent-ish: AddAccessRule merges; duplicates typically coalesce)
$acl.AddAccessRule($ruleGenericRead) | Out-Null
$acl.AddAccessRule($ruleReadControl) | Out-Null

Set-Acl -Path $rootPath -AclObject $acl

Write-Host ""
Write-Host "Bootstrap complete."
Write-Host "  User : $AuditUserSam"
Write-Host "  Group: $AuditGroupName"
Write-Host "  Delegation: GenericRead + ReadControl on domain root (inherited)"
Write-Host ""
Write-Host "Next:"
Write-Host "  - Log in (or RunAs) as ${AuditUserSam} and run:  .\adguard.ps1 scan"