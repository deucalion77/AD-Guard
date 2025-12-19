import argparse, json, datetime
import re
from pathlib import Path
from collections import defaultdict

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def load_json(path: Path):
    if not path.exists():
        return None
    # utf-8-sig safely handles UTF-8 with or without BOM
    txt = path.read_text(encoding="utf-8-sig")
    if not txt.strip():
        return None
    return json.loads(txt)

def ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def filetime_to_dt(filetime_int):
    # AD pwdLastSet is Windows FILETIME (100-ns since 1601). Sometimes comes as int.
    try:
        ft = int(filetime_int)
        if ft <= 0:
            return None
        unix = (ft - 116444736000000000) / 10_000_000
        return datetime.datetime.utcfromtimestamp(unix)
    except Exception:
        return None

def score_posture(findings):
    # Simple scoring: start at 100, subtract by severity count
    score = 100
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev == "CRITICAL": score -= 15
        elif sev == "HIGH": score -= 8
        elif sev == "MEDIUM": score -= 4
        elif sev == "LOW": score -= 2
    if score < 0: score = 0
    return score

# ----------------------------
# Helper normalizers (important because your ACL JSON uses objects/ints)
# ----------------------------
def norm_identity(v):
    # "CORP\\user" OR {"Value":"CORP\\user"}
    if isinstance(v, dict) and "Value" in v:
        return str(v["Value"])
    return str(v or "")

def norm_access_type_allow(v):
    # "Allow"/"Deny" OR 0/1 (Allow=0, Deny=1)
    if isinstance(v, int):
        return v == 0
    s = str(v or "").strip().lower()
    return s == "allow"

def principal_to_sam(principal: str) -> str:
    """
    Convert 'CORP\\john.smith' -> 'john.smith' (lowercase).
    Also works for bare 'john.smith'.
    """
    p = (principal or "").strip()
    if "\\" in p:
        p = p.split("\\", 1)[1]
    return p.strip().lower()

# ----------------------------
# Rules
# ----------------------------
def rule_kerberoast_exposure(users):
    findings = []
    for u in users:
        sam = (u.get("SamAccountName") or "").lower()
        if sam == "krbtgt":
            continue

        spns = u.get("servicePrincipalName")
        if not spns:
            continue

        spns = ensure_list(spns)
        pwd_dt = filetime_to_dt(u.get("pwdLastSet"))
        pwd_age_days = None
        if pwd_dt:
            pwd_age_days = (datetime.datetime.utcnow() - pwd_dt).days

        sev = "HIGH"
        if pwd_age_days is not None and pwd_age_days >= 365:
            sev = "CRITICAL"

        findings.append({
            "id": "AD-KERB-001",
            "title": "Kerberoastable service account (SPN present)",
            "severity": sev,
            "evidence": {
                "user": u.get("SamAccountName"),
                "spn_count": len(spns),
                "pwd_last_set_utc": pwd_dt.isoformat() + "Z" if pwd_dt else None,
                "pwd_age_days": pwd_age_days
            },
            "impact": "Service tickets for SPN accounts can be requested and cracked offline if passwords are weak or old.",
            "remediation": [
                "Prefer gMSA for services where possible.",
                "Rotate service account passwords regularly and enforce strong random values.",
                "Remove unused SPNs from user accounts."
            ]
        })
    return findings

def rule_password_never_expires(users):
    findings = []
    for u in users:
        if u.get("PasswordNeverExpires") is True:
            findings.append({
                "id": "AD-AUTH-002",
                "title": "Account has 'Password never expires'",
                "severity": "MEDIUM",
                "evidence": {"user": u.get("SamAccountName")},
                "impact": "Long-lived credentials increase exposure to offline cracking and credential reuse attacks.",
                "remediation": [
                    "Disable 'Password never expires' for user/service accounts where possible.",
                    "Use gMSA for services to get automatic password rotation."
                ]
            })
    return findings

def rule_machine_account_quota(domain_policies):
    findings = []
    maq = None
    if isinstance(domain_policies, dict):
        maq = domain_policies.get("msDSMachineAccountQuota")
    if maq is None:
        return findings
    try:
        maq_int = int(maq)
    except Exception:
        return findings
    if maq_int > 0:
        findings.append({
            "id": "AD-POSTURE-003",
            "title": "MachineAccountQuota is greater than 0",
            "severity": "MEDIUM",
            "evidence": {"ms-DS-MachineAccountQuota": maq_int},
            "impact": "Allows authenticated users to join machines to the domain, which can enable certain abuse paths in misconfigured environments.",
            "remediation": [
                "Set MachineAccountQuota to 0 unless you explicitly need self-service joins.",
                "If self-service joins are needed, restrict who can join machines using delegated OU permissions."
            ]
        })
    return findings

def rule_krbtgt_password_age(users, warn_days=180, crit_days=365):
    findings = []
    krb = None
    for u in users:
        if (u.get("SamAccountName") or "").lower() == "krbtgt":
            krb = u
            break

    if not krb:
        return findings

    pwd_dt = filetime_to_dt(krb.get("pwdLastSet"))
    if not pwd_dt:
        return findings

    age_days = (datetime.datetime.utcnow() - pwd_dt).days

    if age_days >= crit_days:
        severity = "CRITICAL"
    elif age_days >= warn_days:
        severity = "HIGH"
    else:
        return findings

    findings.append({
        "id": "AD-KRBTGT-001",
        "title": "krbtgt password age exceeds recommended threshold (Golden Ticket exposure)",
        "severity": severity,
        "evidence": {
            "user": "krbtgt",
            "pwd_last_set_utc": pwd_dt.isoformat() + "Z",
            "pwd_age_days": age_days,
            "warn_days": warn_days,
            "crit_days": crit_days
        },
        "impact": "If the KRBTGT secret is compromised, attackers can forge Kerberos tickets (Golden Tickets) and maintain long-term access.",
        "remediation": [
            "Rotate the krbtgt password using a controlled procedure.",
            "Perform a second krbtgt reset after a safe delay (commonly 10+ hours) to invalidate older ticket-signing keys.",
            "Coordinate to avoid authentication disruption."
        ]
    })
    return findings

def rule_gpo_posture(gpo_reports_dir: Path):
    findings = []
    if not gpo_reports_dir.exists():
        return findings

    xml_files = list(gpo_reports_dir.glob("*.xml"))
    if not xml_files:
        return findings

    observed = defaultdict(list)
    best = {}

    def add_obs(key, file_name, value_int):
        observed[key].append({"file": file_name, "value": value_int})
        if key not in best or value_int > best[key]:
            best[key] = value_int

    def extract_value(xml_text, value_name):
        vals = []
        pat = re.compile(
            rf"<ValueName>\s*{re.escape(value_name)}\s*</ValueName>.*?"
            r"(?:<Value>\s*([0-9]+)\s*</Value>|<Decimal>\s*([0-9]+)\s*</Decimal>|<Number>\s*([0-9]+)\s*</Number>)",
            re.IGNORECASE | re.DOTALL
        )
        for m in pat.finditer(xml_text):
            for g in m.groups():
                if g is not None:
                    try:
                        vals.append(int(g))
                    except Exception:
                        pass
        if not vals:
            pat2 = re.compile(rf"{re.escape(value_name)}.*?([0-9]+)", re.IGNORECASE | re.DOTALL)
            for m in pat2.finditer(xml_text):
                try:
                    vals.append(int(m.group(1)))
                except Exception:
                    pass
        return vals

    targets = {
        "LDAPServerIntegrity": "ldap_server_integrity",
        "LDAPClientIntegrity": "ldap_client_integrity",
        "LdapEnforceChannelBinding": "ldap_channel_binding",
        "RequireSecuritySignature": "smb_require_sign",
        "EnableSecuritySignature": "smb_enable_sign",
        "LmCompatibilityLevel": "lm_compat",
    }

    for xf in xml_files:
        try:
            txt = xf.read_text(encoding="utf-8-sig", errors="ignore")
        except Exception:
            continue
        for value_name, key in targets.items():
            vals = extract_value(txt, value_name)
            for v in vals:
                add_obs(key, xf.name, v)

    server = best.get("ldap_server_integrity")
    client = best.get("ldap_client_integrity")
    cb = best.get("ldap_channel_binding")
    smb_req = best.get("smb_require_sign")
    smb_en  = best.get("smb_enable_sign")
    lm = best.get("lm_compat")

    if server is None:
        findings.append({
            "id": "GPO-LDAP-001",
            "title": "LDAP server signing/integrity not configured in any exported GPO",
            "severity": "HIGH",
            "evidence": {"gpo_reports_scanned": len(xml_files), "observed": observed.get("ldap_server_integrity", [])},
            "impact": "Without enforcing LDAP signing on Domain Controllers, LDAP traffic may be vulnerable depending on client behavior.",
            "remediation": [
                "Configure LDAPServerIntegrity via GPO (prefer 2 = Require signing).",
                "Pilot and monitor unsigned binds before enforcing broadly."
            ]
        })
    elif server < 2:
        findings.append({
            "id": "GPO-LDAP-001",
            "title": "LDAP server signing/integrity is configured but not set to 'Require'",
            "severity": "HIGH",
            "evidence": {"LDAPServerIntegrity_best": server, "observed": observed.get("ldap_server_integrity", [])},
            "impact": "LDAP server signing is not enforced at the strongest level.",
            "remediation": ["Set LDAPServerIntegrity=2 via GPO on Domain Controllers."]
        })

    if client is None:
        findings.append({
            "id": "GPO-LDAP-003",
            "title": "LDAP client signing/integrity not configured in any exported GPO",
            "severity": "MEDIUM",
            "evidence": {"gpo_reports_scanned": len(xml_files), "observed": observed.get("ldap_client_integrity", [])},
            "impact": "Clients may perform unsigned LDAP binds depending on defaults and application behavior.",
            "remediation": ["Configure LDAPClientIntegrity via GPO where appropriate."]
        })
    elif client == 0:
        findings.append({
            "id": "GPO-LDAP-003",
            "title": "LDAP client signing/integrity configured to allow unsigned binds (weak value)",
            "severity": "MEDIUM",
            "evidence": {"LDAPClientIntegrity_best": client, "observed": observed.get("ldap_client_integrity", [])},
            "impact": "LDAP clients may not require signing.",
            "remediation": ["Increase LDAPClientIntegrity via GPO after compatibility testing."]
        })

    if cb is None:
        findings.append({
            "id": "GPO-LDAP-002",
            "title": "LDAP channel binding not configured in any exported GPO",
            "severity": "MEDIUM",
            "evidence": {"gpo_reports_scanned": len(xml_files), "observed": observed.get("ldap_channel_binding", [])},
            "impact": "Channel binding can reduce certain relay-style risks but may affect legacy compatibility.",
            "remediation": ["Evaluate enforcing LdapEnforceChannelBinding via staged rollout."]
        })
    elif cb < 2:
        findings.append({
            "id": "GPO-LDAP-002",
            "title": "LDAP channel binding is configured but not enforced at the strongest level",
            "severity": "MEDIUM",
            "evidence": {"LdapEnforceChannelBinding_best": cb, "observed": observed.get("ldap_channel_binding", [])},
            "impact": "Channel binding is not enforced at the strongest level.",
            "remediation": ["Consider LdapEnforceChannelBinding=2 where compatible."]
        })

    if smb_req is None:
        findings.append({
            "id": "GPO-SMB-001",
            "title": "SMB signing requirement not configured in any exported GPO",
            "severity": "HIGH",
            "evidence": {"gpo_reports_scanned": len(xml_files), "observed": observed.get("smb_require_sign", [])},
            "impact": "If SMB signing is not required, some environments may be exposed to relay attacks depending on other controls.",
            "remediation": ["Require SMB signing on servers/clients where feasible."]
        })
    elif smb_req == 0:
        findings.append({
            "id": "GPO-SMB-001",
            "title": "SMB signing requirement is configured but disabled (RequireSecuritySignature=0)",
            "severity": "HIGH",
            "evidence": {"RequireSecuritySignature_best": smb_req, "observed": observed.get("smb_require_sign", [])},
            "impact": "SMB signing is not required, increasing exposure in some environments.",
            "remediation": ["Set RequireSecuritySignature=1 via GPO where feasible."]
        })

    if smb_req is not None and smb_req == 0 and smb_en == 1:
        findings.append({
            "id": "GPO-SMB-002",
            "title": "SMB signing is enabled but not required (weaker posture)",
            "severity": "MEDIUM",
            "evidence": {"EnableSecuritySignature_best": smb_en, "RequireSecuritySignature_best": smb_req},
            "impact": "Enabling signing helps, but not requiring it can still allow unsigned SMB sessions in some cases.",
            "remediation": ["Prefer requiring SMB signing where possible."]
        })

    if lm is None:
        findings.append({
            "id": "GPO-NTLM-001",
            "title": "LM/NTLM compatibility level not configured in any exported GPO",
            "severity": "MEDIUM",
            "evidence": {"gpo_reports_scanned": len(xml_files), "observed": observed.get("lm_compat", [])},
            "impact": "Without setting LmCompatibilityLevel, systems may operate with weaker defaults depending on OS version/local policy.",
            "remediation": ["Set LmCompatibilityLevel to a secure value (commonly 5 for NTLMv2-only) where compatible."]
        })
    elif lm < 5:
        findings.append({
            "id": "GPO-NTLM-001",
            "title": "LM/NTLM compatibility level is configured but below recommended level",
            "severity": "MEDIUM",
            "evidence": {"LmCompatibilityLevel_best": lm, "observed": observed.get("lm_compat", [])},
            "impact": "Lower LmCompatibilityLevel can allow weaker NTLM behavior compared to NTLMv2-only posture.",
            "remediation": ["Increase LmCompatibilityLevel after compatibility testing."]
        })

    return findings

def rule_dcsync_risk(domain_acl_entries, protected_sams: set):
    """
    GUID-accurate DCSync detection.

    Flags only when a non-built-in, non-AdminSDHolder protected principal has
    replication extended-right GUIDs on the domain root ACL.
    """
    findings = []
    if not domain_acl_entries:
        return findings

    REPL_GUIDS = {
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "Replicating Directory Changes",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "Replicating Directory Changes All",
        "89e95b76-444d-4c62-991a-0facbeda640c": "Replicating Directory Changes In Filtered Set",
    }

    # Minimal bit mask for ActiveDirectoryRights.ExtendedRight (0x00000100)
    EXTENDED_RIGHT_BIT = 0x00000100

    def get_objecttype_guid(ace) -> str:
        g = ace.get("ObjectType")
        if isinstance(g, str):
            return g.strip().lower()
        return str(g or "").strip().lower()

    def is_allow_ace(ace) -> bool:
        v = ace.get("AccessControlType")
        # PowerShell export: Allow=0, Deny=1 (often)
        if isinstance(v, int):
            return v == 0
        s = str(v or "").strip().lower()
        return s == "allow"

    def is_inherited(ace) -> bool:
        return str(ace.get("IsInherited")).strip().lower() == "true"

    def has_extendedright(ace) -> bool:
        r = ace.get("ActiveDirectoryRights")
        if isinstance(r, int):
            return (r & EXTENDED_RIGHT_BIT) == EXTENDED_RIGHT_BIT
        # string fallback if ever exported as "ExtendedRight, ..."
        rs = str(r or "").upper()
        return "EXTENDEDRIGHT" in rs

    # Collect which principals have which replication rights
    principal_hits = {}  # principal -> set(guid)

    for ace in domain_acl_entries:
        try:
            if not is_allow_ace(ace):
                continue
            if is_inherited(ace):
                continue

            if not has_extendedright(ace):
                continue

            obj_guid = get_objecttype_guid(ace)
            if obj_guid not in REPL_GUIDS:
                continue

            principal = norm_identity(ace.get("IdentityReference"))
            if not principal:
                continue

            # Suppress built-in / expected Tier-0 principals
            if is_builtin_or_expected_principal(principal):
                continue

            # Suppress AdminSDHolder protected (adminCount=1)
            sam_lc = principal_to_sam(principal)
            if sam_lc in (protected_sams or set()):
                continue

            principal_hits.setdefault(principal, set()).add(obj_guid)
        except Exception:
            continue

    for principal, guids in principal_hits.items():
        rights_names = [REPL_GUIDS[g] for g in sorted(guids)]
        severity = "CRITICAL" if len(guids) >= 2 else "HIGH"

        findings.append({
            "id": "AD-DC-SYNC-001",
            "title": "Non-Tier-0 principal has DCSync replication extended rights on domain root",
            "severity": severity,
            "evidence": {
                "principal": principal,
                "principal_sam": principal_to_sam(principal),
                "replication_rights": rights_names,
                "replication_guids": sorted(list(guids)),
                "note": "Detection is GUID-based against domain root ACL ObjectType (extended rights)."
            },
            "impact": "A principal with replication extended rights can potentially DCSync and extract password hashes (including krbtgt), enabling full domain compromise.",
            "remediation": [
                "Remove replication extended rights from non-Tier-0 users/groups on the domain root.",
                "Limit these rights to Domain Controllers and tightly controlled Tier-0 admin groups only.",
                "Review delegation model and use privileged access workstations (PAWs) for Tier-0."
            ]
        })

    return findings

def build_adminsdholder_protected_set(users, groups):
    """
    Build a set of sAMAccountNames (lowercase) that are protected by AdminSDHolder (adminCount=1).
    Includes both users and groups.
    """
    protected = set()

    for u in users or []:
        sam = (u.get("SamAccountName") or "").strip()
        if sam and str(u.get("adminCount")).strip() == "1":
            protected.add(sam.lower())

    for g in groups or []:
        sam = (g.get("SamAccountName") or "").strip()
        if sam and str(g.get("adminCount")).strip() == "1":
            protected.add(sam.lower())

    return protected

def is_builtin_or_expected_principal(principal: str) -> bool:
    """
    Suppress built-in and expected Tier-0 principals.
    """
    if not principal:
        return True

    p = principal.upper()

    # Built-in / system accounts
    if p.startswith("NT AUTHORITY\\"):
        return True
    if p.startswith("BUILTIN\\"):
        return True
    if p.startswith("S-1-5-"):
        return True

    # AD internal placeholders
    if p in ("SELF", "CREATOR OWNER"):
        return True

    # Tier-0 admin groups
    tier0_keywords = [
        "DOMAIN ADMINS",
        "ENTERPRISE ADMINS",
        "SCHEMA ADMINS",
        "ADMINISTRATORS",
        "ENTERPRISE DOMAIN CONTROLLERS",
        "DOMAIN CONTROLLERS"
    ]

    return any(k in p for k in tier0_keywords)

def rule_dangerous_acls(acl_targets_dir: Path, protected_sams: set):
    """
    Detect dangerous delegated rights on high-value AD containers.
    Handles both string-style JSON and numeric/object-style JSON exported by PowerShell.
    Suppresses principals protected by AdminSDHolder (adminCount=1) via protected_sams.
    """
    findings = []
    if not acl_targets_dir.exists():
        return findings

    RIGHTS_BITS = {
        "CreateChild":      0x00000001,
        "DeleteChild":      0x00000002,
        "Self":             0x00000008,
        "ReadProperty":     0x00000010,
        "WriteProperty":    0x00000020,
        "ExtendedRight":    0x00000100,
        "Delete":           0x00010000,
        "ReadControl":      0x00020000,
        "WriteDacl":        0x00040000,
        "WriteOwner":       0x00080000,
        "GenericAll":       0x10000000,
        "GenericExecute":   0x20000000,
        "GenericWrite":     0x40000000,
        "GenericRead":      0x80000000,
    }

    DANGEROUS = {
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "ExtendedRight",
        "WriteProperty",
        "CreateChild",
        "DeleteChild",
        "Self",
    }

    allow_principal_contains = [
        "NT AUTHORITY\\SYSTEM",
        "BUILTIN\\ADMINISTRATORS",
        "DOMAIN ADMINS",
        "ENTERPRISE ADMINS",
    ]

    def is_allowed_principal(p: str) -> bool:
        up = (p or "").upper()
        return any(x in up for x in allow_principal_contains)

    def normalize_rights(v):
        if isinstance(v, int):
            out = set()
            for name, bit in RIGHTS_BITS.items():
                if v & bit:
                    out.add(name)
            if {"WriteDacl", "WriteOwner", "CreateChild", "DeleteChild", "ExtendedRight"}.issubset(out):
                out.add("GenericAll")
            return out
        s = str(v or "")
        return {r.strip() for r in s.split(",") if r.strip()}

    for jf in sorted(acl_targets_dir.glob("*.json")):
        obj_name = jf.stem
        aces = load_json(jf) or []

        for ace in aces:
            try:
                if not norm_access_type_allow(ace.get("AccessControlType")):
                    continue
                if str(ace.get("IsInherited")).lower() == "true":
                    continue

                principal = norm_identity(ace.get("IdentityReference"))
                if not principal:
                    continue

                # 1) Suppress built-in / expected Tier-0 principals
                if is_builtin_or_expected_principal(principal):
                    continue

                # 2) Suppress AdminSDHolder-protected users/groups
                sam_lc = principal_to_sam(principal)
                if sam_lc in (protected_sams or set()):
                    continue

                rights_set = normalize_rights(ace.get("ActiveDirectoryRights"))
                hit = sorted(list(rights_set.intersection(DANGEROUS)))
                if not hit:
                    continue

                severity = "CRITICAL" if obj_name == "domain_controllers_ou" else "HIGH"

                findings.append({
                    "id": "AD-ACL-001",
                    "title": "Dangerous delegated rights detected on high-value AD container",
                    "severity": severity,
                    "evidence": {
                        "object": obj_name,
                        "principal": principal,
                        "principal_sam": sam_lc,
                        "rights": hit,
                        "activeDirectoryRights_raw": ace.get("ActiveDirectoryRights"),
                        "accessControlType_raw": ace.get("AccessControlType"),
                        "source_file": jf.name
                    },
                    "impact": "Explicit powerful ACLs on Tier-0 containers can enable privilege escalation or domain takeover depending on the principal and target objects.",
                    "remediation": [
                        "Remove unnecessary delegated rights (GenericAll/GenericWrite/WriteDACL/WriteOwner/Extended rights).",
                        "Restrict Tier-0 ACLs (Domain Controllers OU, privileged groups) to tightly controlled admin groups.",
                        "Re-run scan to confirm exposure is removed."
                    ]
                })
            except Exception:
                continue

    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True, help="Raw JSON folder")
    ap.add_argument("--out", required=True, help="Output scan.json")
    ap.add_argument("--html", required=True, help="Output report.html")
    args = ap.parse_args()

    raw = Path(args.raw)
    users = load_json(raw / "users.json") or []
    groups = load_json(raw / "groups.json") or []   # <-- REQUIRED for adminCount-aware suppression
    domain_policies = load_json(raw / "domain_policies.json") or {}
    domain_acl = load_json(raw / "domain_acl.json") or []

    protected_sams = build_adminsdholder_protected_set(users, groups)

    findings = []
    findings += rule_kerberoast_exposure(users)
    findings += rule_password_never_expires(users)
    findings += rule_machine_account_quota(domain_policies)
    findings += rule_dcsync_risk(domain_acl, protected_sams)
    findings += rule_gpo_posture(raw / "gpo_reports")
    findings += rule_dangerous_acls(raw / "acl_targets", protected_sams)  # <-- PASS SET HERE
    findings += rule_krbtgt_password_age(users)

    findings.sort(key=lambda f: -SEVERITY_ORDER.get(f.get("severity", "INFO").upper(), 0))

    posture_score = score_posture(findings)

    result = {
        "generated_utc": datetime.datetime.utcnow().isoformat() + "Z",
        "posture_score": posture_score,
        "finding_count": len(findings),
        "findings": findings
    }

    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")

    html = ["""
    <html>
    <head>
    <meta charset="utf-8">
    <title>ADGuard Report</title>
    <style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    body {
      font-family: Arial, Helvetica, sans-serif;
      background-color: #fafafa;
      margin: 30px;
    }

    h1 {
      font-size: 28px;
      margin-bottom: 10px;
    }

    h3 {
      font-size: 18px;
      margin-top: 0;
    }

    .finding {
      background: #ffffff;
      padding: 15px;
      margin-bottom: 20px;
      border-radius: 6px;
      box-shadow: 0 2px 6px rgba(0,0,0,0.06);
    }

    .sev-CRITICAL { border-left: 8px solid #c62828; }
    .sev-HIGH     { border-left: 8px solid #ef6c00; }
    .sev-MEDIUM   { border-left: 8px solid #f9a825; }
    .sev-LOW      { border-left: 8px solid #0277bd; }
    .sev-INFO     { border-left: 8px solid #546e7a; }

    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: bold;
      color: #fff;
      margin-bottom: 6px;
    }

    .badge.CRITICAL { background: #c62828; }
    .badge.HIGH     { background: #ef6c00; }
    .badge.MEDIUM   { background: #f9a825; color: #000; }
    .badge.LOW      { background: #0277bd; }
    .badge.INFO     { background: #546e7a; }

    pre {
      background: #f4f4f4;
      padding: 10px;
      border-radius: 4px;
      font-size: 13px;
      overflow-x: auto;
    }
    
      details summary {
      cursor: pointer;
      font-size: 16px;
      margin-bottom: 8px;
    }

    details[open] summary {
      margin-bottom: 12px;
    }
    
    .chart-container {
      width: 600px;
      height: 400px;
      float: right;
      margin-left: 30px;
      margin-bottom: 20px;
    }
    
    .chart-wrapper {
      display: flex;
      align-items: center;
    }

    .chart-container {
      width: 600px;
      height: 400px;
    }

    .chart-legend {
      margin-left: 30px;
      font-size: 14px;
    }

    .chart-legend div {
      margin-bottom: 8px;
      display: flex;
      align-items: center;
    }

    .legend-color {
      width: 14px;
      height: 14px;
      margin-right: 8px;
      border-radius: 3px;
      display: inline-block;
    }
    
    </style>
    </head>
    <body>
    """]

    html.append("<h1>ADGuard Report</h1>")
    html.append(f"<p><b>Generated (UTC):</b> {result['generated_utc']}</p>")
    html.append(f"<p><b>Posture score:</b> {posture_score}/100</p>")
    html.append(f"<p><b>Total findings:</b> {len(findings)}</p>")
    
    sev_counts = {}
    for f in findings:
        s = f["severity"].upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    labels_js = json.dumps(list(sev_counts.keys()))
    values_js = json.dumps(list(sev_counts.values()))

    html.append("""
    <h2>Findings Overview</h2>

    <div class="chart-container">
        <canvas id="severityChart" width="600" height="400"></canvas>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
    const ctx = document.getElementById('severityChart').getContext('2d');
    new Chart(ctx, {
      type: 'pie',
      data: {
        labels: """ + labels_js + """,
        datasets: [{
          label: 'Findings by Severity',
          data: """ + values_js + """,
          backgroundColor: [
            '#c62828',
            '#ef6c00',
            '#f9a825',
            '#0277bd',
            '#546e7a'
          ]
        }]
      },
      options: {
        responsive: false,
        plugins: {
          legend: { position: 'right' }
        }
      }
    });
    </script>
    """)

    for f in findings:
        sev = f["severity"].upper()

        html.append(f"""
    <div class="finding sev-{sev}">
      <details>
        <summary>
          <span class="badge {sev}">{sev}</span>
          <strong>{f['title']}</strong>
        </summary>

        <pre>{json.dumps(f.get('evidence', {}), indent=2)}</pre>
        <p><b>Impact:</b> {f.get('impact', '')}</p>
    """)

        if f.get("remediation"):
            html.append("<b>Remediation:</b><ul>")
            for r in f["remediation"]:
                html.append(f"<li>{r}</li>")
            html.append("</ul>")

        html.append("""
      </details>
    </div>
    """)

    Path(args.html).write_text("\n".join(html), encoding="utf-8")

    print(f"Wrote: {args.out}")
    print(f"Wrote: {args.html}")


if __name__ == "__main__":
    main()
