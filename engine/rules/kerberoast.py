import json
from pathlib import Path
from common import (
    _load_json,
    _norm_identity,
    _principal_to_sam,
    _norm_access_type_allow,
    _is_builtin_or_expected_principal,
    ensure_list,
    filetime_to_dt
)

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
            "impact": "Explicit powerful ACLs on Tier-0 containers can enable privilege escalation or domain takeover depending on the principal and target objects. See Microsoft’s guidance to help mitigate Kerberoasting: <a href=\"https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/\" target=\"_blank\">https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/</a>",
            "remediation": [
                "Prefer gMSA for services where possible.",
                "Rotate service account passwords regularly and enforce strong random values.",
                "Remove unused SPNs from user accounts."
            ]
        })
    return findings
