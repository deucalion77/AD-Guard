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
        "impact": "If the KRBTGT secret is compromised, attackers can forge Kerberos tickets (Golden Tickets) and maintain long-term access.See Microsoft’s krbtgt account maintenance onsiderations: <a href=\"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn745899(v=ws.11)#krbtgt-account-maintenance-considerations\" target=\"_blank\">https://learn.microsoft.com/en-us/previous-versions/windows/krbtgt-account-maintenance-considerations</a>",
        "remediation": [
            "Rotate the krbtgt password using a controlled procedure.",
            "Perform a second krbtgt reset after a safe delay (commonly 10+ hours) to invalidate older ticket-signing keys.",
            "Coordinate to avoid authentication disruption."
        ]
    })
    return findings