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

def rule_password_never_expires(users):
    findings = []
    for u in users:
        if u.get("PasswordNeverExpires") is True:
            findings.append({
                "id": "AD-AUTH-002",
                "title": "Account has 'Password never expires'",
                "severity": "MEDIUM",
                "evidence": {"user": u.get("SamAccountName")},
                "impact": "Long-lived credentials increase exposure to offline cracking and credential reuse attacks.See Microsoft’s Password guidance: <a href=\"https://learn.microsoft.com/en-us/microsoft-365/admin/manage/set-password-expiration-policy?view=o365-worldwide\" target=\"_blank\">https://learn.microsoft.com/en-us/microsoft-365/admin/manage/set-password-expiration-policy</a>",
                "remediation": [
                    "Disable 'Password never expires' for user/service accounts where possible.",
                    "Use gMSA for services to get automatic password rotation."
                ]
            })
    return findings