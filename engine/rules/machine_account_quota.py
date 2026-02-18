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
            "impact": "Allows authenticated users to join machines to the domain, which can enable certain abuse paths in misconfigured environments. See Microsoft’s default workstation numbers join domain onsiderations: <a href=\"https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/default-workstation-numbers-join-domain\" target=\"_blank\">https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/default-workstation-numbers-join-domain</a>",
            "remediation": [
                "Set MachineAccountQuota to 0 unless you explicitly need self-service joins.",
                "If self-service joins are needed, restrict who can join machines using delegated OU permissions."
            ]
        })
    return findings
