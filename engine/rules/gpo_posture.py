import json
from pathlib import Path
from collections import defaultdict
import re
from common import (
    _load_json,
    _norm_identity,
    _principal_to_sam,
    _norm_access_type_allow,
    _is_builtin_or_expected_principal,
    ensure_list,
    filetime_to_dt
)

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
            "impact": "Without enforcing LDAP signing on Domain Controllers, LDAP traffic may be vulnerable depending on client behavior.See Microsoft’s LDAP server signing requirements: <a href=\"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements\" target=\"_blank\">https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements</a>",
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
            "impact": "LDAP server signing is not enforced at the strongest level.See Microsoft’s LDAP server signing requirements: <a href=\"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements\" target=\"_blank\">https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements</a>",
            "remediation": ["Set LDAPServerIntegrity=2 via GPO on Domain Controllers."]
        })

    if client is None:
        findings.append({
            "id": "GPO-LDAP-003",
            "title": "LDAP client signing/integrity not configured in any exported GPO",
            "severity": "MEDIUM",
            "evidence": {"gpo_reports_scanned": len(xml_files), "observed": observed.get("ldap_client_integrity", [])},
            "impact": "Clients may perform unsigned LDAP binds depending on defaults and application behavior.See Microsoft’s LDAP client signing requirements: <a href=\"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-ldap-client-signing-requirements\" target=\"_blank\">https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-ldap-client-signing-requirements</a>",
            "remediation": ["Configure LDAPClientIntegrity via GPO where appropriate."]
        })
    elif client == 0:
        findings.append({
            "id": "GPO-LDAP-003",
            "title": "LDAP client signing/integrity configured to allow unsigned binds (weak value)",
            "severity": "MEDIUM",
            "evidence": {"LDAPClientIntegrity_best": client, "observed": observed.get("ldap_client_integrity", [])},
            "impact": "LDAP clients may not require signing.See Microsoft’s LDAP client signing requirements: <a href=\"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-ldap-client-signing-requirements\" target=\"_blank\">https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-ldap-client-signing-requirements</a>",
            "remediation": ["Increase LDAPClientIntegrity via GPO after compatibility testing."]
        })

    if cb is None:
        findings.append({
            "id": "GPO-LDAP-002",
            "title": "LDAP channel binding not configured in any exported GPO",
            "severity": "MEDIUM",
            "evidence": {"gpo_reports_scanned": len(xml_files), "observed": observed.get("ldap_channel_binding", [])},
            "impact": "Channel binding can reduce certain relay-style risks but may affect legacy compatibility.See Microsoft’s LDAP server channel binding token requirements: <a href=\"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-controller-ldap-server-channel-binding-token-requirements\" target=\"_blank\">https://learn.microsoft.com/en-us/previous-versions/windows/security-policy-settings/domain-controller-ldap-server-channel-binding-token-requirements</a>",
            "remediation": ["Evaluate enforcing LdapEnforceChannelBinding via staged rollout."]
        })
    elif cb < 2:
        findings.append({
            "id": "GPO-LDAP-002",
            "title": "LDAP channel binding is configured but not enforced at the strongest level",
            "severity": "MEDIUM",
            "evidence": {"LdapEnforceChannelBinding_best": cb, "observed": observed.get("ldap_channel_binding", [])},
            "impact": "Channel binding is not enforced at the strongest level.See Microsoft’s LDAP server channel binding token requirements: <a href=\"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-controller-ldap-server-channel-binding-token-requirements\" target=\"_blank\">https://learn.microsoft.com/en-us/previous-versions/windows/security-policy-settings/domain-controller-ldap-server-channel-binding-token-requirements</a>",
            "remediation": ["Consider LdapEnforceChannelBinding=2 where compatible."]
        })

    if smb_req is None:
        findings.append({
            "id": "GPO-SMB-001",
            "title": "SMB signing requirement not configured in any exported GPO",
            "severity": "HIGH",
            "evidence": {"gpo_reports_scanned": len(xml_files), "observed": observed.get("smb_require_sign", [])},
            "impact": "If SMB signing is not required, some environments may be exposed to relay attacks depending on other controls.See Microsoft’s Digitally sign communications: <a href=\"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always\"target=\"_blank\">https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always</a>",
            "remediation": ["Require SMB signing on servers/clients where feasible."]
        })
    elif smb_req == 0:
        findings.append({
            "id": "GPO-SMB-001",
            "title": "SMB signing requirement is configured but disabled (RequireSecuritySignature=0)",
            "severity": "HIGH",
            "evidence": {"RequireSecuritySignature_best": smb_req, "observed": observed.get("smb_require_sign", [])},
            "impact": "SMB signing is not required, increasing exposure in some environments.See Microsoft’s Digitally sign communications: <a href=\"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always\"target=\"_blank\">https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always</a>",
            "remediation": ["Set RequireSecuritySignature=1 via GPO where feasible."]
        })

    if smb_req is not None and smb_req == 0 and smb_en == 1:
        findings.append({
            "id": "GPO-SMB-002",
            "title": "SMB signing is enabled but not required (weaker posture)",
            "severity": "MEDIUM",
            "evidence": {"EnableSecuritySignature_best": smb_en, "RequireSecuritySignature_best": smb_req},
            "impact": "Enabling signing helps, but not requiring it can still allow unsigned SMB sessions in some cases.See Microsoft’s Digitally sign communications: <a href=\"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always\"target=\"_blank\">https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always</a>",
            "remediation": ["Prefer requiring SMB signing where possible."]
        })

    if lm is None:
        findings.append({
            "id": "GPO-NTLM-001",
            "title": "LM/NTLM compatibility level not configured in any exported GPO",
            "severity": "MEDIUM",
            "evidence": {"gpo_reports_scanned": len(xml_files), "observed": observed.get("lm_compat", [])},
            "impact": "Without setting LmCompatibilityLevel, systems may operate with weaker defaults depending on OS version/local policy.See Microsoft’s LAN Manager authentication level: <a href=\"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level\"target=\"_blank\">https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level</a>",
            "remediation": ["Set LmCompatibilityLevel to a secure value (commonly 5 for NTLMv2-only) where compatible."]
        })
    elif lm < 5:
        findings.append({
            "id": "GPO-NTLM-001",
            "title": "LM/NTLM compatibility level is configured but below recommended level",
            "severity": "MEDIUM",
            "evidence": {"LmCompatibilityLevel_best": lm, "observed": observed.get("lm_compat", [])},
            "impact": "Lower LmCompatibilityLevel can allow weaker NTLM behavior compared to NTLMv2-only posture.See Microsoft’s LAN Manager authentication level: <a href=\"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level\"target=\"_blank\">https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level</a>",
            "remediation": ["Increase LmCompatibilityLevel after compatibility testing."]
        })

    return findings