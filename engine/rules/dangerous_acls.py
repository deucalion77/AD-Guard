import json
from pathlib import Path
from common import (
    _load_json,
    _norm_identity,
    _principal_to_sam,
    _norm_access_type_allow,
    _is_builtin_or_expected_principal,
)


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

    def normalize_rights(v):
        # Numeric bitmask case (PowerShell export)
        if isinstance(v, int):
            out = set()
            for name, bit in RIGHTS_BITS.items():
                if v & bit:
                    out.add(name)

            # Heuristic: if you see these combined, treat it as effectively "GenericAll"
            if {"WriteDacl", "WriteOwner", "CreateChild", "DeleteChild", "ExtendedRight"}.issubset(out):
                out.add("GenericAll")

            return out

        # String case ("GenericAll, WriteDacl, ...")
        s = str(v or "")
        return {r.strip() for r in s.split(",") if r.strip()}

    # NOTE: any exception inside an ACE loop should not kill the scan
    for jf in sorted(acl_targets_dir.glob("*.json")):
        obj_name = jf.stem
        aces = _load_json(jf) or []

        for ace in aces:
            try:
                if not _norm_access_type_allow(ace.get("AccessControlType")):
                    continue
                if str(ace.get("IsInherited")).lower() == "true":
                    continue

                principal = _norm_identity(ace.get("IdentityReference"))
                if not principal:
                    continue

                # 1) Suppress built-in / expected Tier-0 principals
                if _is_builtin_or_expected_principal(principal):
                    continue

                # 2) Suppress AdminSDHolder-protected users/groups
                sam_lc = _principal_to_sam(principal)
                if sam_lc and sam_lc in (protected_sams or set()):
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
                    "impact": "Explicit powerful ACLs on Tier-0 containers can enable privilege escalation or domain takeover depending on the principal and target objects. See Microsoft's Privileged Access documentation: <a href=\"https://learn.microsoft.com/en-us/security/privileged-access-workstations/overview\" target=\"_blank\">https://learn.microsoft.com/en-us/security/privileged-access-workstations/</a>",
                    "remediation": [
                        "Remove unnecessary delegated rights (GenericAll/GenericWrite/WriteDACL/WriteOwner/Extended rights).",
                        "Restrict Tier-0 ACLs (Domain Controllers OU, privileged groups) to tightly controlled admin groups.",
                        "Re-run scan to confirm exposure is removed."
                    ]    
                })
            except Exception:
                continue

    return findings
