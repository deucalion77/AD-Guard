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