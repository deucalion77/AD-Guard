import json
from pathlib import Path

def _load_json(p: Path):
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8-sig"))

def _norm_identity(v):
    if not v:
        return None
    if isinstance(v, dict) and "Value" in v:
        return v["Value"]
    return str(v)

def _principal_to_sam(principal: str):
    if not principal:
        return ""
    if "\\" in principal:
        return principal.split("\\", 1)[1].lower()
    return principal.lower()

def _norm_access_type_allow(v) -> bool:
    """
    Handles both:
      - numeric exported by PowerShell (0=Allow, 1=Deny)
      - string variants ("Allow"/"Deny")
    """
    if v is None:
        return False
    if isinstance(v, int):
        return v == 0
    s = str(v).strip().lower()
    return s in ("allow", "0")

def _is_builtin_or_expected_principal(principal: str) -> bool:
    """
    Your suppression logic should stay consistent across rules.
    Keep this conservative: filter out built-ins + obvious Tier-0 groups.
    """
    if not principal:
        return True
    p = principal.upper()

    if p.startswith("NT AUTHORITY\\"):
        return True
    if p.startswith("BUILTIN\\"):
        return True
    if p.startswith("S-1-5-"):
        return True
    if p in ("SELF", "CREATOR OWNER"):
        return True

    tier0_keywords = [
        "DOMAIN ADMINS",
        "ENTERPRISE ADMINS",
        "SCHEMA ADMINS",
        "ADMINISTRATORS",
        "ENTERPRISE DOMAIN CONTROLLERS",
        "DOMAIN CONTROLLERS",
    ]
    return any(k in p for k in tier0_keywords)

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