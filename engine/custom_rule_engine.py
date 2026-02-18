import json
import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Custom rules loader

ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
ALLOWED_SOURCES = {"users", "groups", "domain_policies", "domain_acl", "gpo_settings"}

REQUIRED_RULE_FIELDS = {"id", "title", "severity", "source", "when"}
OPTIONAL_RULE_FIELDS = {"evidence", "impact", "remediation", "tags", "references", "enabled"}

def _safe_read_text(p: Path) -> str:
    # utf-8-sig handles BOM if user saved file with BOM
    return p.read_text(encoding="utf-8-sig", errors="replace")

def _is_rule_obj(x: Any) -> bool:
    return isinstance(x, dict)

def _validate_rule(rule: Dict[str, Any], origin: str) -> Tuple[bool, List[str], List[str]]:
    """
    Returns: (is_valid, warnings, errors)
    - Missing required fields => ERROR (skip)
    - Invalid severity/source => ERROR (skip)
    - Missing optional fields => WARN (rule still loads)
    - Unknown fields => WARN (helps catch typos)
    """
    warnings: List[str] = []
    errors: List[str] = []

    # Required fields
    missing = [k for k in REQUIRED_RULE_FIELDS if k not in rule]
    if missing:
        errors.append(f"[ERROR] {origin}: missing required field(s): {', '.join(missing)}")
        return False, warnings, errors

    # Basic types
    if not isinstance(rule["id"], str) or not rule["id"].strip():
        errors.append(f"[ERROR] {origin}: 'id' must be a non-empty string")
    if not isinstance(rule["title"], str) or not rule["title"].strip():
        errors.append(f"[ERROR] {origin}: 'title' must be a non-empty string")
    if not isinstance(rule["severity"], str):
        errors.append(f"[ERROR] {origin}: 'severity' must be a string")
    if not isinstance(rule["source"], str):
        errors.append(f"[ERROR] {origin}: 'source' must be a string")
    if not isinstance(rule["when"], dict):
        errors.append(f"[ERROR] {origin}: 'when' must be an object (dict)")

    if errors:
        return False, warnings, errors

    # Normalize + validate severity/source
    sev = rule["severity"].strip().upper()
    rule["severity"] = sev
    if sev not in ALLOWED_SEVERITIES:
        errors.append(f"[ERROR] {origin}: invalid severity '{sev}'. Allowed: {sorted(ALLOWED_SEVERITIES)}")

    src = rule["source"].strip().lower()
    rule["source"] = src
    if src not in ALLOWED_SOURCES:
        errors.append(f"[ERROR] {origin}: invalid source '{src}'. Allowed: {sorted(ALLOWED_SOURCES)}")

    # Optional fields warnings (do not block)
    for opt in ("evidence", "impact", "remediation"):
        if opt not in rule:
            warnings.append(f"[WARN] {origin}: missing optional field '{opt}' (report may be less informative)")

    # Unknown fields (warn; helps catch typos)
    known = REQUIRED_RULE_FIELDS.union(OPTIONAL_RULE_FIELDS)
    unknown = [k for k in rule.keys() if k not in known]
    if unknown:
        warnings.append(f"[WARN] {origin}: unknown field(s) ignored: {', '.join(sorted(unknown))}")

    # enabled (optional)
    if "enabled" in rule and not isinstance(rule["enabled"], bool):
        warnings.append(f"[WARN] {origin}: 'enabled' should be boolean; treating as enabled")
        rule["enabled"] = True

    # remediation type (optional)
    if "remediation" in rule and rule["remediation"] is not None and not isinstance(rule["remediation"], list):
        warnings.append(f"[WARN] {origin}: 'remediation' should be a list of strings; coercing to single-item list")
        rule["remediation"] = [str(rule["remediation"])]

    return len(errors) == 0, warnings, errors

def load_custom_rules(custom_dir: Path) -> List[Dict[str, Any]]:
# Loads rules from:

    rules: List[Dict[str, Any]] = []
    seen_ids: set = set()

    if not custom_dir.exists():
        print(f"[INFO] Custom rules directory not found: {custom_dir} (0 custom rules loaded)")
        return rules

    files = sorted(list(custom_dir.glob("*.json")) + list(custom_dir.glob("*.ndjson")))
    if not files:
        print(f"[INFO] No custom rule files found in: {custom_dir} (0 custom rules loaded)")
        return rules

    print(f"[INFO] Loading custom rules from: {custom_dir}")

    for f in files:
        origin_base = f"{f.name}"
        try:
            txt = _safe_read_text(f).strip()
            if not txt:
                print(f"[WARN] {origin_base}: empty file (skipped)")
                continue

            # NDJSON: each non-empty line is a rule object
            if f.suffix.lower() == ".ndjson":
                for idx, line in enumerate(txt.splitlines(), start=1):
                    line = line.strip()
                    if not line:
                        continue
                    origin = f"{origin_base}:{idx}"
                    try:
                        obj = json.loads(line)
                    except Exception as e:
                        print(f"[ERROR] {origin}: invalid JSON line: {e}")
                        continue
                    if not _is_rule_obj(obj):
                        print(f"[ERROR] {origin}: expected JSON object per line (skipped)")
                        continue

                    valid, warns, errs = _validate_rule(obj, origin)
                    for w in warns: print(w)
                    for e in errs: print(e)
                    if not valid:
                        continue
                    if obj.get("enabled") is False:
                        print(f"[INFO] {origin}: rule disabled (skipped)")
                        continue

                    rid = obj["id"]
                    if rid in seen_ids:
                        print(f"[WARN] {origin}: duplicate rule id '{rid}' (skipped)")
                        continue
                    seen_ids.add(rid)
                    rules.append(obj)
                    print(f"[INFO] Loaded rule {obj['id']} ({obj['title']})")

                continue  # next file

            # JSON: allow either:
            #  - a single rule object
            #  - a pack object: {"version":"ARL-1.0","rules":[...]}
            obj = json.loads(txt)

            # Pack format
            if isinstance(obj, dict) and "rules" in obj and isinstance(obj["rules"], list):
                for i, r in enumerate(obj["rules"], start=1):
                    origin = f"{origin_base}:rules[{i}]"
                    if not _is_rule_obj(r):
                        print(f"[ERROR] {origin}: expected object (skipped)")
                        continue

                    valid, warns, errs = _validate_rule(r, origin)
                    for w in warns: print(w)
                    for e in errs: print(e)
                    if not valid:
                        continue
                    if r.get("enabled") is False:
                        print(f"[INFO] {origin}: rule disabled (skipped)")
                        continue

                    rid = r["id"]
                    if rid in seen_ids:
                        print(f"[WARN] {origin}: duplicate rule id '{rid}' (skipped)")
                        continue
                    seen_ids.add(rid)
                    rules.append(r)
                    print(f"[INFO] Loaded rule {r['id']} ({r['title']})")
                continue

            # Single rule object
            if not _is_rule_obj(obj):
                print(f"[ERROR] {origin_base}: expected JSON object or {{'rules':[...]}}, got {type(obj).__name__} (skipped)")
                continue

            valid, warns, errs = _validate_rule(obj, origin_base)
            for w in warns: print(w)
            for e in errs: print(e)
            if not valid:
                continue
            if obj.get("enabled") is False:
                print(f"[INFO] {origin_base}: rule disabled (skipped)")
                continue

            rid = obj["id"]
            if rid in seen_ids:
                print(f"[WARN] {origin_base}: duplicate rule id '{rid}' (skipped)")
                continue
            seen_ids.add(rid)
            rules.append(obj)
            print(f"[INFO] Loaded rule {obj['id']} ({obj['title']})")

        except Exception as e:
            print(f"[ERROR] {origin_base}: failed to load: {e}")

    print(f"[INFO] Loaded {len(rules)} custom rule(s)")
    return rules

def _get_field_value(obj: dict, field: str):
    if obj is None:
        return None
    return obj.get(field)

def _op_exists(val, expected: bool) -> bool:
    exists = val is not None and val != "" and val != [] and val != {}
    return exists if expected else (not exists)

def _op_is(val, expected) -> bool:
    return val == expected

def _op_is_not(val, expected) -> bool:
    return val != expected

def _op_contains(val, expected) -> bool:
    if val is None:
        return False
    # list contains (memberOf is usually a list)
    if isinstance(val, list):
        exp = str(expected)
        # allow substring match inside list items too
        return any(exp in str(x) for x in val)
    # string contains
    return str(expected) in str(val)

def _filetime_to_dt_utc(ft):
    # ft is AD "pwdLastSet" FILETIME (100ns ticks since 1601-01-01)
    try:
        ft_int = int(ft)
    except Exception:
        return None
    if ft_int <= 0:
        return None
    # Convert FILETIME -> Unix epoch seconds
    unix_seconds = (ft_int / 10_000_000) - 11644473600
    return datetime.datetime.fromtimestamp(unix_seconds, tz=datetime.UTC)

def _op_older_than_days(val, days: int) -> bool:
    dt = _filetime_to_dt_utc(val)
    if dt is None:
        return False
    now = datetime.datetime.now(datetime.UTC)
    age_days = (now - dt).days
    return age_days > int(days)

def _eval_condition(cond: dict, record: dict) -> bool:
    # group conditions
    if "all_of" in cond:
        return all(_eval_condition(c, record) for c in cond["all_of"])
    if "any_of" in cond:
        return any(_eval_condition(c, record) for c in cond["any_of"])
    if "not" in cond:
        return not _eval_condition(cond["not"], record)

    # leaf condition
    field = cond.get("field")
    val = _get_field_value(record, field) if field else None

    # exactly one operator per leaf
    if "exists" in cond:
        return _op_exists(val, bool(cond["exists"]))
    if "is" in cond:
        return _op_is(val, cond["is"])
    if "is_not" in cond:
        return _op_is_not(val, cond["is_not"])
    if "contains" in cond:
        return _op_contains(val, cond["contains"])
    if "in" in cond:
        try:
            return val in cond["in"]
        except Exception:
            return False
    if "older_than_days" in cond:
        return _op_older_than_days(val, cond["older_than_days"])

    # unsupported operator -> false (and let caller warn)
    return False

def evaluate_custom_rules(custom_rules, *, users, groups, domain_policies, domain_acl):
# Returns findings list in ADGuard format.
# Currently supports: all_of/any_of/not + exists/is/is_not/contains/in

    datasets = {
        "users": users or [],
        "groups": groups or [],
        "domain_policies": [domain_policies or {}],  # normalize to list with 1 item
        "domain_acl": domain_acl or [],
        "gpo_settings": []  # placeholder for future
    }

    findings = []

    for rule in (custom_rules or []):
        if rule.get("enabled") is False:
            continue

        src = rule.get("source")
        data = datasets.get(src, [])
        when = rule.get("when") or {}
        evidence_fields = rule.get("evidence") or []

        match_count = 0
        for rec in data:
            try:
                if _eval_condition(when, rec):
                    match_count += 1
                    ev = {}
                    for f in evidence_fields:
                        ev[f] = rec.get(f)
                    if not ev:
                        # fallback minimal evidence
                        ev = {"source": src}

                    findings.append({
                        "id": rule["id"],
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "evidence": ev,
                        "impact": rule.get("impact", ""),
                        "remediation": rule.get("remediation", [])
                    })
            except Exception:
                continue

    return findings
